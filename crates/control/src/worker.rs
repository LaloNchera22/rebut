//! Worker pool: N tasks claiming jobs until shutdown is signalled. A job in
//! flight is always finished (or failed back to the queue) before a worker exits.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::orchestrator::Orchestrator;
use crate::queue::{FailOutcome, JobQueue};

#[derive(Debug, Clone, Copy)]
pub struct WorkerConfig {
    pub workers: usize,
    /// Sleep between claims when the queue is empty.
    pub poll_interval: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        WorkerConfig {
            workers: 4,
            poll_interval: Duration::from_secs(2),
        }
    }
}

/// Runs until `shutdown` becomes `true` (or its sender is dropped).
pub async fn run_workers(
    queue: Arc<dyn JobQueue>,
    orchestrator: Arc<Orchestrator>,
    config: WorkerConfig,
    shutdown: watch::Receiver<bool>,
) {
    let prefix = uuid::Uuid::new_v4().simple().to_string();
    let mut set = JoinSet::new();
    for n in 0..config.workers {
        let worker = format!("{}-{n}", &prefix[..8]);
        set.spawn(worker_loop(
            worker,
            queue.clone(),
            orchestrator.clone(),
            config.poll_interval,
            shutdown.clone(),
        ));
    }
    while let Some(res) = set.join_next().await {
        if let Err(e) = res {
            tracing::error!(error = %e, "worker task panicked");
        }
    }
}

async fn worker_loop(
    worker: String,
    queue: Arc<dyn JobQueue>,
    orchestrator: Arc<Orchestrator>,
    poll: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    tracing::info!(%worker, "worker started");
    while !*shutdown.borrow() {
        let job = match queue.claim(&worker).await {
            Ok(Some(job)) => job,
            Ok(None) => {
                if idle(poll, &mut shutdown).await {
                    break;
                }
                continue;
            }
            Err(e) => {
                tracing::error!(%worker, error = %format!("{e:#}"), "claim failed");
                if idle(poll, &mut shutdown).await {
                    break;
                }
                continue;
            }
        };
        let result = match orchestrator.process(&job).await {
            Ok(_) => queue.complete(&job).await,
            Err(e) => {
                let msg = format!("{e:#}");
                tracing::warn!(%worker, job = %job.id, error = %msg, "job failed");
                queue.fail(&job, &msg).await.map(|outcome| {
                    if outcome == FailOutcome::Dead {
                        tracing::error!(job = %job.id, "job exhausted its attempts");
                    }
                })
            }
        };
        if let Err(e) = result {
            tracing::error!(%worker, job = %job.id, error = %format!("{e:#}"), "could not settle job");
        }
    }
    tracing::info!(%worker, "worker stopped");
}

/// Waits for the poll interval; returns `true` if the worker should stop.
async fn idle(poll: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(poll) => false,
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
    }
}
