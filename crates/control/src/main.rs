//! `verifier-control`: HTTP API + worker pool in one process.
//!
//! The planner, drand beacon, execution fabric and engines are wired here.
//! Until those crates land, explicit placeholders keep the service honest:
//! every verdict comes out `inconclusive` rather than silently passing.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use time::OffsetDateTime;
use verifier_control::{
    router, run_workers, AppState, BeaconSource, Config, GitHubForge, NoSealedSpecs, Orchestrator,
    PgQueue, PgStore, Planner, RetryPolicy, WorkerConfig, MIGRATOR,
};
use verifier_core::{
    DrandBeacon, ExecutionRequest, ExecutionResult, Executor, ImpactPlan, PullRequest,
};
use verifier_receipts::{Ed25519Signer, InMemoryLog, RekorLog, Signer, TransparencyLog};

/// Placeholder until the fabric is wired: refuses to run anything.
struct NoExecutor;

#[async_trait::async_trait]
impl Executor for NoExecutor {
    async fn execute(&self, _: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
        anyhow::bail!("no execution fabric configured")
    }
}

/// Placeholder until the planner is wired: widen to the full suite.
struct FullSuitePlanner;

#[async_trait::async_trait]
impl Planner for FullSuitePlanner {
    async fn plan(&self, _: &PullRequest) -> anyhow::Result<ImpactPlan> {
        Ok(ImpactPlan {
            widen_to_full_suite: true,
            ..Default::default()
        })
    }
}

/// Placeholder until drand is wired: runs proceed without a seed.
struct NoBeacon;

#[async_trait::async_trait]
impl BeaconSource for NoBeacon {
    async fn round_after(&self, _: OffsetDateTime) -> anyhow::Result<DrandBeacon> {
        anyhow::bail!("no beacon source configured")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let config = Config::parse();

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections((config.workers as u32 + 4).max(8))
        .connect(&config.database_url)
        .await
        .context("connecting to Postgres")?;
    MIGRATOR.run(&pool).await.context("running migrations")?;

    let signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_key_file(&config.signing_key_path)?);
    tracing::info!(key_id = %signer.key_id(), "receipt signing key loaded");
    let log: Arc<dyn TransparencyLog> = match &config.rekor_url {
        Some(url) => Arc::new(RekorLog::new(url.clone(), signer.public_key())),
        None => {
            tracing::warn!("REKOR_URL unset: using an in-memory log (lost on restart)");
            Arc::new(InMemoryLog::new(signer.clone()))
        }
    };
    let key_pem =
        std::fs::read(&config.github_private_key_path).context("reading GitHub App private key")?;
    let forge = Arc::new(GitHubForge::new(
        config.github_app_id,
        &key_pem,
        config.github_api_url.clone(),
    )?);

    let queue = Arc::new(PgQueue::new(
        pool.clone(),
        RetryPolicy {
            max_attempts: config.job_max_attempts,
            lease: Duration::from_secs(config.job_lease_secs),
            ..Default::default()
        },
    ));
    let store = Arc::new(PgStore::new(pool));

    let orchestrator = Arc::new(Orchestrator {
        engines: vec![],
        executor: Arc::new(NoExecutor),
        store: store.clone(),
        signer,
        log: log.clone(),
        forge,
        planner: Arc::new(FullSuitePlanner),
        beacon: Arc::new(NoBeacon),
        sealed: Arc::new(NoSealedSpecs),
        public_url: config.public_url.clone(),
    });

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let workers = tokio::spawn(run_workers(
        queue.clone(),
        orchestrator,
        WorkerConfig {
            workers: config.workers,
            ..Default::default()
        },
        shutdown_rx.clone(),
    ));

    let app = router(AppState {
        queue,
        store,
        log,
        webhook_secret: config.github_webhook_secret.as_bytes().into(),
        maintainer_token: config.maintainer_token.as_deref().map(Into::into),
    });
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(addr = %config.bind, "listening");

    let mut http_shutdown = shutdown_rx;
    let server = axum::serve(listener, app).with_graceful_shutdown(async move {
        let _ = http_shutdown.wait_for(|stop| *stop).await;
    });
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            // Without a signal handler, keep running rather than exit at once.
            tracing::error!(error = %e, "cannot listen for ctrl-c");
            std::future::pending::<()>().await;
        }
        tracing::info!("shutdown requested; finishing in-flight jobs");
        let _ = shutdown_tx.send(true);
    });

    server.await?;
    workers.await?;
    Ok(())
}
