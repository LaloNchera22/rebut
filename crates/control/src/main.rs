//! `rebut-control`: HTTP API + worker pool in one process.
//!
//! Wires the planner, drand beacon, execution fabric and the engines
//! (differential, challenges, mutation; formal when an Anthropic API key is
//! configured; the rival agent with `REBUT_ADVERSARY` or that key) into the
//! orchestrator.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use rebut_adversary::{AdversaryConfig, AdversaryEngine};
use rebut_challenges::DrandClient;
use rebut_control::wiring::{
    BaseChallenges, CheckoutDiff, CheckoutPlanner, DirSealedSpecs, DrandBeaconSource, GitCheckouts,
    GitSource,
};
use rebut_control::{
    router, run_workers, AppState, Config, ExecutorKind, GitHubForge, NoSealedSpecs, Orchestrator,
    PgQueue, PgStore, RetryPolicy, SealedSpecSource, WorkerConfig, MIGRATOR,
};
use rebut_core::{Engine, ExecutionRequest, ExecutionResult, Executor};
use rebut_differential::DifferentialEngine;
use rebut_fabric::firecracker::jailer::JailerConfig;
use rebut_fabric::{FirecrackerConfig, FirecrackerExecutor, LocalProcessExecutor, SnapshotCache};
use rebut_formal::{AnthropicInvariantProposer, FabricKaniRunner, FormalEngine};
use rebut_mutation::MutationEngine;
use rebut_receipts::{Ed25519Signer, InMemoryLog, RekorLog, Signer, TransparencyLog};

/// `EXECUTOR=none`: refuses to run anything, so every verdict is inconclusive
/// rather than silently passing.
struct NoExecutor;

#[async_trait::async_trait]
impl Executor for NoExecutor {
    async fn execute(&self, _: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
        anyhow::bail!("no execution fabric configured (set EXECUTOR)")
    }
}

async fn executor(config: &Config, checkouts: &GitCheckouts) -> anyhow::Result<Arc<dyn Executor>> {
    let source = GitSource(checkouts.clone());
    Ok(match config.executor {
        ExecutorKind::None => {
            tracing::warn!("EXECUTOR=none: no code will run; verdicts are inconclusive");
            Arc::new(NoExecutor)
        }
        ExecutorKind::InsecureLocal => {
            Arc::new(LocalProcessExecutor::insecure_for_development(source))
        }
        ExecutorKind::Firecracker => {
            let fc = &config.firecracker;
            let snapshots = match &fc.fc_snapshot_dir {
                Some(dir) => Some(Arc::new(SnapshotCache::open(dir)?)),
                None => None,
            };
            let fc_config = FirecrackerConfig {
                jailer: JailerConfig {
                    jailer_bin: fc.fc_jailer.clone(),
                    firecracker_bin: fc.fc_firecracker.clone(),
                    uid: fc.fc_uid,
                    gid: fc.fc_gid,
                    chroot_base: fc.fc_chroot_base.clone(),
                    cgroup_root: fc.fc_cgroup_root.clone(),
                    seccomp_filter: fc.fc_seccomp_filter.clone(),
                },
                kernel: fc.fc_kernel.clone(),
                rootfs: fc.fc_rootfs.clone(),
                boot_args: fc.fc_boot_args.clone(),
                scratch_mib: fc.fc_scratch_mib,
                toolchain: fc.fc_toolchain.clone(),
                boot_grace: Duration::from_secs(30),
            };
            Arc::new(FirecrackerExecutor::new(fc_config, source, snapshots).await?)
        }
    })
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

    let checkouts = GitCheckouts::new(&config.checkout_dir);
    let drand = match &config.drand_url {
        Some(url) => DrandClient::new(url, rebut_challenges::drand::QUICKNET_CHAIN_HASH)?,
        None => DrandClient::quicknet()?,
    };
    let sealed: Arc<dyn SealedSpecSource> = match &config.sealed_specs_dir {
        Some(dir) => Arc::new(DirSealedSpecs(dir.clone())),
        None => Arc::new(NoSealedSpecs),
    };
    let mut engines: Vec<Arc<dyn Engine>> = vec![
        Arc::new(DifferentialEngine::new()),
        Arc::new(BaseChallenges(checkouts.clone())),
        Arc::new(MutationEngine::new().with_diff_source(Arc::new(CheckoutDiff(checkouts.clone())))),
    ];
    if config.anthropic_api_key.is_some() {
        let proposer = Arc::new(AnthropicInvariantProposer::from_env()?);
        engines.push(Arc::new(
            FormalEngine::new(proposer).with_kani(Arc::new(FabricKaniRunner)),
        ));
    } else {
        tracing::info!("ANTHROPIC_API_KEY unset: formal engine unavailable");
    }
    // `REBUT_ADVERSARY` picks the rival agent's provider (ADR-9); without
    // it, Anthropic when a key is set, as before.
    let adversary = match std::env::var("REBUT_ADVERSARY") {
        Ok(spec) => AdversaryConfig::parse(
            &spec,
            std::env::var("REBUT_ADVERSARY_URL").ok(),
            std::env::var("REBUT_ADVERSARY_MODEL").ok(),
        )
        .context("REBUT_ADVERSARY")?
        .map(|c| c.build().map(AdversaryEngine::new))
        .transpose()?,
        Err(_) if config.anthropic_api_key.is_some() => {
            Some(AdversaryEngine::anthropic_from_env()?)
        }
        Err(_) => None,
    };
    match adversary {
        Some(engine) => engines.push(Arc::new(engine)),
        None => {
            tracing::info!("rival agent unavailable (set REBUT_ADVERSARY or ANTHROPIC_API_KEY)")
        }
    }

    let orchestrator = Arc::new(Orchestrator {
        engines,
        executor: executor(&config, &checkouts).await?,
        store: store.clone(),
        signer,
        log: log.clone(),
        forge,
        planner: Arc::new(CheckoutPlanner(checkouts.clone())),
        beacon: Arc::new(DrandBeaconSource {
            source: drand,
            max_wait: Duration::from_secs(30),
        }),
        sealed,
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
