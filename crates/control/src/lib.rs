//! Control plane: one binary (modular monolith) that receives GitHub
//! webhooks, queues work in Postgres (ADR-3), orchestrates engines through
//! the core [`rebut_core::Engine`] and [`rebut_core::Executor`] traits,
//! signs receipts (ADR-5) and publishes check runs.
//!
//! Wiring seams for the real components: [`orchestrator::Planner`],
//! [`orchestrator::BeaconSource`], [`orchestrator::SealedSpecSource`],
//! `Vec<Arc<dyn Engine>>` and `Arc<dyn Executor>` on
//! [`orchestrator::Orchestrator`].

pub mod api;
pub mod config;
pub mod forge;
pub mod github;
pub mod orchestrator;
pub mod queue;
pub mod store;
pub mod webhook;
pub mod wiring;
pub mod worker;

pub use api::{router, AppState};
pub use config::{Config, ExecutorKind};
pub use forge::{CheckRun, Conclusion, Forge};
pub use github::GitHubForge;
pub use orchestrator::{
    BeaconSource, MeteredExecutor, NoSealedSpecs, Orchestrator, Planner, Processed,
    SealedSpecSource,
};
pub use queue::{Enqueued, InMemoryQueue, Job, JobQueue, PgQueue, RetryPolicy};
pub use store::{InMemoryStore, PgStore, RunRecord, Store};
pub use worker::{run_workers, WorkerConfig};

/// Schema migrations (`crates/control/migrations`), embedded at compile time.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
