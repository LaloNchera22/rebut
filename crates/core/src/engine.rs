//! The engine contract. Control plane and CLI orchestrate engines only through
//! this trait, so engines can be added without touching orchestration.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{EngineKind, Executor, Finding, Hypothesis, IntentManifest, Policy, PullRequest, Seed};

/// A function signature the planner extracted from the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FnSignature {
    /// `crate_name::module::function` (crate name with `-` replaced by `_`).
    pub path: String,
    /// Argument types as written, e.g. `["u32", "&str"]`.
    pub args: Vec<String>,
    /// Return type as written, `()` if none.
    pub ret: String,
    pub is_pub: bool,
}

/// Output of the planner: what the diff touches and what to run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ImpactPlan {
    /// Paths of functions whose body changed between base and head.
    pub changed_functions: Vec<FnSignature>,
    /// Test names (as accepted by `cargo test <filter>`) that exercise them.
    pub tests: Vec<String>,
    /// Files touched by the diff.
    pub changed_files: Vec<String>,
    /// True when the diff touches something the planner can't reason about
    /// (build.rs, Cargo.toml, macros): engines should widen to the full suite.
    pub widen_to_full_suite: bool,
    /// Which functions the differential engine compares.
    #[serde(default)]
    pub scope: DiffScope,
    /// With [`DiffScope::AllPublic`]: every function of the crate under test
    /// that is reachable by a `pub` path from its root and has a shape a
    /// harness could call (no generics, `self`, `async`, `unsafe`...).
    /// Empty otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_functions: Vec<FnSignature>,
    /// With [`DiffScope::AllPublic`]: reachable public functions left out of
    /// `public_functions` because no harness can call them.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub public_skipped: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Which functions the differential engine compares between base and head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiffScope {
    /// Only functions whose code changed (the default).
    #[default]
    Changed,
    /// Every public, harnessable function of the crate under test, changed
    /// or not: for changes whose effect is not in the crate's own code, such
    /// as a dependency update (`cargo update`).
    AllPublic,
}

/// Everything an engine needs for one PR.
#[derive(Clone)]
pub struct EngineContext {
    pub pr: PullRequest,
    pub intent: IntentManifest,
    pub policy: Policy,
    pub plan: ImpactPlan,
    /// Present when a drand beacon was obtained (ADR-7).
    pub seed: Option<Seed>,
    /// Maintainer's sealed challenge specs (TOML), only on the server side.
    /// Their hashes must match `policy.sealed_commitments`.
    pub sealed_specs: Vec<String>,
    pub executor: Arc<dyn Executor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EngineReport {
    pub findings: Vec<Finding>,
    /// Hypotheses that could not be reproduced. Logged for tuning, never
    /// shown as findings (ADR-6).
    pub unreproduced: Vec<Hypothesis>,
    /// Set when the engine could not reach a conclusion (e.g. build failed).
    pub inconclusive: Option<String>,
    pub vm_seconds: u64,
}

#[async_trait::async_trait]
pub trait Engine: Send + Sync {
    fn kind(&self) -> EngineKind;
    async fn run(&self, ctx: &EngineContext) -> anyhow::Result<EngineReport>;
}
