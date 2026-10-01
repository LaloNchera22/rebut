//! Shared vocabulary of the verifier.
//!
//! Every other crate speaks in these types. Two rules are encoded here and
//! nowhere else, so they cannot drift:
//!
//! * **ADR-6 — LLM output is never evidence.** A [`Hypothesis`] can never
//!   become a [`Finding`] on its own. A `Finding` is only constructible from a
//!   [`Reproduction`], which in turn is only constructible from an
//!   [`ExecutionResult`] produced by the execution fabric.
//! * **Sealed-challenge asymmetry.** [`Verdict::for_contributor`] is the only
//!   way to build what a contributor sees, and it strips every byte of a sealed
//!   finding except its category.

pub mod digest;
pub mod engine;
pub mod exec;
pub mod finding;
pub mod intent;
pub mod policy;
pub mod pr;
pub mod seed;
pub mod verdict;

pub use digest::Digest;
pub use engine::{Engine, EngineContext, EngineReport, FnSignature, ImpactPlan};
pub use exec::{ExecutionRequest, ExecutionResult, Executor, Step, StepOutcome};
pub use finding::{Finding, Hypothesis, HypothesisSource, Reproduction, Visibility};
pub use intent::{ChangeKind, IntentManifest};
pub use policy::{Budget, EnforcementMode, Policy};
pub use pr::{CommitSha, PullRequest, RepoId};
pub use seed::{DrandBeacon, Seed, GENERATOR_VERSION};
pub use verdict::{ContributorReport, Verdict, VerdictStatus};

/// Name of every engine that can emit findings. Kept closed so reports and
/// receipts stay stable across versions.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    Differential,
    Challenges,
    Mutation,
    Formal,
    /// The rival agent (`verifier-adversary`).
    Adversary,
}

impl std::fmt::Display for EngineKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            EngineKind::Differential => "differential",
            EngineKind::Challenges => "challenges",
            EngineKind::Mutation => "mutation",
            EngineKind::Formal => "formal",
            EngineKind::Adversary => "adversary",
        };
        f.write_str(s)
    }
}
