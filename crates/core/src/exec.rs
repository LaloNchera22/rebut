//! The contract between engines and the execution fabric.
//!
//! Engines describe *what* to run as a list of [`Step`]s; the fabric decides
//! *where* (a Firecracker microVM in production). Hostile code never runs
//! outside an [`Executor`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{CommitSha, Digest};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Step {
    /// `cargo build --locked --offline` (+ tests compiled). `build.rs` and
    /// proc-macros run here, which is why this is already inside the VM.
    Build { profile: String },
    /// Run test binaries, optionally filtered by name.
    Test { filters: Vec<String> },
    /// Run a harness binary produced by an engine with the given stdin.
    /// Used by differential and challenge engines to feed concrete inputs.
    Harness {
        name: String,
        source: String,
        input: Vec<u8>,
    },
    /// `cargo mutants --in-diff` scoped to `diff` (the unified diff from
    /// base to head), with a per-mutant `timeout_secs` and `jobs` parallel
    /// builds. On success stdout is the run's `mutants.out/outcomes.json`;
    /// cargo-mutants' own output goes to stderr. The exit code is
    /// cargo-mutants' (0 all caught, 2 some missed, 3 timeouts, 4 the
    /// unmutated baseline failed).
    Mutants {
        diff: String,
        timeout_secs: u64,
        jobs: u8,
    },
    /// Append `source` (a `#[cfg(kani)]` proof harness) to the crate root and
    /// run `cargo kani --harness <harness> -Z concrete-playback
    /// --concrete-playback=print`. Stdout is Kani's stdout.
    Kani { harness: String, source: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub id: uuid::Uuid,
    pub repo_url: String,
    pub commit: CommitSha,
    pub steps: Vec<Step>,
    pub timeout_secs: u64,
    pub vcpus: u8,
    pub memory_mib: u32,
    /// Sealed requests: stdout/stderr/timings never leave the VM toward the
    /// contributor. The fabric still returns them to the control plane, which
    /// routes them only to maintainer-visible storage.
    pub sealed: bool,
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepOutcome {
    pub step_index: usize,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
}

impl StepOutcome {
    pub fn success(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }
}

/// What the fabric returns. `transcript` is the content digest of the full,
/// canonical record of the run (request + outcomes + recording), stored in
/// the object store; findings point at it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub request_id: uuid::Uuid,
    pub outcomes: Vec<StepOutcome>,
    pub transcript: Digest,
    /// Digest of the microVM rootfs/kernel/snapshot used, for receipts.
    pub environment: Digest,
}

impl ExecutionResult {
    /// Canonical transcript digest over request and outcomes.
    pub fn compute_transcript(req: &ExecutionRequest, outcomes: &[StepOutcome]) -> Digest {
        let r = serde_json::to_vec(req).expect("request serializes");
        let o = serde_json::to_vec(outcomes).expect("outcomes serialize");
        Digest::of_parts(&[b"verifier/transcript/v1", &r, &o])
    }
}

#[async_trait::async_trait]
pub trait Executor: Send + Sync {
    async fn execute(&self, req: ExecutionRequest) -> anyhow::Result<ExecutionResult>;
}
