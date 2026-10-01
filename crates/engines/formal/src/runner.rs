//! [`KaniRunner`] backed by the execution fabric ([`Step::Kani`]).

use std::collections::BTreeMap;

use rebut_core::{EngineContext, ExecutionRequest, Step};

use crate::codegen::GeneratedHarness;
use crate::kani::{parse_kani_output, KaniOutcome};
use crate::{KaniRun, KaniRunner};

/// Longest stderr excerpt kept in a failure note.
const STDERR_TAIL_CHARS: usize = 300;
/// The marker the guest appends when it caps a step's output.
const TRUNCATION_MARKER: &str = "[rebut: output truncated";

/// The request that runs one proof harness against the PR head. Kani
/// compiles the crate itself, so there is no separate `Build` step; the proof
/// is `#[cfg(kani)]` and does not affect any other step.
pub fn kani_request(ctx: &EngineContext, harness: &GeneratedHarness) -> ExecutionRequest {
    let b = &ctx.policy.budget;
    ExecutionRequest {
        id: uuid::Uuid::new_v4(),
        repo_url: ctx.pr.head_clone_url.clone(),
        commit: ctx.pr.head_sha.clone(),
        steps: vec![Step::Kani {
            harness: harness.name.clone(),
            source: harness.source.clone(),
        }],
        timeout_secs: b.vm_timeout_secs,
        vcpus: b.vcpus,
        memory_mib: b.memory_mib,
        sealed: false,
        env: BTreeMap::new(),
    }
}

/// Runs `cargo kani` in a fresh microVM through `ctx.executor`.
///
/// Kani exits nonzero when verification *fails*, which is the interesting
/// case, so the exit code is not used: the run is judged by whether stdout
/// carries a verdict. When it doesn't, [`KaniRun::failure`] says why (timeout,
/// Kani never started, compile error, truncated output).
#[derive(Debug, Clone, Copy, Default)]
pub struct FabricKaniRunner;

#[async_trait::async_trait]
impl KaniRunner for FabricKaniRunner {
    async fn run(
        &self,
        ctx: &EngineContext,
        harness: &GeneratedHarness,
    ) -> anyhow::Result<KaniRun> {
        let result = ctx.executor.execute(kani_request(ctx, harness)).await?;
        let vm_seconds = result.outcomes.iter().map(|o| o.duration_ms).sum::<u64>() / 1000;
        let Some(o) = result.outcomes.iter().find(|o| o.step_index == 0) else {
            return Ok(KaniRun {
                stdout: String::new(),
                vm_seconds,
                failure: Some("kani step did not run".into()),
            });
        };
        let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
        let failure = if parse_kani_output(&stdout) != KaniOutcome::Unknown {
            None
        } else if o.timed_out {
            Some(format!(
                "timed out after {}s",
                ctx.policy.budget.vm_timeout_secs
            ))
        } else if stdout.contains(TRUNCATION_MARKER) {
            Some("output truncated before the verdict".into())
        } else {
            match o.exit_code {
                None => Some("kani did not start or was killed".into()),
                Some(code) => Some(format!(
                    "kani exited {code} without a verdict{}",
                    stderr_tail(&o.stderr)
                )),
            }
        };
        Ok(KaniRun {
            stdout,
            vm_seconds,
            failure,
        })
    }
}

/// The last few non-empty stderr lines, on one line (usually the compile
/// error). Kept only in unreproduced hypotheses, for tuning.
fn stderr_tail(stderr: &[u8]) -> String {
    let s = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = s.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let tail = lines[lines.len().saturating_sub(3)..].join(" | ");
    if tail.is_empty() {
        return String::new();
    }
    let n = tail.chars().count();
    let tail: String = tail
        .chars()
        .skip(n.saturating_sub(STDERR_TAIL_CHARS))
        .collect();
    format!(": {tail}")
}
