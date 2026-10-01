//! Execution helpers shared by engines that talk to the fabric.

use rebut_core::{
    channel, CommitSha, EngineContext, ExecutionRequest, ExecutionResult, Step, StepOutcome,
};

/// Which commit of the PR a request runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Base,
    Head,
}

impl Side {
    pub fn repo_and_commit(self, ctx: &EngineContext) -> (&str, &CommitSha) {
        match self {
            Side::Base => (&ctx.pr.base_clone_url, &ctx.pr.base_sha),
            Side::Head => (&ctx.pr.head_clone_url, &ctx.pr.head_sha),
        }
    }
}

/// A request sized by the policy budget.
pub fn request(
    ctx: &EngineContext,
    side: Side,
    steps: Vec<Step>,
    sealed: bool,
) -> ExecutionRequest {
    let (url, commit) = side.repo_and_commit(ctx);
    let b = &ctx.policy.budget;
    ExecutionRequest {
        id: uuid::Uuid::new_v4(),
        repo_url: url.to_string(),
        commit: commit.clone(),
        steps,
        timeout_secs: b.vm_timeout_secs,
        vcpus: b.vcpus,
        memory_mib: b.memory_mib,
        sealed,
        env: Default::default(),
    }
}

/// Runs `steps` on `side` and adds the time spent to `vm_seconds`. Harness
/// steps go through the authenticated result channel: each gets a fresh
/// nonce, and its stdout comes back in canonical form (see
/// [`rebut_core::channel`]).
pub async fn execute(
    ctx: &EngineContext,
    side: Side,
    steps: Vec<Step>,
    sealed: bool,
    vm_seconds: &mut u64,
) -> anyhow::Result<ExecutionResult> {
    let result = channel::execute(ctx.executor.as_ref(), request(ctx, side, steps, sealed)).await?;
    let ms: u64 = result.outcomes.iter().map(|o| o.duration_ms).sum();
    *vm_seconds += ms.div_ceil(1000);
    Ok(result)
}

pub fn outcome(result: &ExecutionResult, step: usize) -> Option<&StepOutcome> {
    result.outcomes.iter().find(|o| o.step_index == step)
}

/// Whether step `step` succeeded in every run: `Some(true)` all succeeded,
/// `Some(false)` all failed (a missing outcome counts as failed), `None` the
/// runs disagree.
pub fn consistent_success(runs: &[ExecutionResult], step: usize) -> Option<bool> {
    let ok: Vec<bool> = runs
        .iter()
        .map(|r| outcome(r, step).is_some_and(StepOutcome::success))
        .collect();
    if ok.iter().all(|&b| b) {
        Some(true)
    } else if ok.iter().all(|&b| !b) {
        Some(false)
    } else {
        None
    }
}
