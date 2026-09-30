//! Formal engine (phase 2): Kani proofs of proposed invariants.
//!
//! Pipeline, per changed function whose signature Kani can model:
//!
//! 1. An [`InvariantProposer`] (in practice an LLM) proposes invariants.
//!    Each one is a [`Hypothesis`] with [`HypothesisSource::Llm`] — a guess,
//!    worth nothing on its own (ADR-6).
//! 2. [`HarnessSpec::kani_harness`] renders a `#[kani::proof]` with
//!    `kani::any()` arguments and `kani::assume` preconditions.
//! 3. A [`KaniRunner`] runs `cargo kani` (inside the fabric) and
//!    [`parse_kani_output`] reads the verdict and the concrete counterexample
//!    printed by `--concrete-playback=print`.
//! 4. [`replay_counterexample`] replays that input through the ordinary
//!    [`Executor`] as a [`Step::Harness`] against the real crate. Only if the
//!    replay really violates the invariant (or panics) does
//!    [`Reproduction::confirm`] produce a [`Finding`].
//!
//! Kani itself must run in the microVM (it compiles the PR, so `build.rs`
//! executes). Core's [`Step`] has no variant for it; phase 2 adds
//! `Step::Kani { harness: String, source: String }` returning Kani's stdout.
//! Until then [`FormalEngine`] is constructed without a runner and reports
//! the proposed invariants as unreproduced hypotheses.

pub mod codegen;
pub mod kani;

use std::collections::BTreeMap;
use std::sync::Arc;

pub use codegen::{
    encode_input, kani_argv, ArgType, CodegenError, GeneratedHarness, HarnessSpec, Invariant,
    Scalar,
};
pub use kani::{check_shape, parse_kani_output, KaniOutcome};
use rebut_core::{
    Engine, EngineContext, EngineKind, EngineReport, ExecutionRequest, ExecutionResult, Finding,
    FnSignature, Hypothesis, HypothesisSource, IntentManifest, Reproduction, Step, Visibility,
};

/// Proposes invariants for a function. Implementations are typically LLM
/// clients; their output is untrusted and only ever becomes a [`Hypothesis`].
#[async_trait::async_trait]
pub trait InvariantProposer: Send + Sync {
    async fn propose(
        &self,
        function: &FnSignature,
        ctx: &EngineContext,
    ) -> anyhow::Result<Vec<Invariant>>;
}

/// Runs `cargo kani` ([`kani_argv`]) on the PR head with `harness.source`
/// appended to the crate root, returning Kani's stdout. Implementations must
/// execute inside the fabric, never on the host.
#[async_trait::async_trait]
pub trait KaniRunner: Send + Sync {
    async fn run(&self, ctx: &EngineContext, harness: &GeneratedHarness) -> anyhow::Result<String>;
}

/// The hypothesis an invariant stands for.
pub fn invariant_hypothesis(function: &FnSignature, invariant: &Invariant) -> Hypothesis {
    Hypothesis {
        source: HypothesisSource::Llm,
        target: function.path.clone(),
        claim: format!("proposed invariant: {}", invariant.describe()),
        candidate_input: None,
    }
}

/// Result of replaying one counterexample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayOutcome {
    Finding(Box<Finding>),
    /// The replay did not confirm the counterexample; the string says why.
    Unreproduced(String),
}

const START: &[u8] = b"rebut:start\n";
const EXPECTED: &[u8] = b"exit:Some(0)\nrebut:start\nrebut:invariant:held\n";

/// The request that replays `values` against the PR head.
pub fn replay_request(
    ctx: &EngineContext,
    spec: &HarnessSpec,
    values: &[Vec<u8>],
) -> ExecutionRequest {
    let h = spec.replay_harness();
    let b = &ctx.policy.budget;
    ExecutionRequest {
        id: uuid::Uuid::new_v4(),
        repo_url: ctx.pr.head_clone_url.clone(),
        commit: ctx.pr.head_sha.clone(),
        steps: vec![
            Step::Build {
                profile: "dev".to_string(),
            },
            Step::Harness {
                name: h.name,
                source: h.source,
                input: encode_input(values),
            },
        ],
        timeout_secs: b.vm_timeout_secs,
        vcpus: b.vcpus,
        memory_mib: b.memory_mib,
        sealed: false,
        env: BTreeMap::new(),
    }
}

/// Decide what a replay run shows. Step 0 is the build, step 1 the harness.
pub fn judge_replay(
    spec: &HarnessSpec,
    intent: &IntentManifest,
    result: &ExecutionResult,
    input: Vec<u8>,
) -> ReplayOutcome {
    let unrepro = |s: &str| ReplayOutcome::Unreproduced(s.to_string());
    match result.outcomes.iter().find(|o| o.step_index == 0) {
        Some(b) if b.success() => {}
        _ => return unrepro("build failed; replay inconclusive"),
    }
    let Some(run) = result.outcomes.iter().find(|o| o.step_index == 1) else {
        return unrepro("harness step did not run");
    };
    // Guard against false positives: a timeout is not a counterexample, and a
    // harness that never reached the call (decode error, link error) says
    // nothing about the function.
    if run.timed_out {
        return unrepro("replay timed out");
    }
    if !run.stdout.starts_with(START) {
        return unrepro("replay harness did not reach the function call");
    }
    if contains(&run.stdout, b"rebut:assumption-violated") {
        return unrepro("counterexample violates the invariant's preconditions");
    }
    let Some(repro) = Reproduction::confirm(result, 1, input, EXPECTED.to_vec()) else {
        return unrepro("invariant held on the real binary; Kani result not reproduced");
    };
    let violated = contains(repro.observed(), b"rebut:invariant:violated");
    let (category, title, explained) = if violated {
        (
            "invariant-violation",
            format!(
                "`{}` violates invariant `{}` on a concrete input",
                spec.function.path,
                spec.invariant.describe()
            ),
            // The invariant was proposed, not declared: if the contributor
            // said this function's behavior changes, a violated guess about
            // its behavior is informational.
            intent.allows_behavior_change(&spec.function.path),
        )
    } else {
        (
            "panic",
            format!("`{}` panics on a concrete input", spec.function.path),
            false,
        )
    };
    ReplayOutcome::Finding(Box::new(Finding::new(
        EngineKind::Formal,
        category,
        title,
        Visibility::Public,
        Some(spec.function.path.clone()),
        explained,
        repro,
    )))
}

/// Replay a Kani counterexample through the executor. Returns the outcome
/// and the VM-seconds spent.
pub async fn replay_counterexample(
    ctx: &EngineContext,
    spec: &HarnessSpec,
    values: Vec<Vec<u8>>,
) -> anyhow::Result<(ReplayOutcome, u64)> {
    if !spec.function.is_pub {
        return Ok((
            ReplayOutcome::Unreproduced(
                "function is private; cannot be replayed from a harness".into(),
            ),
            0,
        ));
    }
    if let Err(e) = check_shape(&values, &spec.args) {
        return Ok((ReplayOutcome::Unreproduced(e), 0));
    }
    let req = replay_request(ctx, spec, &values);
    let input = encode_input(&values);
    let result = ctx.executor.execute(req).await?;
    let secs = result.outcomes.iter().map(|o| o.duration_ms).sum::<u64>() / 1000;
    Ok((judge_replay(spec, &ctx.intent, &result, input), secs))
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// The formal engine.
pub struct FormalEngine {
    proposer: Arc<dyn InvariantProposer>,
    kani: Option<Arc<dyn KaniRunner>>,
    /// Upper bound on invariants tried per function (VM budget).
    pub max_invariants_per_fn: usize,
}

impl FormalEngine {
    /// Phase-1 construction: no Kani runner, proposals are only recorded.
    pub fn new(proposer: Arc<dyn InvariantProposer>) -> Self {
        FormalEngine {
            proposer,
            kani: None,
            max_invariants_per_fn: 4,
        }
    }

    pub fn with_kani(mut self, runner: Arc<dyn KaniRunner>) -> Self {
        self.kani = Some(runner);
        self
    }
}

#[async_trait::async_trait]
impl Engine for FormalEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::Formal
    }

    async fn run(&self, ctx: &EngineContext) -> anyhow::Result<EngineReport> {
        let mut report = EngineReport::default();
        for function in &ctx.plan.changed_functions {
            let invariants = match self.proposer.propose(function, ctx).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(function = %function.path, error = %e, "invariant proposer failed");
                    continue;
                }
            };
            for (i, inv) in invariants
                .iter()
                .take(self.max_invariants_per_fn)
                .enumerate()
            {
                let mut hyp = invariant_hypothesis(function, inv);
                let spec = match HarnessSpec::new(function, inv, i) {
                    Ok(s) => s,
                    Err(e) => {
                        hyp.claim.push_str(&format!(" [not checked: {e}]"));
                        report.unreproduced.push(hyp);
                        continue;
                    }
                };
                let Some(kani) = &self.kani else {
                    hyp.claim
                        .push_str(" [not checked: Kani executor step lands in phase 2]");
                    report.unreproduced.push(hyp);
                    continue;
                };
                let out = match kani.run(ctx, &spec.kani_harness()).await {
                    Ok(o) => o,
                    Err(e) => {
                        hyp.claim.push_str(&format!(" [kani failed: {e}]"));
                        report.unreproduced.push(hyp);
                        continue;
                    }
                };
                match parse_kani_output(&out) {
                    // Proved: nothing to report, and nothing to tune either.
                    KaniOutcome::Verified => {}
                    KaniOutcome::Unknown => {
                        hyp.claim.push_str(" [kani gave no verdict]");
                        report.unreproduced.push(hyp);
                    }
                    KaniOutcome::Failed {
                        counterexample: None,
                        ..
                    } => {
                        hyp.claim
                            .push_str(" [kani failed without a concrete counterexample]");
                        report.unreproduced.push(hyp);
                    }
                    KaniOutcome::Failed {
                        counterexample: Some(values),
                        ..
                    } => {
                        let input = encode_input(&values);
                        let (outcome, secs) = replay_counterexample(ctx, &spec, values).await?;
                        report.vm_seconds += secs;
                        match outcome {
                            ReplayOutcome::Finding(f) => report.findings.push(*f),
                            ReplayOutcome::Unreproduced(why) => {
                                hyp.claim.push_str(&format!(" [counterexample: {why}]"));
                                hyp.candidate_input = Some(input);
                                report.unreproduced.push(hyp);
                            }
                        }
                    }
                }
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rebut_core::{CommitSha, Digest, Executor, PullRequest, RepoId, StepOutcome};
    use std::sync::Mutex;

    /// Fake fabric: "runs" the replay by evaluating a Rust closure standing in
    /// for the compiled harness.
    struct FakeExec {
        stdout: fn(&[u8]) -> (i32, Vec<u8>),
        seen: Mutex<Vec<ExecutionRequest>>,
    }

    #[async_trait::async_trait]
    impl Executor for FakeExec {
        async fn execute(&self, req: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
            let Step::Harness { input, .. } = &req.steps[1] else {
                anyhow::bail!("expected harness step");
            };
            let (code, stdout) = (self.stdout)(input);
            let outcomes = vec![
                StepOutcome {
                    step_index: 0,
                    exit_code: Some(0),
                    timed_out: false,
                    stdout: vec![],
                    stderr: vec![],
                    duration_ms: 2000,
                },
                StepOutcome {
                    step_index: 1,
                    exit_code: Some(code),
                    timed_out: false,
                    stdout,
                    stderr: vec![],
                    duration_ms: 10,
                },
            ];
            let transcript = ExecutionResult::compute_transcript(&req, &outcomes);
            self.seen.lock().unwrap().push(req.clone());
            Ok(ExecutionResult {
                request_id: req.id,
                outcomes,
                transcript,
                environment: Digest::of(b"test-env"),
            })
        }
    }

    /// Buggy clamp on the head: returns `x` when `x < lo`.
    fn buggy_clamp(input: &[u8]) -> (i32, Vec<u8>) {
        let v: Vec<i32> = input
            .chunks(8)
            .map(|c| i32::from_le_bytes(c[4..8].try_into().unwrap()))
            .collect();
        let (x, lo, hi) = (v[0], v[1], v[2]);
        if lo > hi {
            return (0, b"rebut:start\nrebut:assumption-violated\n".to_vec());
        }
        let ret = if x > hi { hi } else { x };
        let held = ret >= lo && ret <= hi;
        let line = if held { "held" } else { "violated" };
        (
            0,
            format!("rebut:start\nrebut:invariant:{line}\n").into_bytes(),
        )
    }

    struct FixedProposer;
    #[async_trait::async_trait]
    impl InvariantProposer for FixedProposer {
        async fn propose(
            &self,
            _: &FnSignature,
            _: &EngineContext,
        ) -> anyhow::Result<Vec<Invariant>> {
            Ok(vec![Invariant {
                assumptions: vec!["a1 <= a2".into()],
                property: "ret >= a1 && ret <= a2".into(),
            }])
        }
    }

    struct CannedKani(String);
    #[async_trait::async_trait]
    impl KaniRunner for CannedKani {
        async fn run(&self, _: &EngineContext, h: &GeneratedHarness) -> anyhow::Result<String> {
            assert!(h.source.contains("#[kani::proof]"));
            Ok(self.0.clone())
        }
    }

    fn ctx(exec: Arc<dyn Executor>) -> EngineContext {
        let sha = CommitSha::new("c".repeat(40)).unwrap();
        EngineContext {
            pr: PullRequest {
                repo: RepoId {
                    owner: "o".into(),
                    name: "mylib".into(),
                },
                number: 7,
                base_sha: sha.clone(),
                head_sha: sha,
                head_clone_url: "https://example.invalid/head.git".into(),
                base_clone_url: "https://example.invalid/base.git".into(),
                author: "mallory".into(),
                body: String::new(),
            },
            intent: IntentManifest::default(),
            policy: Default::default(),
            plan: rebut_core::ImpactPlan {
                changed_functions: vec![FnSignature {
                    path: "mylib::math::clamp".into(),
                    args: vec!["i32".into(), "i32".into(), "i32".into()],
                    ret: "i32".into(),
                    is_pub: true,
                }],
                ..Default::default()
            },
            seed: None,
            sealed_specs: vec![],
            executor: exec,
        }
    }

    fn exec(f: fn(&[u8]) -> (i32, Vec<u8>)) -> Arc<FakeExec> {
        Arc::new(FakeExec {
            stdout: f,
            seen: Mutex::new(vec![]),
        })
    }

    #[tokio::test]
    async fn without_kani_everything_stays_a_hypothesis() {
        let e = exec(buggy_clamp);
        let r = FormalEngine::new(Arc::new(FixedProposer))
            .run(&ctx(e.clone()))
            .await
            .unwrap();
        assert!(r.findings.is_empty());
        assert_eq!(r.unreproduced.len(), 1);
        assert_eq!(r.unreproduced[0].source, HypothesisSource::Llm);
        assert!(e.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn kani_counterexample_becomes_finding_only_after_replay() {
        let e = exec(buggy_clamp);
        let engine = FormalEngine::new(Arc::new(FixedProposer))
            .with_kani(Arc::new(CannedKani(kani::FAILED_FIXTURE.to_string())));
        // With no declared intent, a violated *proposed* invariant is
        // informational: the guess may simply be wrong about the new behavior.
        let r = engine.run(&ctx(e.clone())).await.unwrap();
        assert_eq!(r.findings.len(), 1, "{r:?}");
        assert!(!r.findings[0].is_actionable());
        // Under a declared refactor, the same counterexample counts.
        let mut c = ctx(e.clone());
        c.intent.kind = rebut_core::ChangeKind::Refactor;
        let r = engine.run(&c).await.unwrap();
        let f = &r.findings[0];
        assert_eq!(f.category, "invariant-violation");
        assert_eq!(f.engine, EngineKind::Formal);
        assert!(f.is_actionable());
        assert_eq!(
            f.reproduction().input(),
            encode_input(&[vec![0, 0, 0, 128], vec![0, 0, 0, 0], vec![10, 0, 0, 0]])
        );
        // The replay went through the executor as a normal harness.
        let seen = e.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(
            matches!(&seen[0].steps[1], Step::Harness { source, .. } if source.contains("mylib::math::clamp(a0, a1, a2)"))
        );
    }

    #[tokio::test]
    async fn kani_claim_that_does_not_replay_is_not_a_finding() {
        // A correct clamp: Kani's (spurious, e.g. modelling bug) counterexample
        // does not reproduce on the real binary.
        fn correct(_: &[u8]) -> (i32, Vec<u8>) {
            (0, b"rebut:start\nrebut:invariant:held\n".to_vec())
        }
        let e = exec(correct);
        let engine = FormalEngine::new(Arc::new(FixedProposer))
            .with_kani(Arc::new(CannedKani(kani::FAILED_FIXTURE.to_string())));
        let r = engine.run(&ctx(e)).await.unwrap();
        assert!(r.findings.is_empty());
        assert_eq!(r.unreproduced.len(), 1);
        assert!(r.unreproduced[0].candidate_input.is_some());
    }

    #[tokio::test]
    async fn harness_that_never_starts_is_not_a_finding() {
        fn link_error(_: &[u8]) -> (i32, Vec<u8>) {
            (101, b"".to_vec())
        }
        let e = exec(link_error);
        let engine = FormalEngine::new(Arc::new(FixedProposer))
            .with_kani(Arc::new(CannedKani(kani::FAILED_FIXTURE.to_string())));
        let r = engine.run(&ctx(e)).await.unwrap();
        assert!(r.findings.is_empty());
    }

    #[tokio::test]
    async fn panic_after_start_is_a_panic_finding() {
        fn panics(_: &[u8]) -> (i32, Vec<u8>) {
            (101, b"rebut:start\n".to_vec())
        }
        let e = exec(panics);
        let engine = FormalEngine::new(Arc::new(FixedProposer))
            .with_kani(Arc::new(CannedKani(kani::FAILED_FIXTURE.to_string())));
        let r = engine.run(&ctx(e)).await.unwrap();
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].category, "panic");
    }
}
