//! End to end through a fake fabric: the engine sends a `Step::Kani`
//! request, reads the canned Kani output, and replays any counterexample as a
//! normal `Step::Harness` request. Only a confirming replay is a finding.

use std::sync::{Arc, Mutex};

use rebut_core::{
    channel, ChangeKind, CommitSha, Digest, Engine, EngineContext, EngineKind, ExecutionRequest,
    ExecutionResult, Executor, FnSignature, IntentManifest, PullRequest, RepoId, Step, StepOutcome,
};
use rebut_formal::{
    encode_input, kani_request, FabricKaniRunner, FormalEngine, HarnessSpec, Invariant, KaniRunner,
    StaticProposer,
};

const FAILED: &str = r#"Kani Rust Rebut 0.56.0 (cargo plugin)
Checking harness rebut_proof_math_clamp_0...

RESULTS:
Check 1: rebut_proof_math_clamp_0.assertion.1
	 - Status: FAILURE
	 - Description: "rebut-formal invariant: ret >= a1 && ret <= a2"
	 - Location: src/lib.rs:31:5 in function rebut_proof_math_clamp_0


SUMMARY:
 ** 1 of 1 failed

VERIFICATION:- FAILED
Concrete playback unit test for `rebut_proof_math_clamp_0`:
```
#[test]
fn kani_concrete_playback_rebut_proof_math_clamp_0_1() {
    let concrete_vals: Vec<Vec<u8>> = vec![
        // -5
        vec![251, 255, 255, 255],
        // 0
        vec![0, 0, 0, 0],
        // 10
        vec![10, 0, 0, 0],
    ];
    kani::concrete_playback_run(concrete_vals, rebut_proof_math_clamp_0);
}
```
Verification Time: 0.41s
"#;

const VERIFIED: &str = "Kani Rust Rebut 0.56.0 (cargo plugin)\n\
RESULTS:\nCheck 1: rebut_proof_math_clamp_0.assertion.1\n\t - Status: SUCCESS\n\n\
SUMMARY:\n ** 0 of 1 failed\n\nVERIFICATION:- SUCCESSFUL\nVerification Time: 0.1s\n";

/// What the fake Kani step does.
#[derive(Clone, Copy)]
enum KaniStep {
    /// Exit code and stdout of a completed run.
    Done(i32, &'static str),
    TimedOut,
}

/// Fake fabric: answers `Step::Kani` with canned output and "runs" the replay
/// harness by evaluating a closure standing in for the compiled crate.
struct FakeFabric {
    kani: KaniStep,
    replay: fn(i32, i32, i32) -> (i32, &'static str),
    seen: Mutex<Vec<ExecutionRequest>>,
}

fn outcome(i: usize, code: Option<i32>, timed_out: bool, stdout: &[u8], ms: u64) -> StepOutcome {
    StepOutcome {
        step_index: i,
        exit_code: code,
        timed_out,
        stdout: stdout.to_vec(),
        stderr: vec![],
        duration_ms: ms,
    }
}

#[async_trait::async_trait]
impl Executor for FakeFabric {
    async fn execute(&self, req: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
        self.seen.lock().unwrap().push(req.clone());
        let outcomes = match &req.steps[..] {
            [Step::Kani { .. }] => vec![match self.kani {
                // Kani exits nonzero when verification fails.
                KaniStep::Done(code, out) => outcome(0, Some(code), false, out.as_bytes(), 45_000),
                KaniStep::TimedOut => outcome(0, None, true, b"Checking harness", 600_000),
            }],
            [Step::Build { .. }, Step::Harness { input, .. }] => {
                let (nonce, input) = channel::unseal_input(input).expect("sealed stdin");
                let v: Vec<i32> = input
                    .chunks(8)
                    .map(|c| i32::from_le_bytes(c[4..8].try_into().unwrap()))
                    .collect();
                let (code, out) = (self.replay)(v[0], v[1], v[2]);
                // The replay reports over the authenticated channel.
                let out = channel::frame(nonce, out.as_bytes());
                vec![
                    outcome(0, Some(0), false, b"", 20_000),
                    outcome(1, Some(code), false, &out, 100),
                ]
            }
            other => anyhow::bail!("unexpected steps {other:?}"),
        };
        let transcript = ExecutionResult::compute_transcript(&req, &outcomes);
        Ok(ExecutionResult {
            request_id: req.id,
            outcomes,
            transcript,
            environment: Digest::of(b"test-env"),
        })
    }
}

fn fabric(kani: KaniStep, replay: fn(i32, i32, i32) -> (i32, &'static str)) -> Arc<FakeFabric> {
    Arc::new(FakeFabric {
        kani,
        replay,
        seen: Mutex::new(vec![]),
    })
}

/// `x < lo` falls through unclamped.
fn buggy(x: i32, _lo: i32, hi: i32) -> (i32, &'static str) {
    if x > hi {
        (0, "rebut:start\nrebut:returned\nrebut:invariant:held\n")
    } else if x < 0 {
        (0, "rebut:start\nrebut:returned\nrebut:invariant:violated\n")
    } else {
        (0, "rebut:start\nrebut:returned\nrebut:invariant:held\n")
    }
}

fn correct(_: i32, _: i32, _: i32) -> (i32, &'static str) {
    (0, "rebut:start\nrebut:returned\nrebut:invariant:held\n")
}

fn clamp() -> FnSignature {
    FnSignature {
        path: "mylib::math::clamp".into(),
        args: vec!["i32".into(), "i32".into(), "i32".into()],
        ret: "i32".into(),
        is_pub: true,
    }
}

fn invariant() -> Invariant {
    Invariant {
        assumptions: vec!["a1 <= a2".into()],
        property: "ret >= a1 && ret <= a2".into(),
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
            base_sha: CommitSha::new("b".repeat(40)).unwrap(),
            head_sha: sha,
            head_clone_url: "https://example.invalid/head.git".into(),
            base_clone_url: "https://example.invalid/base.git".into(),
            author: "mallory".into(),
            body: String::new(),
        },
        intent: IntentManifest {
            kind: ChangeKind::Refactor,
            ..Default::default()
        },
        policy: Default::default(),
        plan: rebut_core::ImpactPlan {
            changed_functions: vec![clamp()],
            ..Default::default()
        },
        seed: None,
        sealed_specs: vec![],
        executor: exec,
    }
}

fn engine() -> FormalEngine {
    FormalEngine::new(Arc::new(StaticProposer(vec![invariant()])))
        .with_kani(Arc::new(FabricKaniRunner))
}

#[test]
fn kani_request_shape() {
    let c = ctx(fabric(KaniStep::Done(0, VERIFIED), correct));
    let h = HarnessSpec::new(&clamp(), &invariant(), 0)
        .unwrap()
        .kani_harness();
    let req = kani_request(&c, &h);
    assert_eq!(req.repo_url, "https://example.invalid/head.git");
    assert_eq!(req.commit, c.pr.head_sha);
    assert_eq!(req.timeout_secs, c.policy.budget.vm_timeout_secs);
    assert_eq!(req.vcpus, c.policy.budget.vcpus);
    assert_eq!(req.memory_mib, c.policy.budget.memory_mib);
    assert!(!req.sealed);
    assert!(req.env.is_empty());
    assert_eq!(
        req.steps,
        vec![Step::Kani {
            harness: "rebut_proof_math_clamp_0".into(),
            source: h.source.clone(),
        }]
    );
}

#[tokio::test]
async fn runner_returns_stdout_even_when_kani_exits_nonzero() {
    let f = fabric(KaniStep::Done(1, FAILED), correct);
    let h = HarnessSpec::new(&clamp(), &invariant(), 0)
        .unwrap()
        .kani_harness();
    let run = FabricKaniRunner.run(&ctx(f.clone()), &h).await.unwrap();
    assert_eq!(run.stdout, FAILED);
    assert_eq!(run.failure, None);
    assert_eq!(run.vm_seconds, 45);
    assert_eq!(f.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn runner_reports_why_there_is_no_verdict() {
    let h = HarnessSpec::new(&clamp(), &invariant(), 0)
        .unwrap()
        .kani_harness();
    let run = FabricKaniRunner
        .run(&ctx(fabric(KaniStep::TimedOut, correct)), &h)
        .await
        .unwrap();
    assert_eq!(run.failure.as_deref(), Some("timed out after 600s"));
    assert_eq!(run.vm_seconds, 600);
    let run = FabricKaniRunner
        .run(
            &ctx(fabric(
                KaniStep::Done(101, "error: could not compile"),
                correct,
            )),
            &h,
        )
        .await
        .unwrap();
    assert_eq!(
        run.failure.as_deref(),
        Some("kani exited 101 without a verdict")
    );
}

#[tokio::test]
async fn confirmed_counterexample_is_a_finding() {
    let f = fabric(KaniStep::Done(1, FAILED), buggy);
    let r = engine().run(&ctx(f.clone())).await.unwrap();
    assert_eq!(r.findings.len(), 1, "{r:?}");
    let finding = &r.findings[0];
    assert_eq!(finding.engine, EngineKind::Formal);
    assert_eq!(finding.category, "invariant-violation");
    assert!(finding.is_actionable());
    assert_eq!(
        finding.reproduction().input(),
        encode_input(&[vec![251, 255, 255, 255], vec![0; 4], vec![10, 0, 0, 0]])
    );
    assert!(r.unreproduced.is_empty());
    // 45s of Kani + 20s of replay.
    assert_eq!(r.vm_seconds, 65);
    let seen = f.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(matches!(&seen[0].steps[..], [Step::Kani { .. }]));
    assert!(matches!(
        &seen[1].steps[..],
        [Step::Build { .. }, Step::Harness { .. }]
    ));
}

#[tokio::test]
async fn unconfirmed_counterexample_stays_unreproduced() {
    let f = fabric(KaniStep::Done(1, FAILED), correct);
    let r = engine().run(&ctx(f.clone())).await.unwrap();
    assert!(r.findings.is_empty());
    assert_eq!(r.unreproduced.len(), 1);
    assert!(r.unreproduced[0].claim.contains("[counterexample:"));
    assert!(r.unreproduced[0].candidate_input.is_some());
    assert_eq!(f.seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn verified_reports_nothing_and_replays_nothing() {
    let f = fabric(KaniStep::Done(0, VERIFIED), buggy);
    let r = engine().run(&ctx(f.clone())).await.unwrap();
    assert!(r.findings.is_empty());
    assert!(r.unreproduced.is_empty());
    assert_eq!(r.vm_seconds, 45);
    assert_eq!(f.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn timeout_is_not_a_finding() {
    let f = fabric(KaniStep::TimedOut, buggy);
    let r = engine().run(&ctx(f.clone())).await.unwrap();
    assert!(r.findings.is_empty());
    assert_eq!(r.unreproduced.len(), 1);
    assert!(r.unreproduced[0]
        .claim
        .ends_with("[kani gave no verdict: timed out after 600s]"));
    assert_eq!(f.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn no_proposals_no_vm_time() {
    let f = fabric(KaniStep::Done(1, FAILED), buggy);
    let r = FormalEngine::new(Arc::new(StaticProposer::none()))
        .with_kani(Arc::new(FabricKaniRunner))
        .run(&ctx(f.clone()))
        .await
        .unwrap();
    assert_eq!(r, rebut_core::EngineReport::default());
    assert!(f.seen.lock().unwrap().is_empty());
}
