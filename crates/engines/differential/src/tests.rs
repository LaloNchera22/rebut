//! Engine tests against a fake executor that simulates base and head.

use std::sync::{Arc, Mutex};

use rebut_core::{
    ChangeKind, CommitSha, ExecutionRequest, Executor, ImpactPlan, IntentManifest, Policy,
    PullRequest, RepoId, StepOutcome,
};

use super::*;

type HarnessSim = dyn Fn(Side, usize, &str) -> Option<String> + Send + Sync;
type TestSim = dyn Fn(Side, usize) -> Vec<(&'static str, bool)> + Send + Sync;

/// Simulates the fabric. `harness(side, run, line)` returns the payload for a
/// case (`None` = the process dies there); `tests(side, run)` the test
/// results. `run` counts executions per side, starting at 0.
struct Fake {
    build_ok: [bool; 2],
    harness: Box<HarnessSim>,
    tests: Box<TestSim>,
    runs: Mutex<[usize; 2]>,
    requests: Mutex<Vec<ExecutionRequest>>,
}

fn head_sha() -> CommitSha {
    CommitSha::new("b".repeat(40)).unwrap()
}

impl Fake {
    fn new(harness: impl Fn(Side, usize, &str) -> Option<String> + Send + Sync + 'static) -> Self {
        Fake {
            build_ok: [true, true],
            harness: Box::new(harness),
            tests: Box::new(|_, _| vec![]),
            runs: Mutex::new([0, 0]),
            requests: Mutex::new(vec![]),
        }
    }
}

#[async_trait::async_trait]
impl Executor for Fake {
    async fn execute(&self, req: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
        let side = if req.commit == head_sha() {
            Side::Head
        } else {
            Side::Base
        };
        let si = side as usize;
        let run = {
            let mut r = self.runs.lock().unwrap();
            r[si] += 1;
            r[si] - 1
        };
        self.requests.lock().unwrap().push(req.clone());
        let mut outcomes = Vec::new();
        for (i, step) in req.steps.iter().enumerate() {
            let (code, stdout) = match step {
                Step::Build { .. } => (if self.build_ok[si] { 0 } else { 101 }, String::new()),
                Step::Test { filters } => {
                    let mut out = String::new();
                    let mut code = 0;
                    for (name, pass) in (self.tests)(side, run) {
                        if filters.is_empty() || filters.iter().any(|f| name.contains(f.as_str())) {
                            out += &format!(
                                "test {name} ... {}\n",
                                if pass { "ok" } else { "FAILED" }
                            );
                            if !pass {
                                code = 101;
                            }
                        }
                    }
                    (code, out)
                }
                Step::Harness { input, .. } => {
                    let mut out = format!("{}\n", harness::START_MARKER);
                    let mut code = 0;
                    for (ci, line) in String::from_utf8(input.clone())
                        .unwrap()
                        .lines()
                        .enumerate()
                    {
                        match (self.harness)(side, run, line) {
                            Some(p) => out += &format!("case {ci} {p}\n"),
                            None => {
                                code = 134;
                                break;
                            }
                        }
                    }
                    (code, out)
                }
            };
            outcomes.push(StepOutcome {
                step_index: i,
                exit_code: Some(code),
                timed_out: false,
                stdout: stdout.into_bytes(),
                stderr: b"noise".to_vec(),
                duration_ms: 1500,
            });
            if matches!(step, Step::Build { .. }) && code != 0 {
                break;
            }
        }
        Ok(ExecutionResult {
            request_id: req.id,
            transcript: ExecutionResult::compute_transcript(&req, &outcomes),
            outcomes,
            environment: Digest::of(b"env"),
        })
    }
}

fn ctx(fake: Arc<Fake>, plan: ImpactPlan, intent: IntentManifest) -> EngineContext {
    EngineContext {
        pr: PullRequest {
            repo: RepoId {
                owner: "o".into(),
                name: "r".into(),
            },
            number: 7,
            base_sha: CommitSha::new("a".repeat(40)).unwrap(),
            head_sha: head_sha(),
            head_clone_url: "https://example.invalid/fork.git".into(),
            base_clone_url: "https://example.invalid/repo.git".into(),
            author: "someone".into(),
            body: String::new(),
        },
        intent,
        policy: Policy::default(),
        plan,
        seed: None,
        sealed_specs: vec![],
        executor: fake,
    }
}

fn refactor() -> IntentManifest {
    IntentManifest {
        kind: ChangeKind::Refactor,
        ..Default::default()
    }
}

fn plan_for(path: &str, args: &[&str]) -> ImpactPlan {
    ImpactPlan {
        changed_functions: vec![FnSignature {
            path: path.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            ret: "u32".into(),
            is_pub: true,
        }],
        ..Default::default()
    }
}

fn debug_payload(v: impl std::fmt::Debug) -> String {
    format!("ok {:?}", format!("{v:?}"))
}

/// base: `x.saturating_mul(2)`; head: `x.wrapping_mul(2)` — they differ
/// exactly when the multiplication overflows.
fn doubling(side: Side, _run: usize, line: &str) -> Option<String> {
    let x: u32 = line.parse().unwrap();
    Some(match side {
        Side::Base => debug_payload(x.saturating_mul(2)),
        Side::Head => debug_payload(x.wrapping_mul(2)),
    })
}

async fn run(fake: Fake, plan: ImpactPlan, intent: IntentManifest) -> (EngineReport, Arc<Fake>) {
    let fake = Arc::new(fake);
    let report = DifferentialEngine::new()
        .run(&ctx(fake.clone(), plan, intent))
        .await
        .unwrap();
    (report, fake)
}

#[tokio::test]
async fn divergence_is_confirmed_by_single_case_runs() {
    let (report, fake) = run(
        Fake::new(doubling),
        plan_for("mylib::double", &["u32"]),
        refactor(),
    )
    .await;
    assert!(report.inconclusive.is_none());
    assert!(!report.findings.is_empty() && report.findings.len() <= 3);
    let reqs = fake.requests.lock().unwrap();
    // 2 screening runs per side + 1 confirmation run per side.
    assert_eq!(reqs.len(), 6);
    let (base_c, head_c) = (&reqs[4], &reqs[5]);
    for (i, f) in report.findings.iter().enumerate() {
        assert_eq!(f.category, CATEGORY_DIVERGENCE);
        assert_eq!(f.target.as_deref(), Some("mylib::double"));
        assert!(f.is_actionable());
        assert_eq!(f.visibility, Visibility::Public);
        let r = f.reproduction();
        // The reproduction input is exactly the stdin of the confirming step.
        let Step::Harness { input, .. } = &head_c.steps[1 + i] else {
            panic!("expected harness step")
        };
        assert_eq!(r.input(), input.as_slice());
        let x: u32 = std::str::from_utf8(r.input())
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            x.checked_mul(2).is_none(),
            "only overflowing inputs diverge: {x}"
        );
        assert!(String::from_utf8_lossy(r.observed()).contains(&format!("{:?}", x.wrapping_mul(2))));
        assert_eq!(base_c.steps[1 + i], head_c.steps[1 + i]);
    }
    let confirm_ms = 1500 * (1 + report.findings.len() as u64);
    assert_eq!(report.vm_seconds, 12 + 2 * confirm_ms.div_ceil(1000));
}

#[tokio::test]
async fn divergence_explained_by_intent() {
    let intent = IntentManifest {
        kind: ChangeKind::Bugfix,
        changes_behavior_of: vec!["mylib::double".into()],
        summary: String::new(),
    };
    let (report, _) = run(
        Fake::new(doubling),
        plan_for("mylib::double", &["u32"]),
        intent,
    )
    .await;
    assert!(!report.findings.is_empty());
    assert!(report
        .findings
        .iter()
        .all(|f| f.explained_by_intent && !f.is_actionable()));
}

#[tokio::test]
async fn identical_behavior_has_no_findings() {
    let same = |_: Side, _: usize, line: &str| Some(debug_payload(line.len()));
    let (report, fake) = run(
        Fake::new(same),
        plan_for("mylib::f", &["&str", "Option<u8>"]),
        refactor(),
    )
    .await;
    assert_eq!(
        report,
        EngineReport {
            vm_seconds: 12,
            ..Default::default()
        }
    );
    // No confirmation phase.
    assert_eq!(fake.requests.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn nondeterministic_output_is_never_a_finding() {
    // Head embeds the run number (think: a timestamp or HashMap order) for
    // some inputs; base is stable.
    let flaky = |side: Side, run: usize, line: &str| {
        let x: u64 = line.parse().unwrap();
        Some(match side {
            Side::Head if x % 2 == 1 => debug_payload((x, run)),
            _ => debug_payload(x),
        })
    };
    let (report, _) = run(Fake::new(flaky), plan_for("mylib::f", &["u64"]), refactor()).await;
    assert!(report.findings.is_empty());
    assert!(report
        .unreproduced
        .iter()
        .any(|h| h.target == "mylib::f" && h.claim.contains("nondeterministic")));

    // Stable in screening but different in the confirmation run: a third
    // observation that disagrees means no finding either.
    let late = |side: Side, run: usize, line: &str| {
        let x: u64 = line.parse().unwrap();
        Some(match (side, run) {
            (Side::Head, 0 | 1) if x == 0 => debug_payload("changed"),
            _ => debug_payload(x),
        })
    };
    let (report, _) = run(Fake::new(late), plan_for("mylib::f", &["u64"]), refactor()).await;
    assert!(report.findings.is_empty());
    assert!(report
        .unreproduced
        .iter()
        .any(|h| h.claim.contains("did not reproduce")));
}

#[tokio::test]
async fn crash_on_head_is_a_divergence() {
    let crash = |side: Side, _: usize, line: &str| {
        let x: i32 = line.parse().unwrap();
        (side == Side::Base || x != -1).then(|| debug_payload(x))
    };
    let (report, _) = run(Fake::new(crash), plan_for("mylib::f", &["i32"]), refactor()).await;
    assert_eq!(report.findings.len(), 1);
    let r = report.findings[0].reproduction();
    assert_eq!(r.input(), b"-1\n");
    assert!(r.observed().starts_with(b"exit:Some(134)"));
}

#[tokio::test]
async fn test_regression_found_and_filtered() {
    let mut fake = Fake::new(|_, _, _| None);
    fake.tests = Box::new(|side, run| match side {
        Side::Base => vec![
            ("tests::a", true),
            ("tests::b", true),
            ("tests::flaky", true),
        ],
        Side::Head => vec![
            ("tests::a", true),
            ("tests::b", false),
            ("tests::flaky", run % 2 == 0),
            ("tests::new_failing", false),
        ],
    });
    let names = ["tests::a", "tests::b", "tests::flaky", "tests::new_failing"];
    let plan = ImpactPlan {
        tests: names.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    let (report, fake) = run(fake, plan, refactor()).await;
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    let f = &report.findings[0];
    assert_eq!(f.category, CATEGORY_TEST_REGRESSION);
    assert_eq!(f.target.as_deref(), Some("tests::b"));
    assert_eq!(f.reproduction().input(), b"tests::b");
    assert!(f.reproduction().expected().starts_with(b"exit:Some(0)"));
    assert!(f.reproduction().observed().starts_with(b"exit:Some(101)"));
    assert!(report
        .unreproduced
        .iter()
        .any(|h| h.target == "tests::flaky"));
    let reqs = fake.requests.lock().unwrap();
    assert_eq!(
        reqs[0].steps[1],
        Step::Test {
            filters: names.iter().map(|s| s.to_string()).collect()
        }
    );
}

#[tokio::test]
async fn widened_plan_runs_full_suite() {
    let mut fake = Fake::new(|_, _, _| None);
    fake.tests = Box::new(|_, _| vec![("x", true)]);
    let plan = ImpactPlan {
        widen_to_full_suite: true,
        ..Default::default()
    };
    let (report, fake) = run(fake, plan, refactor()).await;
    assert!(report.findings.is_empty());
    assert_eq!(
        fake.requests.lock().unwrap()[0].steps[1],
        Step::Test { filters: vec![] }
    );
}

#[tokio::test]
async fn build_failure_is_inconclusive() {
    for (build_ok, reason) in [
        ([true, false], "head does not build"),
        ([false, true], "base does not build"),
        (
            [false, false],
            "neither base nor head builds; nothing to compare",
        ),
    ] {
        let mut fake = Fake::new(doubling);
        fake.build_ok = build_ok;
        let (report, _) = run(fake, plan_for("mylib::double", &["u32"]), refactor()).await;
        assert!(report.findings.is_empty());
        assert_eq!(report.inconclusive.as_deref(), Some(reason));
    }
}

#[tokio::test]
async fn unsupported_functions_are_skipped() {
    let mut plan = plan_for("mylib::Counter::bump", &["&mut self", "u32"]);
    plan.changed_functions.push(FnSignature {
        path: "mylib::private".into(),
        args: vec![],
        ret: "()".into(),
        is_pub: false,
    });
    let (report, fake) = run(Fake::new(doubling), plan, refactor()).await;
    assert_eq!(report, EngineReport::default());
    assert!(fake.requests.lock().unwrap().is_empty());
}

#[test]
fn case_seed_prefers_drand_seed() {
    let fake = Arc::new(Fake::new(doubling));
    let mut c = ctx(fake, ImpactPlan::default(), refactor());
    let without = case_seed(&c, "a::f");
    c.seed = Some(Seed(Digest::of(b"drand")));
    assert_ne!(without, case_seed(&c, "a::f"));
    assert_ne!(case_seed(&c, "a::f"), case_seed(&c, "a::g"));
}

/// Compiles a generated harness with the local `rustc` against a stand-in
/// crate module and checks its real output. Skipped if `rustc` is missing.
#[test]
fn generated_harness_compiles_and_runs() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if Command::new("rustc").arg("--version").output().is_err() {
        eprintln!("rustc not available; skipping");
        return;
    }
    let args: Vec<ArgType> = ["&str", "Option<u8>", "&[u8]", "char", "bool", "i64"]
        .iter()
        .map(|s| ArgType::parse(s).unwrap())
        .collect();
    let mut src = harness::differential_source("mylib::f", &args);
    src.push_str(
        "mod mylib {\n\
         pub fn f(s: &str, o: Option<u8>, b: &[u8], c: char, flag: bool, n: i64) -> (usize, Option<u8>, usize, char, bool, i64) {\n\
             if n == i64::MIN { panic!(\"boom\") }\n\
             (s.chars().count(), o, b.len(), c, flag, n.abs())\n\
         }\n}\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let (src_path, bin) = (dir.path().join("main.rs"), dir.path().join("harness"));
    std::fs::write(&src_path, &src).unwrap();
    let status = Command::new("rustc")
        .args(["--edition", "2021", "-o"])
        .arg(&bin)
        .arg(&src_path)
        .status()
        .unwrap();
    assert!(status.success(), "harness failed to compile:\n{src}");

    let cases = gen::differential_cases(&args, &Seed(Digest::of(b"e2e")), 30);
    let lines: Vec<String> = cases.iter().map(|c| harness::encode_case(c)).collect();
    let mut child = Command::new(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&harness::encode_input(&lines))
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let parsed = HarnessOutput::parse(&out.stdout);
    assert!(parsed.started);
    assert_eq!(parsed.cases.len(), 30);
    for (i, case) in cases.iter().enumerate() {
        let payload = &parsed.cases[&i];
        match &case[5] {
            harness::Value::Int(n) if *n == i64::MIN as i128 => assert_eq!(payload, "panic"),
            harness::Value::Int(n) => {
                let harness::Value::Str(s) = &case[0] else {
                    panic!()
                };
                assert!(
                    payload.starts_with(&format!("ok \"({}, ", s.chars().count())),
                    "{payload}"
                );
                assert!(
                    payload.ends_with(&format!(", {})\"", n.unsigned_abs())),
                    "{payload}"
                );
            }
            other => panic!("{other:?}"),
        }
    }
}

fn pub_sig(path: &str, args: &[&str]) -> FnSignature {
    FnSignature {
        path: path.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        ret: "u32".into(),
        is_pub: true,
    }
}

#[test]
fn all_public_selects_unchanged_functions_up_to_a_cap() {
    let plan = ImpactPlan {
        changed_functions: vec![pub_sig("mylib::changed", &["u32"])],
        scope: DiffScope::AllPublic,
        public_functions: vec![
            pub_sig("mylib::a", &["u32"]),
            pub_sig("mylib::b", &["Vec<String>"]),
            pub_sig("mylib::c", &["&str", "Option<u8>"]),
            pub_sig("mylib::changed", &["u32"]),
        ],
        public_skipped: 2,
        ..Default::default()
    };
    let c = ctx(Arc::new(Fake::new(doubling)), plan.clone(), refactor());
    let sel = DifferentialEngine::new().select(&c);
    let picked: Vec<(&str, bool)> = sel
        .targets
        .iter()
        .map(|t| (t.sig.path.as_str(), t.changed))
        .collect();
    assert_eq!(
        picked,
        vec![
            ("mylib::changed", true),
            ("mylib::a", false),
            ("mylib::c", false)
        ]
    );
    // Two from the planner, plus `b`'s unsupported argument type.
    assert_eq!((sel.skipped, sel.truncated), (3, 0));

    let capped = DifferentialEngine::with_config(DifferentialConfig {
        max_public_functions: 2,
        ..Default::default()
    })
    .select(&c);
    assert_eq!(capped.targets.len(), 2);
    assert_eq!(capped.truncated, 1);

    // The default scope ignores the public list.
    let plan = ImpactPlan {
        scope: DiffScope::Changed,
        ..plan
    };
    let c = ctx(Arc::new(Fake::new(doubling)), plan, refactor());
    let sel = DifferentialEngine::new().select(&c);
    assert_eq!(sel.targets.len(), 1);
    assert_eq!((sel.skipped, sel.truncated), (0, 0));
}

#[tokio::test]
async fn divergence_in_an_unchanged_public_fn_needs_an_explicit_intent() {
    let plan = ImpactPlan {
        scope: DiffScope::AllPublic,
        public_functions: vec![pub_sig("mylib::double", &["u32"])],
        widen_to_full_suite: true,
        ..Default::default()
    };
    // An unspecified intent explains changes in changed functions, but this
    // one's code did not change: the dependency did.
    let (report, _) = run(Fake::new(doubling), plan.clone(), IntentManifest::default()).await;
    assert!(!report.findings.is_empty());
    for f in &report.findings {
        assert_eq!(f.category, CATEGORY_DIVERGENCE);
        assert!(f.is_actionable());
        assert!(f.title.contains("did not change"), "{}", f.title);
    }

    let intent = IntentManifest {
        kind: ChangeKind::Feature,
        changes_behavior_of: vec!["mylib".into()],
        summary: String::new(),
    };
    let (report, _) = run(Fake::new(doubling), plan, intent).await;
    assert!(!report.findings.is_empty());
    assert!(report.findings.iter().all(|f| !f.is_actionable()));
}
