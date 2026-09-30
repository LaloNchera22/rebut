//! Engine tests against a fake executor, plus a real compile-and-run of the
//! generated challenge harnesses.

use std::sync::{Arc, Mutex};

use verifier_core::{
    CommitSha, ExecutionRequest, Executor, ImpactPlan, IntentManifest, Policy, PullRequest, RepoId,
    Seed,
};

use super::*;

/// `sim(harness_name, run, line)` -> payload, `None` = the process dies.
type Sim = dyn Fn(&str, usize, &str) -> Option<String> + Send + Sync;

struct Fake {
    sim: Box<Sim>,
    build_ok: bool,
    runs: Mutex<usize>,
    requests: Mutex<Vec<ExecutionRequest>>,
}

impl Fake {
    fn new(sim: impl Fn(&str, usize, &str) -> Option<String> + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Fake {
            sim: Box::new(sim),
            build_ok: true,
            runs: Mutex::new(0),
            requests: Mutex::new(vec![]),
        })
    }
}

#[async_trait::async_trait]
impl Executor for Fake {
    async fn execute(&self, req: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
        let run = {
            let mut r = self.runs.lock().unwrap();
            *r += 1;
            *r - 1
        };
        self.requests.lock().unwrap().push(req.clone());
        let mut outcomes = Vec::new();
        for (i, step) in req.steps.iter().enumerate() {
            let (code, stdout) = match step {
                Step::Build { .. } => (if self.build_ok { 0 } else { 101 }, String::new()),
                Step::Harness { name, input, .. } => {
                    let mut out = format!("{START_MARKER}\n");
                    let mut code = 0;
                    for (ci, line) in String::from_utf8(input.clone())
                        .unwrap()
                        .lines()
                        .enumerate()
                    {
                        match (self.sim)(name, run, line) {
                            Some(p) => out += &format!("case {ci} {p}\n"),
                            None => {
                                code = 134;
                                break;
                            }
                        }
                    }
                    (code, out)
                }
                Step::Test { .. } | Step::Mutants { .. } | Step::Kani { .. } => {
                    unreachable!("challenges only build and run harnesses")
                }
            };
            outcomes.push(StepOutcome {
                step_index: i,
                exit_code: Some(code),
                timed_out: false,
                stdout: stdout.into_bytes(),
                stderr: vec![],
                duration_ms: 10,
            });
            if code != 0 && matches!(step, Step::Build { .. }) {
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

fn head() -> CommitSha {
    CommitSha::new("e".repeat(40)).unwrap()
}

fn ctx(fake: Arc<Fake>, sealed_specs: Vec<String>, commitments: Vec<Digest>) -> EngineContext {
    EngineContext {
        pr: PullRequest {
            repo: RepoId {
                owner: "o".into(),
                name: "r".into(),
            },
            number: 1,
            base_sha: CommitSha::new("d".repeat(40)).unwrap(),
            head_sha: head(),
            head_clone_url: "https://example.invalid/fork.git".into(),
            base_clone_url: "https://example.invalid/repo.git".into(),
            author: "a".into(),
            body: String::new(),
        },
        intent: IntentManifest::default(),
        policy: Policy {
            sealed_commitments: commitments,
            ..Policy::default()
        },
        plan: ImpactPlan::default(),
        seed: Some(Seed(Digest::of(b"drand round 1234"))),
        sealed_specs,
        executor: fake,
    }
}

const PUBLIC: &str = r#"
[[challenge]]
id = "parse"
target = "mylib::parse"
cases = 50
args = [{ ty = "&str", alphabet = "12-", len = [0, 4] }]
oracle = { kind = "no_panic" }
"#;

const SEALED: &str = r#"
[[challenge]]
id = "secret-range"
target = "mylib::clamp"
category = "out-of-range"
cases = 30
args = [{ ty = "i32", min = -500, max = 500 }]
oracle = { kind = "property", expr = "output.abs() <= 100" }
"#;

fn decode_str(line: &str) -> String {
    String::from_utf8(hex::decode(line.strip_prefix('s').unwrap()).unwrap()).unwrap()
}

/// `parse` panics on inputs starting with '-'; `clamp` is wrong above 100.
fn buggy(name: &str, _run: usize, line: &str) -> Option<String> {
    let ok = match name {
        "challenge_parse" => !decode_str(line).starts_with('-'),
        "challenge_secret_range" => line.parse::<i32>().unwrap() <= 100,
        other => panic!("unexpected harness {other}"),
    };
    Some(
        if ok {
            "pass"
        } else if name == "challenge_parse" {
            "panic"
        } else {
            "fail"
        }
        .into(),
    )
}

#[tokio::test]
async fn public_failure_becomes_public_finding() {
    let fake = Fake::new(buggy);
    let report = ChallengesEngine::with_public_specs(PUBLIC)
        .run(&ctx(fake.clone(), vec![], vec![]))
        .await
        .unwrap();
    assert!(report.inconclusive.is_none());
    assert_eq!(report.findings.len(), 3, "capped per challenge");
    for f in &report.findings {
        assert_eq!(f.engine, EngineKind::Challenges);
        assert_eq!(f.category, "panic");
        assert_eq!(f.visibility, Visibility::Public);
        assert_eq!(f.target.as_deref(), Some("mylib::parse"));
        let r = f.reproduction();
        assert_eq!(r.expected(), b"exit:Some(0)\n#harness-start\ncase 0 pass\n");
        assert_eq!(
            r.observed(),
            b"exit:Some(0)\n#harness-start\ncase 0 panic\n"
        );
        let line = std::str::from_utf8(r.input()).unwrap().trim_end();
        assert!(decode_str(line).starts_with('-'));
    }
    let reqs = fake.requests.lock().unwrap();
    assert_eq!(reqs.len(), 3, "two screening runs and one confirmation");
    assert!(reqs.iter().all(|r| r.commit == head() && !r.sealed));
    // The finding's transcript is the confirmation run's.
    let Step::Harness { input, .. } = &reqs[2].steps[1] else {
        panic!()
    };
    assert_eq!(report.findings[0].reproduction().input(), input.as_slice());
}

#[tokio::test]
async fn sealed_specs_run_sealed_and_stay_sealed() {
    let fake = Fake::new(buggy);
    let commitment = Digest::of(SEALED.as_bytes());
    let report = ChallengesEngine::with_public_specs(PUBLIC)
        .run(&ctx(fake.clone(), vec![SEALED.into()], vec![commitment]))
        .await
        .unwrap();
    let sealed: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.visibility == Visibility::Sealed)
        .collect();
    assert!(!sealed.is_empty());
    assert!(sealed.iter().all(|f| f.category == "out-of-range"));
    for req in fake.requests.lock().unwrap().iter() {
        let names: Vec<&str> = req
            .steps
            .iter()
            .filter_map(|s| match s {
                Step::Harness { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        // Sealed and public cases never share a request.
        if req.sealed {
            assert!(names.iter().all(|n| *n == "challenge_secret_range"));
        } else {
            assert!(names.iter().all(|n| *n == "challenge_parse"));
        }
    }
}

#[tokio::test]
async fn uncommitted_sealed_spec_is_rejected() {
    let fake = Fake::new(buggy);
    let wrong = Digest::of(b"some other spec");
    let err = ChallengesEngine::new()
        .run(&ctx(fake.clone(), vec![SEALED.into()], vec![wrong]))
        .await
        .unwrap_err();
    assert!(matches!(
        err.downcast_ref::<SpecError>(),
        Some(SpecError::UncommittedSealedSpec(_))
    ));
    assert!(fake.requests.lock().unwrap().is_empty(), "nothing ran");
}

#[tokio::test]
async fn flaky_failures_are_not_findings() {
    // Fails only in the first screening run.
    let fake = Fake::new(|_, run, _| Some(if run == 0 { "panic" } else { "pass" }.into()));
    let report = ChallengesEngine::with_public_specs(PUBLIC)
        .run(&ctx(fake.clone(), vec![], vec![]))
        .await
        .unwrap();
    assert!(report.findings.is_empty());
    assert!(report
        .unreproduced
        .iter()
        .any(|h| h.claim.contains("different results")));
    assert_eq!(
        fake.requests.lock().unwrap().len(),
        2,
        "no confirmation needed"
    );

    // Stable in screening, passing in the confirmation run.
    let fake = Fake::new(|_, run, _| Some(if run < 2 { "fail" } else { "pass" }.into()));
    let report = ChallengesEngine::with_public_specs(PUBLIC)
        .run(&ctx(fake, vec![], vec![]))
        .await
        .unwrap();
    assert!(report.findings.is_empty());
    assert!(report
        .unreproduced
        .iter()
        .any(|h| h.claim.contains("did not reproduce")));
}

#[tokio::test]
async fn crash_is_a_finding() {
    let fake = Fake::new(|_, _, line| (!decode_str(line).contains("21")).then(|| "pass".into()));
    let report = ChallengesEngine::with_public_specs(PUBLIC)
        .run(&ctx(fake, vec![], vec![]))
        .await
        .unwrap();
    assert_eq!(report.findings.len(), 1);
    let r = report.findings[0].reproduction();
    assert!(r.observed().starts_with(b"exit:Some(134)"));
    assert!(decode_str(std::str::from_utf8(r.input()).unwrap().trim_end()).contains("21"));
}

#[tokio::test]
async fn build_failure_and_missing_seed_are_inconclusive() {
    let mut fake = Fake::new(buggy);
    Arc::get_mut(&mut fake).unwrap().build_ok = false;
    let report = ChallengesEngine::with_public_specs(PUBLIC)
        .run(&ctx(fake, vec![], vec![]))
        .await
        .unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.inconclusive.as_deref(), Some("head does not build"));

    let fake = Fake::new(buggy);
    let mut c = ctx(fake.clone(), vec![], vec![]);
    c.seed = None;
    let report = ChallengesEngine::with_public_specs(PUBLIC)
        .run(&c)
        .await
        .unwrap();
    assert!(report.inconclusive.unwrap().contains("drand"));
    assert!(fake.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn harness_that_does_not_start_is_not_a_finding() {
    let fake = Fake::new(buggy);
    struct NoStart(Arc<Fake>);
    #[async_trait::async_trait]
    impl Executor for NoStart {
        async fn execute(&self, req: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
            let mut r = self.0.execute(req).await?;
            for o in r.outcomes.iter_mut().skip(1) {
                o.stdout.clear();
                o.exit_code = Some(1);
            }
            Ok(r)
        }
    }
    let mut c = ctx(fake.clone(), vec![], vec![]);
    c.executor = Arc::new(NoStart(fake));
    let report = ChallengesEngine::with_public_specs(PUBLIC)
        .run(&c)
        .await
        .unwrap();
    assert!(report.findings.is_empty());
    assert!(report.unreproduced[0].claim.contains("did not compile"));
}

#[tokio::test]
async fn public_budget_caps_cases() {
    let fake = Fake::new(|_, _, _| Some("pass".into()));
    let mut c = ctx(fake.clone(), vec![], vec![]);
    c.policy.budget.public_challenges = 10;
    let report = ChallengesEngine::with_public_specs(PUBLIC)
        .run(&c)
        .await
        .unwrap();
    assert_eq!(report.findings.len(), 0);
    let reqs = fake.requests.lock().unwrap();
    let Step::Harness { input, .. } = &reqs[0].steps[1] else {
        panic!()
    };
    assert_eq!(input.iter().filter(|b| **b == b'\n').count(), 10);
}

#[test]
fn from_base_checkout_reads_specs() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("checkout");
    assert!(ChallengesEngine::from_base_checkout(&dir)
        .unwrap()
        .public_specs
        .is_none());
    std::fs::create_dir_all(dir.join(".verifier")).unwrap();
    std::fs::write(dir.join(PUBLIC_SPECS_PATH), PUBLIC).unwrap();
    let e = ChallengesEngine::from_base_checkout(&dir).unwrap();
    assert_eq!(e.public_specs.as_deref(), Some(PUBLIC));
}

/// Compiles each oracle's harness with the local `rustc` against a stand-in
/// crate module and checks the real pass/fail markers.
#[test]
fn generated_harnesses_compile_and_judge_correctly() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if Command::new("rustc").arg("--version").output().is_err() {
        eprintln!("rustc not available; skipping");
        return;
    }
    let specs = r#"
[[challenge]]
id = "parse"
target = "mylib::parse"
args = [{ ty = "&str", alphabet = "12-", len = [0, 3] }]
oracle = { kind = "no_panic" }

[[challenge]]
id = "clamp"
target = "mylib::clamp"
args = [{ ty = "i32", min = -1000, max = 1000 }, { ty = "Option<u8>" }]
oracle = { kind = "property", expr = "output >= -100 && output <= 100 && input.1.is_some() == input.1.is_some()" }

[[challenge]]
id = "hex"
target = "mylib::to_hex"
args = [{ ty = "&[u8]", len = [0, 8] }]
oracle = { kind = "roundtrip", decode = "mylib::from_hex", decode_returns = "option" }

[[challenge]]
id = "abs"
target = "mylib::abs"
args = [{ ty = "i64" }]
oracle = { kind = "equals_reference", source = "fn reference(x: i64) -> i64 { x.abs() }" }
"#;
    let stand_in = r#"
mod mylib {
    pub fn parse(s: &str) -> i64 { s.parse().unwrap() }
    // Bug: upper bound off by one.
    pub fn clamp(x: i32, _o: Option<u8>) -> i32 { x.clamp(-100, 101) }
    pub fn to_hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
    pub fn from_hex(s: &str) -> Option<Vec<u8>> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
    }
    pub fn abs(x: i64) -> i64 { x.wrapping_abs() }
}
"#;
    let seed = Seed(Digest::of(b"e2e"));
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    for ch in spec::parse_public(specs).unwrap() {
        let src = format!("{}{stand_in}", spec::harness_source(&ch));
        let (src_path, bin) = (
            dir.join(format!("{}.rs", ch.spec.id)),
            dir.join(&ch.spec.id),
        );
        std::fs::write(&src_path, &src).unwrap();
        let ok = Command::new("rustc")
            .args(["--edition", "2021", "-o"])
            .arg(&bin)
            .arg(&src_path)
            .status()
            .unwrap()
            .success();
        assert!(ok, "{} failed to compile:\n{src}", ch.spec.id);
        let cases = spec::generate_cases(&ch, &seed, 40);
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
        let out = HarnessOutput::parse(&child.wait_with_output().unwrap().stdout);
        assert!(out.started);
        assert_eq!(out.cases.len(), 40, "{}", ch.spec.id);
        for (i, case) in cases.iter().enumerate() {
            use verifier_differential::harness::Value;
            let got = out.cases[&i].as_str();
            let want = match (ch.spec.id.as_str(), &case[0]) {
                ("parse", Value::Str(s)) => {
                    if s.parse::<i64>().is_ok() {
                        "pass"
                    } else {
                        "panic"
                    }
                }
                ("clamp", Value::Int(x)) => {
                    if *x > 100 {
                        "fail"
                    } else {
                        "pass"
                    }
                }
                ("hex", _) => "pass",
                ("abs", Value::Int(x)) => {
                    if *x == i64::MIN as i128 {
                        "skip"
                    } else {
                        "pass"
                    }
                }
                other => panic!("{other:?}"),
            };
            assert_eq!(got, want, "{} case {i}: {case:?}", ch.spec.id);
        }
    }
}
