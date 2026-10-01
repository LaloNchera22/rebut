//! The differential engine: does head behave like base?
//!
//! Two independent checks, both run on base and head inside the fabric:
//!
//! * **Generated inputs.** For every changed `pub` function whose arguments
//!   the harness can generate (integers, `bool`, `char`, strings, byte
//!   vectors, one level of `Option`), a harness feeds deterministic inputs
//!   (boundary values, then seeded random ones) and prints the `Debug` of the
//!   result per case; panics are caught and printed as `panic`. With
//!   [`DiffScope::AllPublic`] (a dependency update, or asked for) every
//!   public function the planner listed is driven too, changed or not; a
//!   divergence in a function whose code did not change is only explained
//!   by an intent that names it explicitly.
//! * **Test regressions.** The planner's tests (or the full suite when the
//!   plan widens) run on both sides; a test that passes on base and fails on
//!   head is a regression. Tests absent on base are skipped.
//!
//! # Evidence (ADR-6) and the Skeptic's rule
//!
//! Everything runs in two phases:
//!
//! 1. **Screening.** One request per side, each executed twice. A case or
//!    test whose output differs between the two identical runs is
//!    nondeterministic and dropped (logged as an unreproduced hypothesis,
//!    never a finding). Only cases that are stable on both sides and differ
//!    between sides become candidates (at most a few per function).
//! 2. **Confirmation.** One more request per side in which every candidate is
//!    its *own* step: a harness step whose stdin is exactly that one case, or
//!    a test step filtered to that one test. The confirmation output must
//!    match what screening saw (a third identical run), and the finding's
//!    [`Reproduction`] is built by [`Reproduction::confirm_divergence`] over
//!    those single-case steps. So the reproduction's input is exactly the
//!    stdin that was fed (after the result channel's nonce line), its
//!    expected/observed are the complete (canonical) outcomes of those steps,
//!    and its transcript digest binds the two real confirmation runs. We never slice a multi-case stdout into synthetic outcomes.
//!
//! A build failure on either side makes the engine inconclusive, never a
//! finding. A harness that does not start on a side (typically: the function
//! was added, removed or changed signature, so the harness does not compile)
//! is not compared. A harness whose result channel was tampered with (see
//! [`rebut_core::channel`]) makes the engine inconclusive: an untrusted
//! result never counts as "no divergence".

pub mod gen;
pub mod harness;
pub mod libtest;
pub mod run;

use std::collections::{BTreeMap, BTreeSet};

use rebut_core::{
    DiffScope, Digest, Engine, EngineContext, EngineKind, EngineReport, ExecutionResult, Finding,
    FnSignature, Hypothesis, HypothesisSource, Reproduction, Seed, Step, Visibility,
};

use harness::{ArgType, HarnessOutput};
use libtest::{parse_test_output, TestStatus};
use run::{consistent_success, execute, outcome, Side};

pub const CATEGORY_DIVERGENCE: &str = "behavior-divergence";
pub const CATEGORY_TEST_REGRESSION: &str = "test-regression";

#[derive(Debug, Clone)]
pub struct DifferentialConfig {
    /// Generated cases per function.
    pub cases_per_fn: usize,
    /// Functions harnessed per PR (the rest are skipped).
    pub max_functions: usize,
    /// Functions harnessed per PR with [`DiffScope::AllPublic`].
    pub max_public_functions: usize,
    /// Divergent cases confirmed (and reported) per function.
    pub max_findings_per_fn: usize,
    /// Test regressions confirmed per PR.
    pub max_test_findings: usize,
    /// Profile passed to [`Step::Build`].
    pub build_profile: String,
}

impl Default for DifferentialConfig {
    fn default() -> Self {
        DifferentialConfig {
            cases_per_fn: 64,
            max_functions: 32,
            max_public_functions: 200,
            max_findings_per_fn: 3,
            max_test_findings: 16,
            build_profile: "dev".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DifferentialEngine {
    config: DifferentialConfig,
}

/// A function the engine can drive, with its generated input lines.
#[derive(Debug, Clone)]
pub struct HarnessTarget {
    pub sig: FnSignature,
    pub args: Vec<ArgType>,
    pub lines: Vec<String>,
    /// The function's own code changed (it is in `changed_functions`).
    pub changed: bool,
}

/// The functions [`DifferentialEngine::select`] will compare.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    pub targets: Vec<HarnessTarget>,
    /// With [`DiffScope::AllPublic`]: public functions left out because no
    /// harness can call them (the planner's shape checks plus unsupported
    /// argument types).
    pub skipped: usize,
    /// Harnessable functions beyond the cap, not compared.
    pub truncated: usize,
}

impl HarnessTarget {
    fn source(&self) -> String {
        harness::differential_source(&self.sig.path, &self.args)
    }
    fn step(&self, lines: &[String]) -> Step {
        Step::Harness {
            name: harness_name(&self.sig.path),
            source: self.source(),
            input: harness::encode_input(lines),
        }
    }
}

fn harness_name(path: &str) -> String {
    let s: String = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("differential_{s}")
}

/// Whether the harness can call and feed `sig`.
pub fn supported(sig: &FnSignature) -> Option<Vec<ArgType>> {
    if !sig.is_pub || !harness::is_plain_path(&sig.path) {
        return None;
    }
    sig.args.iter().map(|a| ArgType::parse(a)).collect()
}

/// The seed for a function's cases: forked from the PR's drand seed when
/// present, otherwise derived from the head commit (still deterministic and
/// reproducible, just not unpredictable).
pub fn case_seed(ctx: &EngineContext, path: &str) -> Seed {
    let root = ctx.seed.unwrap_or_else(|| {
        Seed(Digest::of_parts(&[
            b"rebut/differential/v1",
            ctx.pr.head_sha.as_str().as_bytes(),
        ]))
    });
    root.fork(&format!("differential/{path}"))
}

/// A screening candidate: a case whose output is stable on each side and
/// differs between them.
struct CaseCandidate {
    target: usize,
    line: String,
    base: String,
    /// `None`: the head harness died on this case.
    head: Option<String>,
}

impl DifferentialEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: DifferentialConfig) -> Self {
        DifferentialEngine { config }
    }

    /// Functions the engine will harness, with their inputs.
    pub fn targets(&self, ctx: &EngineContext) -> Vec<HarnessTarget> {
        self.select(ctx).targets
    }

    /// Changed functions first, then (with [`DiffScope::AllPublic`]) the
    /// plan's public functions, keeping those a harness can call, up to the
    /// scope's cap.
    pub fn select(&self, ctx: &EngineContext) -> Selection {
        let plan = &ctx.plan;
        let all_public = plan.scope == DiffScope::AllPublic;
        let mut skipped = if all_public { plan.public_skipped } else { 0 };
        let mut seen = BTreeSet::new();
        let mut picked = Vec::new();
        for sig in &plan.changed_functions {
            if let Some(args) = supported(sig) {
                if seen.insert(sig.path.as_str()) {
                    picked.push((sig, args, true));
                }
            }
        }
        if all_public {
            for sig in &plan.public_functions {
                match supported(sig) {
                    _ if seen.contains(sig.path.as_str()) => {}
                    Some(args) => {
                        seen.insert(sig.path.as_str());
                        picked.push((sig, args, false));
                    }
                    None => skipped += 1,
                }
            }
        }
        let cap = if all_public {
            self.config.max_public_functions
        } else {
            self.config.max_functions
        };
        let truncated = picked.len().saturating_sub(cap);
        picked.truncate(cap);
        let targets = picked
            .into_iter()
            .map(|(sig, args, changed)| {
                let seed = case_seed(ctx, &sig.path);
                let lines = gen::differential_cases(&args, &seed, self.config.cases_per_fn)
                    .iter()
                    .map(|c| harness::encode_case(c))
                    .collect();
                HarnessTarget {
                    sig: sig.clone(),
                    args,
                    lines,
                    changed,
                }
            })
            .collect();
        Selection {
            targets,
            skipped,
            truncated,
        }
    }

    fn build(&self) -> Step {
        Step::Build {
            profile: self.config.build_profile.clone(),
        }
    }
}

fn hypothesis(target: &str, claim: String, input: Option<Vec<u8>>) -> Hypothesis {
    Hypothesis {
        source: HypothesisSource::Generator,
        target: target.to_string(),
        claim,
        candidate_input: input,
    }
}

/// Test statuses that agree across all runs; the second map holds tests
/// whose status changed between identical runs.
fn stable_tests(
    runs: &[ExecutionResult],
    step: usize,
) -> (BTreeMap<String, TestStatus>, Vec<String>) {
    let parsed: Vec<BTreeMap<String, TestStatus>> = runs
        .iter()
        .map(|r| {
            outcome(r, step)
                .map(|o| parse_test_output(&o.stdout))
                .unwrap_or_default()
        })
        .collect();
    let mut stable = BTreeMap::new();
    let mut flaky = Vec::new();
    if let Some((first, rest)) = parsed.split_first() {
        for (name, st) in first {
            if rest.iter().all(|m| m.get(name) == Some(st)) {
                stable.insert(name.clone(), *st);
            } else if rest.iter().all(|m| m.contains_key(name)) {
                flaky.push(name.clone());
            }
        }
    }
    (stable, flaky)
}

fn harness_outputs(runs: &[ExecutionResult], step: usize) -> Vec<HarnessOutput> {
    runs.iter()
        .map(|r| {
            outcome(r, step)
                .map(|o| HarnessOutput::parse(&o.stdout))
                .unwrap_or_default()
        })
        .collect()
}

#[async_trait::async_trait]
impl Engine for DifferentialEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::Differential
    }

    async fn run(&self, ctx: &EngineContext) -> anyhow::Result<EngineReport> {
        let mut report = EngineReport::default();
        let targets = self.targets(ctx);
        let test_filters = if ctx.plan.widen_to_full_suite {
            Some(vec![])
        } else if !ctx.plan.tests.is_empty() {
            Some(ctx.plan.tests.clone())
        } else {
            None
        };
        if targets.is_empty() && test_filters.is_none() {
            return Ok(report);
        }

        // Phase 1: screening, each side twice.
        let mut steps = vec![self.build()];
        let test_step = test_filters.map(|filters| {
            steps.push(Step::Test { filters });
            steps.len() - 1
        });
        let first_harness = steps.len();
        steps.extend(targets.iter().map(|t| t.step(&t.lines)));

        let mut base = Vec::new();
        let mut head = Vec::new();
        for _ in 0..2 {
            base.push(
                execute(
                    ctx,
                    Side::Base,
                    steps.clone(),
                    false,
                    &mut report.vm_seconds,
                )
                .await?,
            );
            head.push(
                execute(
                    ctx,
                    Side::Head,
                    steps.clone(),
                    false,
                    &mut report.vm_seconds,
                )
                .await?,
            );
        }
        let reason = match (consistent_success(&base, 0), consistent_success(&head, 0)) {
            (Some(true), Some(true)) => None,
            (Some(false), Some(false)) => Some("neither base nor head builds; nothing to compare"),
            (_, Some(false)) => Some("head does not build"),
            (Some(false), _) => Some("base does not build"),
            _ => Some("build result is nondeterministic"),
        };
        if let Some(reason) = reason {
            report.inconclusive = Some(reason.to_string());
            return Ok(report);
        }

        // Test regressions: stable pass on base, stable failure on head.
        let mut test_candidates = Vec::new();
        if let Some(step) = test_step {
            let (b, b_flaky) = stable_tests(&base, step);
            let (h, h_flaky) = stable_tests(&head, step);
            for name in b_flaky.iter().chain(&h_flaky) {
                report.unreproduced.push(hypothesis(
                    name,
                    "test outcome differs between identical runs (flaky); ignored".into(),
                    None,
                ));
            }
            for (name, st) in &b {
                if *st == TestStatus::Passed && h.get(name) == Some(&TestStatus::Failed) {
                    test_candidates.push(name.clone());
                }
            }
            test_candidates.truncate(self.config.max_test_findings);
        }

        // Generated-input divergences.
        let mut case_candidates = Vec::new();
        let mut tampered = Vec::new();
        for (ti, t) in targets.iter().enumerate() {
            let b = harness_outputs(&base, first_harness + ti);
            let h = harness_outputs(&head, first_harness + ti);
            if b.iter().chain(&h).any(|o| o.tampered) {
                tampered.push(t.sig.path.clone());
                continue;
            }
            if !b.iter().chain(&h).all(|o| o.started) {
                // Not comparable: the harness does not compile/start on a side.
                continue;
            }
            let mut flaky = Vec::new();
            let mut found = 0;
            for (ci, line) in t.lines.iter().enumerate() {
                if found >= self.config.max_findings_per_fn {
                    break;
                }
                // Base must have observed the case identically twice.
                let (Some(b0), Some(b1)) = (b[0].cases.get(&ci), b[1].cases.get(&ci)) else {
                    break;
                };
                if b0 != b1 {
                    flaky.push(line);
                    continue;
                }
                let head_obs = match (h[0].cases.get(&ci), h[1].cases.get(&ci)) {
                    (Some(h0), Some(h1)) if h0 == h1 => Some(h0),
                    (None, None) => None,
                    (Some(_), Some(_)) => {
                        flaky.push(line);
                        continue;
                    }
                    // Died in one run only: nondeterministic, and later
                    // cases are not comparable either.
                    _ => {
                        flaky.push(line);
                        break;
                    }
                };
                if head_obs == Some(b0) {
                    continue;
                }
                found += 1;
                case_candidates.push(CaseCandidate {
                    target: ti,
                    line: line.clone(),
                    base: b0.clone(),
                    head: head_obs.cloned(),
                });
                if head_obs.is_none() {
                    break; // Nothing after a crash was observed.
                }
            }
            if let Some(first) = flaky.first() {
                report.unreproduced.push(hypothesis(
                    &t.sig.path,
                    format!(
                        "{} generated input(s) produced different output on identical runs \
                         (nondeterministic); excluded",
                        flaky.len()
                    ),
                    Some(first.as_bytes().to_vec()),
                ));
            }
        }

        if case_candidates.is_empty() && test_candidates.is_empty() {
            report.inconclusive = tamper_reason(&tampered);
            return Ok(report);
        }

        // Phase 2: confirmation, one step per candidate.
        let mut steps = vec![self.build()];
        for c in &case_candidates {
            steps.push(targets[c.target].step(std::slice::from_ref(&c.line)));
        }
        let first_test = steps.len();
        for name in &test_candidates {
            steps.push(Step::Test {
                filters: vec![name.clone()],
            });
        }
        let base_c = execute(
            ctx,
            Side::Base,
            steps.clone(),
            false,
            &mut report.vm_seconds,
        )
        .await?;
        let head_c = execute(ctx, Side::Head, steps, false, &mut report.vm_seconds).await?;
        let rebuilt = consistent_success(&[base_c.clone(), head_c.clone()], 0) == Some(true);

        for (i, c) in case_candidates.iter().enumerate() {
            let step = 1 + i;
            let target = &targets[c.target];
            let path = &target.sig.path;
            // A function whose code did not change (e.g. after a dependency
            // update) is only expected to change behavior if named.
            let (explained, why) = if target.changed {
                (ctx.intent.allows_behavior_change(path), "")
            } else {
                (ctx.intent.lists(path), " although its code did not change")
            };
            if [&base_c, &head_c]
                .iter()
                .any(|r| outcome(r, step).is_some_and(|o| HarnessOutput::parse(&o.stdout).tampered))
            {
                tampered.push(path.clone());
                continue;
            }
            let confirmed = rebuilt && confirms_case(&base_c, &head_c, step, c);
            let repro = confirmed
                .then(|| {
                    Reproduction::confirm_divergence(
                        &base_c,
                        step,
                        &head_c,
                        step,
                        harness::encode_input(std::slice::from_ref(&c.line)),
                    )
                })
                .flatten();
            match repro {
                Some(r) => report.findings.push(Finding::new(
                    EngineKind::Differential,
                    CATEGORY_DIVERGENCE,
                    format!(
                        "`{path}` behaves differently on head than on base for a generated \
                         input{why}"
                    ),
                    Visibility::Public,
                    Some(path.clone()),
                    explained,
                    r,
                )),
                None => report.unreproduced.push(hypothesis(
                    path,
                    "divergence seen during screening did not reproduce in a single-case run"
                        .into(),
                    Some(c.line.as_bytes().to_vec()),
                )),
            }
        }

        for (i, name) in test_candidates.iter().enumerate() {
            let step = first_test + i;
            let status = |r: &ExecutionResult| {
                outcome(r, step)
                    .filter(|o| !o.timed_out)
                    .and_then(|o| parse_test_output(&o.stdout).get(name).copied())
            };
            let confirmed = rebuilt
                && status(&base_c) == Some(TestStatus::Passed)
                && status(&head_c) == Some(TestStatus::Failed);
            let repro = confirmed
                .then(|| {
                    Reproduction::confirm_divergence(
                        &base_c,
                        step,
                        &head_c,
                        step,
                        name.as_bytes().to_vec(),
                    )
                })
                .flatten();
            match repro {
                Some(r) => report.findings.push(Finding::new(
                    EngineKind::Differential,
                    CATEGORY_TEST_REGRESSION,
                    format!("test `{name}` passes on base but fails on head"),
                    Visibility::Public,
                    Some(name.clone()),
                    false,
                    r,
                )),
                None => report.unreproduced.push(hypothesis(
                    name,
                    "test regression seen during screening did not reproduce".into(),
                    None,
                )),
            }
        }
        report.inconclusive = tamper_reason(&tampered);
        Ok(report)
    }
}

/// Why the engine is inconclusive when some harness output was forged.
fn tamper_reason(paths: &[String]) -> Option<String> {
    let mut paths = paths.to_vec();
    paths.dedup();
    (!paths.is_empty()).then(|| {
        format!(
            "harness result channel tampered with while testing {}; results cannot be trusted",
            paths.join(", ")
        )
    })
}

/// The single-case confirmation runs must show exactly what screening saw
/// (a third identical observation) and must not have timed out.
fn confirms_case(
    base: &ExecutionResult,
    head: &ExecutionResult,
    step: usize,
    c: &CaseCandidate,
) -> bool {
    let (Some(bo), Some(ho)) = (outcome(base, step), outcome(head, step)) else {
        return false;
    };
    if bo.timed_out || ho.timed_out || !bo.success() {
        return false;
    }
    let (b, h) = (
        HarnessOutput::parse(&bo.stdout),
        HarnessOutput::parse(&ho.stdout),
    );
    b.started && h.started && b.cases.get(&0) == Some(&c.base) && h.cases.get(&0) == c.head.as_ref()
}

#[cfg(test)]
mod tests;
