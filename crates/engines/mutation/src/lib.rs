//! Mutation engine: `cargo-mutants` scoped to the diff.
//!
//! A mutant that *survives* the test suite in code the PR changed means "the
//! tests do not pin this behavior". That is useful to a reviewer, but it is
//! not a bug: nothing was shown to be wrong, only unobserved. Per ADR-6 a
//! surviving mutant is therefore a [`Hypothesis`] (source
//! [`HypothesisSource::Generator`]), reported in
//! [`EngineReport::unreproduced`], and never a [`verifier_core::Finding`].
//!
//! # How it runs
//!
//! `cargo mutants` builds and runs the PR's code (so `build.rs` and
//! proc-macros execute), so it only ever runs inside the fabric, as a single
//! [`Step::Mutants`] on the PR head. That step needs the unified diff
//! base..head, which [`EngineContext`] does not carry; the engine gets it
//! from a [`DiffSource`] injected with [`MutationEngine::with_diff_source`]
//! (the control plane provides a git-based one). [`MutationEngine::run`]
//! picks, in order:
//!
//! 1. an `outcomes.json` supplied externally
//!    ([`MutationEngine::from_outcomes_json`], e.g. from the maintainer's
//!    trusted CI): parsed, nothing executed;
//! 2. a [`DiffSource`]: fetch the diff, skip if it is empty or touches no
//!    `.rs` file, otherwise execute one [`Step::Mutants`] (per-mutant timeout
//!    and `--jobs` from the policy budget, see [`MutationEngine::invocation`])
//!    and parse the step's stdout (`outcomes.json`) with [`parse_outcomes`];
//! 3. neither: an empty report and a log line ([`NO_SOURCE_NOTE`]).
//!
//! # Failures are silent, never inconclusive
//!
//! Any engine's `inconclusive` (or an `Err` from `run`, which the
//! orchestrator treats the same way) turns the whole verdict `Inconclusive`
//! unless another engine has an actionable finding. This engine can only
//! produce hypotheses, which carry no weight in a verdict, so failing to run
//! it costs at most some reviewer hints. Letting its failures reach the
//! verdict would do the opposite of the Skeptic's rule (docs/council.md): a
//! baseline failure (exit 4) is as likely to be the VM's environment
//! (offline vendoring, a flaky test, cargo-mutants missing) as the PR, and
//! a build or test failure the contributor did cause is already reported by
//! the engines whose job that is. So a failed diff source, a fabric error,
//! a VM timeout, exit 4 or any other unexpected exit code, and an empty or
//! unparseable `outcomes.json` all yield an empty report (plus the VM-seconds
//! spent) and a `warn!` log. `inconclusive` is always `None` and `run` only
//! returns `Err` for a malformed externally supplied `outcomes.json`, which
//! is a configuration error of the maintainer, not a property of the PR.
//! (The orchestrator's own per-engine timeout still applies on top.)
//!
//! Only exit codes 0 (all caught), 2 (some missed) and 3 (some timed out)
//! with a step that finished in time are trusted; partial results of a
//! killed run are dropped rather than guessed at.
//!
//! # What is tested
//!
//! The request shape and the interpretation of step outcomes are unit-tested
//! against a fake executor and a realistic `outcomes.json` fixture.
//! cargo-mutants is not installed in this development environment, so there
//! is no live test that runs it in a VM; the fixture's format is taken from
//! cargo-mutants 25.x and unknown fields are ignored.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde::Deserialize;
use verifier_core::{
    Engine, EngineContext, EngineKind, EngineReport, ExecutionRequest, FnSignature, Hypothesis,
    HypothesisSource, Step,
};

/// Logged when the engine has neither supplied outcomes nor a diff source.
pub const NO_SOURCE_NOTE: &str = "mutation engine: no diff source and no outcomes supplied; \
     cargo-mutants was not run and no hypotheses were produced";

/// Arguments for one diff-scoped `cargo mutants` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutantsInvocation {
    /// Path (inside the VM) of the unified diff between base and head.
    pub diff_file: String,
    /// Output directory; cargo-mutants writes `<dir>/mutants.out/outcomes.json`.
    pub output_dir: String,
    /// Per-mutant test timeout in seconds.
    pub timeout_secs: u64,
    /// Parallel build jobs (`--jobs`); keep at the VM's vCPU count.
    pub jobs: u8,
    /// Restrict to these packages (`--package`), empty for all.
    pub packages: Vec<String>,
}

impl MutantsInvocation {
    fn common(&self) -> Vec<String> {
        let mut v = vec![
            "cargo".to_string(),
            "mutants".to_string(),
            "--in-diff".to_string(),
            self.diff_file.clone(),
            // Deterministic order: two runs over the same commit test the
            // mutants in the same sequence, which keeps transcripts stable.
            "--no-shuffle".to_string(),
        ];
        for p in &self.packages {
            v.push("--package".to_string());
            v.push(p.clone());
        }
        v
    }

    /// `cargo mutants --in-diff <diff> --no-shuffle --list --json`: enumerate
    /// the mutants without running them (cheap; used to check the VM budget).
    /// `--json` only changes the output format of `--list`.
    pub fn list_argv(&self) -> Vec<String> {
        let mut v = self.common();
        v.extend(["--list".to_string(), "--json".to_string()]);
        v
    }

    /// The real run. Results land in `<output_dir>/mutants.out/outcomes.json`,
    /// which [`parse_outcomes`] reads.
    pub fn run_argv(&self) -> Vec<String> {
        let mut v = self.common();
        v.extend([
            "--output".to_string(),
            self.output_dir.clone(),
            "--timeout".to_string(),
            self.timeout_secs.to_string(),
            "--jobs".to_string(),
            self.jobs.to_string(),
            // Never touch the network from inside the VM (ADR-4).
            "--cargo-arg=--offline".to_string(),
        ]);
        v
    }

    /// Path of the outcomes file this invocation produces.
    pub fn outcomes_path(&self) -> String {
        format!(
            "{}/mutants.out/outcomes.json",
            self.output_dir.trim_end_matches('/')
        )
    }
}

// ---------------------------------------------------------------------------
// outcomes.json

/// Top-level `outcomes.json`. Unknown fields are ignored: cargo-mutants adds
/// fields between releases and we only depend on the ones below.
#[derive(Debug, Clone, Deserialize)]
pub struct Outcomes {
    #[serde(default)]
    pub cargo_mutants_version: Option<String>,
    pub outcomes: Vec<Outcome>,
    #[serde(default)]
    pub total_mutants: u64,
    #[serde(default)]
    pub missed: u64,
    #[serde(default)]
    pub caught: u64,
    #[serde(default)]
    pub timeout: u64,
    #[serde(default)]
    pub unviable: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Outcome {
    pub scenario: Scenario,
    pub summary: Summary,
    #[serde(default)]
    pub log_path: Option<String>,
    #[serde(default)]
    pub diff_path: Option<String>,
}

/// `"Baseline"` or `{"Mutant": {...}}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Scenario {
    Mutant {
        #[serde(rename = "Mutant")]
        mutant: Mutant,
    },
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum Summary {
    Success,
    CaughtMutant,
    MissedMutant,
    Unviable,
    Timeout,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Mutant {
    pub package: String,
    pub file: String,
    #[serde(default)]
    pub function: Option<MutantFunction>,
    pub span: Span,
    pub replacement: String,
    pub genre: String,
    /// Human-readable description; present in recent cargo-mutants releases.
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MutantFunction {
    pub function_name: String,
    #[serde(default)]
    pub return_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Span {
    pub start: LineCol,
    pub end: LineCol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct LineCol {
    pub line: u32,
    pub column: u32,
}

impl Mutant {
    /// Description in cargo-mutants' own words, reconstructed when the
    /// `name` field is absent (older releases).
    pub fn describe(&self) -> String {
        if let Some(n) = &self.name {
            return n.clone();
        }
        let loc = format!(
            "{}:{}:{}",
            self.file, self.span.start.line, self.span.start.column
        );
        match &self.function {
            Some(f) => format!(
                "{loc}: replace {} with {} ({})",
                f.function_name, self.replacement, self.genre
            ),
            None => format!("{loc}: replace with {} ({})", self.replacement, self.genre),
        }
    }
}

pub fn parse_outcomes(json: &str) -> anyhow::Result<Outcomes> {
    Ok(serde_json::from_str(json)?)
}

/// Mutants the test suite did not catch. Timeouts are deliberately excluded:
/// a mutant that makes tests hang is usually caught in practice and counting
/// it would be noise (the Skeptic's rule). If `changed_files` is non-empty,
/// only mutants in those files are kept (cargo-mutants' `--in-diff` already
/// does this; filtering again is cheap and protects against a stale diff).
pub fn surviving_mutants<'a>(outcomes: &'a Outcomes, changed_files: &[String]) -> Vec<&'a Mutant> {
    let files: BTreeSet<&str> = changed_files.iter().map(|s| normalize(s)).collect();
    outcomes
        .outcomes
        .iter()
        .filter(|o| o.summary == Summary::MissedMutant)
        .filter_map(|o| match &o.scenario {
            Scenario::Mutant { mutant } => Some(mutant),
            Scenario::Other(_) => None,
        })
        .filter(|m| files.is_empty() || files.contains(normalize(&m.file)))
        .collect()
}

fn normalize(p: &str) -> &str {
    p.trim_start_matches("./")
}

/// Resolve the planner's fully qualified path for a mutant's function, if
/// the planner saw it change; otherwise fall back to `file::function`.
fn target_for(m: &Mutant, changed: &[FnSignature]) -> String {
    let Some(f) = &m.function else {
        return format!("{}:{}", m.file, m.span.start.line);
    };
    let suffix = format!("::{}", f.function_name);
    changed
        .iter()
        .find(|s| s.path.ends_with(&suffix))
        .map(|s| s.path.clone())
        .unwrap_or_else(|| format!("{}::{}", m.file, f.function_name))
}

/// Surviving mutants in changed code, as hypotheses. They carry no candidate
/// input: there is nothing to replay, only a gap in the tests to point at.
pub fn hypotheses_from_outcomes(
    outcomes: &Outcomes,
    changed_files: &[String],
    changed_functions: &[FnSignature],
) -> Vec<Hypothesis> {
    surviving_mutants(outcomes, changed_files)
        .into_iter()
        .map(|m| Hypothesis {
            source: HypothesisSource::Generator,
            target: target_for(m, changed_functions),
            claim: format!(
                "tests don't pin this behavior: mutant survived the test suite: {}",
                m.describe()
            ),
            candidate_input: None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Engine

/// Supplies the unified diff from the PR's base to its head, as `git diff
/// base..head` prints it. The control plane implements it from its checkout;
/// tests use a constant.
#[async_trait::async_trait]
pub trait DiffSource: Send + Sync {
    async fn diff(&self, ctx: &EngineContext) -> anyhow::Result<String>;
}

/// The mutation engine. See the crate docs for what it runs and when.
#[derive(Clone, Default)]
pub struct MutationEngine {
    outcomes_json: Option<String>,
    diff_source: Option<Arc<dyn DiffSource>>,
}

impl std::fmt::Debug for MutationEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutationEngine")
            .field(
                "outcomes_json",
                &self.outcomes_json.as_ref().map(String::len),
            )
            .field("diff_source", &self.diff_source.is_some())
            .finish()
    }
}

impl MutationEngine {
    /// Engine with no outcomes and no diff source: returns an empty report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Engine that interprets an `outcomes.json` produced elsewhere, e.g. by
    /// the maintainer's trusted CI. Never feed it output of a run that
    /// happened outside a VM on untrusted code.
    pub fn from_outcomes_json(json: impl Into<String>) -> Self {
        MutationEngine {
            outcomes_json: Some(json.into()),
            diff_source: None,
        }
    }

    /// Runs cargo-mutants in the fabric on the diff `source` returns.
    /// Supplied outcomes, if any, still take precedence.
    pub fn with_diff_source(mut self, source: Arc<dyn DiffSource>) -> Self {
        self.diff_source = Some(source);
        self
    }

    /// Invocation parameters for this context. The `Step::Mutants` request
    /// uses its `timeout_secs` and `jobs`; the paths are the guest's concern.
    pub fn invocation(ctx: &EngineContext) -> MutantsInvocation {
        MutantsInvocation {
            diff_file: "/work/pr.diff".to_string(),
            output_dir: "/work/mutants".to_string(),
            timeout_secs: ctx.policy.budget.vm_timeout_secs.clamp(10, 120),
            jobs: ctx.policy.budget.vcpus.max(1),
            packages: vec![],
        }
    }

    /// The single-step request that runs cargo-mutants on the PR head.
    /// Not sealed: surviving mutants point at the PR's own code.
    pub fn request(ctx: &EngineContext, diff: String) -> ExecutionRequest {
        let inv = Self::invocation(ctx);
        let b = &ctx.policy.budget;
        ExecutionRequest {
            id: uuid::Uuid::new_v4(),
            repo_url: ctx.pr.head_clone_url.clone(),
            commit: ctx.pr.head_sha.clone(),
            steps: vec![Step::Mutants {
                diff,
                timeout_secs: inv.timeout_secs,
                jobs: inv.jobs,
            }],
            timeout_secs: b.vm_timeout_secs,
            vcpus: b.vcpus,
            memory_mib: b.memory_mib,
            sealed: false,
            env: Default::default(),
        }
    }

    fn hypotheses(ctx: &EngineContext, outcomes: &Outcomes) -> Vec<Hypothesis> {
        hypotheses_from_outcomes(
            outcomes,
            &ctx.plan.changed_files,
            &ctx.plan.changed_functions,
        )
    }

    /// Executes cargo-mutants through the fabric. Every failure is logged
    /// and yields an empty report (see the crate docs for why).
    async fn run_in_fabric(ctx: &EngineContext, source: &dyn DiffSource) -> EngineReport {
        let mut report = EngineReport::default();
        let diff = match source.diff(ctx).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "mutation engine: no diff; skipped");
                return report;
            }
        };
        if !touches_rust(&diff) {
            tracing::info!("mutation engine: diff is empty or touches no Rust file; skipped");
            return report;
        }
        let result = match ctx.executor.execute(Self::request(ctx, diff)).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "mutation engine: fabric error; skipped");
                return report;
            }
        };
        let ms: u64 = result.outcomes.iter().map(|o| o.duration_ms).sum();
        report.vm_seconds = ms.div_ceil(1000);

        let Some(out) = result.outcomes.iter().find(|o| o.step_index == 0) else {
            tracing::warn!("mutation engine: no outcome for the mutants step; skipped");
            return report;
        };
        if out.timed_out {
            tracing::warn!("mutation engine: cargo-mutants run timed out; results dropped");
            return report;
        }
        match out.exit_code {
            Some(0 | 2 | 3) => {}
            Some(4) => {
                tracing::warn!(
                    "mutation engine: unmutated baseline failed in the VM; no hypotheses"
                );
                return report;
            }
            code => {
                tracing::warn!(
                    ?code,
                    "mutation engine: unexpected cargo-mutants exit; skipped"
                );
                return report;
            }
        }
        let json = String::from_utf8_lossy(&out.stdout);
        if json.trim().is_empty() {
            tracing::warn!("mutation engine: step produced no outcomes.json; skipped");
            return report;
        }
        match parse_outcomes(&json) {
            Ok(outcomes) => report.unreproduced = Self::hypotheses(ctx, &outcomes),
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "mutation engine: bad outcomes.json; skipped")
            }
        }
        report
    }
}

/// Whether a unified diff changes at least one `.rs` file (added, modified,
/// deleted or renamed on either side).
pub fn touches_rust(diff: &str) -> bool {
    diff.lines().any(|l| {
        let paths: Vec<&str> = if let Some(rest) = l.strip_prefix("diff --git ") {
            rest.split_whitespace().collect()
        } else if let Some(p) = l.strip_prefix("+++ ").or_else(|| l.strip_prefix("--- ")) {
            vec![p.split('\t').next().unwrap_or(p)]
        } else {
            return false;
        };
        paths
            .iter()
            .any(|p| *p != "/dev/null" && p.trim_matches('"').ends_with(".rs"))
    })
}

#[async_trait::async_trait]
impl Engine for MutationEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::Mutation
    }

    async fn run(&self, ctx: &EngineContext) -> anyhow::Result<EngineReport> {
        if let Some(json) = &self.outcomes_json {
            let outcomes = parse_outcomes(json)?;
            return Ok(EngineReport {
                unreproduced: Self::hypotheses(ctx, &outcomes),
                ..EngineReport::default()
            });
        }
        let Some(source) = &self.diff_source else {
            tracing::info!(argv = ?Self::invocation(ctx).run_argv(), "{NO_SOURCE_NOTE}");
            return Ok(EngineReport::default());
        };
        Ok(Self::run_in_fabric(ctx, source.as_ref()).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/outcomes.json");

    #[test]
    fn parses_realistic_outcomes() {
        let o = parse_outcomes(FIXTURE).unwrap();
        assert_eq!(o.cargo_mutants_version.as_deref(), Some("25.0.1"));
        assert_eq!(o.outcomes.len(), 6);
        assert!(matches!(&o.outcomes[0].scenario, Scenario::Other(s) if s == "Baseline"));
        assert_eq!(o.outcomes[1].summary, Summary::CaughtMutant);
        assert_eq!((o.missed, o.caught, o.timeout, o.unviable), (2, 1, 1, 1));
    }

    #[test]
    fn only_missed_mutants_in_changed_files_survive() {
        let o = parse_outcomes(FIXTURE).unwrap();
        let all = surviving_mutants(&o, &[]);
        assert_eq!(
            all.len(),
            2,
            "timeouts and unviable mutants are not survivors"
        );
        let scoped = surviving_mutants(&o, &["./src/parse.rs".to_string()]);
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].replacement, "<=");
        assert_eq!(scoped[0].span.start.line, 17);
    }

    #[test]
    fn hypotheses_resolve_planner_paths_and_carry_no_input() {
        let o = parse_outcomes(FIXTURE).unwrap();
        let changed = vec![FnSignature {
            path: "mylib::parse::parse_len".into(),
            args: vec!["&[u8]".into()],
            ret: "Option<usize>".into(),
            is_pub: true,
        }];
        let hs = hypotheses_from_outcomes(&o, &[], &changed);
        assert_eq!(hs.len(), 2);
        assert_eq!(hs[0].target, "mylib::parse::parse_len");
        assert!(hs[0]
            .claim
            .contains("src/parse.rs:17:16: replace < with <= in parse_len"));
        assert_eq!(hs[1].target, "src/checksum.rs::Crc::update");
        assert!(hs[1].claim.contains("replace Crc::update with ()"));
        assert!(hs
            .iter()
            .all(|h| h.candidate_input.is_none() && h.source == HypothesisSource::Generator));
    }

    #[test]
    fn argv_is_scoped_to_diff_and_offline() {
        let inv = MutantsInvocation {
            diff_file: "/work/pr.diff".into(),
            output_dir: "/work/m/".into(),
            timeout_secs: 60,
            jobs: 2,
            packages: vec!["mylib".into()],
        };
        let run = inv.run_argv();
        assert_eq!(
            &run[..5],
            [
                "cargo",
                "mutants",
                "--in-diff",
                "/work/pr.diff",
                "--no-shuffle"
            ]
        );
        assert!(run.contains(&"--cargo-arg=--offline".to_string()));
        assert!(inv
            .list_argv()
            .ends_with(&["--list".to_string(), "--json".to_string()]));
        assert_eq!(inv.outcomes_path(), "/work/m/mutants.out/outcomes.json");
    }

    /// Fake fabric: records requests and answers the mutants step with a
    /// fixed exit code and stdout.
    struct FakeExec {
        exit_code: Option<i32>,
        timed_out: bool,
        stdout: String,
        requests: std::sync::Mutex<Vec<ExecutionRequest>>,
    }

    impl FakeExec {
        fn new(exit_code: i32, stdout: &str) -> Arc<Self> {
            Arc::new(FakeExec {
                exit_code: Some(exit_code),
                timed_out: false,
                stdout: stdout.to_string(),
                requests: Default::default(),
            })
        }
    }

    #[async_trait::async_trait]
    impl verifier_core::Executor for FakeExec {
        async fn execute(
            &self,
            req: ExecutionRequest,
        ) -> anyhow::Result<verifier_core::ExecutionResult> {
            self.requests.lock().unwrap().push(req.clone());
            let outcomes = vec![verifier_core::StepOutcome {
                step_index: 0,
                exit_code: self.exit_code,
                timed_out: self.timed_out,
                stdout: self.stdout.clone().into_bytes(),
                stderr: b"cargo-mutants human output".to_vec(),
                duration_ms: 42_300,
            }];
            Ok(verifier_core::ExecutionResult {
                request_id: req.id,
                transcript: verifier_core::ExecutionResult::compute_transcript(&req, &outcomes),
                outcomes,
                environment: verifier_core::Digest::of(b"env"),
            })
        }
    }

    struct FixedDiff(Result<&'static str, &'static str>);
    #[async_trait::async_trait]
    impl DiffSource for FixedDiff {
        async fn diff(&self, _: &EngineContext) -> anyhow::Result<String> {
            self.0.map(str::to_string).map_err(|e| anyhow::anyhow!(e))
        }
    }

    const RUST_DIFF: &str = "diff --git a/src/parse.rs b/src/parse.rs\n\
        --- a/src/parse.rs\n\
        +++ b/src/parse.rs\n\
        @@ -17 +17 @@\n\
        -    if n < 4 {\n\
        +    if n < 8 {\n";

    fn head_sha() -> verifier_core::CommitSha {
        verifier_core::CommitSha::new("b".repeat(40)).unwrap()
    }

    fn ctx(executor: Arc<dyn verifier_core::Executor>) -> EngineContext {
        EngineContext {
            pr: verifier_core::PullRequest {
                repo: verifier_core::RepoId {
                    owner: "o".into(),
                    name: "n".into(),
                },
                number: 1,
                base_sha: verifier_core::CommitSha::new("a".repeat(40)).unwrap(),
                head_sha: head_sha(),
                head_clone_url: "https://example.test/fork.git".into(),
                base_clone_url: "https://example.test/upstream.git".into(),
                author: "a".into(),
                body: String::new(),
            },
            intent: Default::default(),
            policy: Default::default(),
            plan: verifier_core::ImpactPlan {
                changed_files: vec!["src/parse.rs".into()],
                ..Default::default()
            },
            seed: None,
            sealed_specs: vec![],
            executor,
        }
    }

    fn fabric_engine(diff: Result<&'static str, &'static str>) -> MutationEngine {
        MutationEngine::new().with_diff_source(Arc::new(FixedDiff(diff)))
    }

    #[tokio::test]
    async fn supplied_outcomes_never_execute_and_yield_only_hypotheses() {
        let fake = FakeExec::new(0, "");
        let r = MutationEngine::from_outcomes_json(FIXTURE)
            .with_diff_source(Arc::new(FixedDiff(Ok(RUST_DIFF))))
            .run(&ctx(fake.clone()))
            .await
            .unwrap();
        assert!(r.findings.is_empty());
        assert_eq!(r.unreproduced.len(), 1);
        assert!(r.inconclusive.is_none());
        assert!(fake.requests.lock().unwrap().is_empty());

        let empty = MutationEngine::new().run(&ctx(fake.clone())).await.unwrap();
        assert_eq!(empty, EngineReport::default());
        assert!(fake.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn surviving_mutants_from_the_fabric_are_hypotheses_only() {
        let fake = FakeExec::new(2, FIXTURE);
        let r = fabric_engine(Ok(RUST_DIFF))
            .run(&ctx(fake.clone()))
            .await
            .unwrap();
        assert!(r.findings.is_empty(), "a surviving mutant is not a bug");
        assert!(r.inconclusive.is_none());
        assert_eq!(r.unreproduced.len(), 1);
        assert!(r.unreproduced[0].claim.contains("replace < with <="));
        assert_eq!(r.unreproduced[0].source, HypothesisSource::Generator);
        assert_eq!(r.vm_seconds, 43, "42.3 s rounds up");
    }

    #[tokio::test]
    async fn request_is_one_mutants_step_on_head_sized_by_budget() {
        let fake = FakeExec::new(0, FIXTURE);
        let mut c = ctx(fake.clone());
        c.policy.budget.vm_timeout_secs = 900;
        c.policy.budget.vcpus = 4;
        c.policy.budget.memory_mib = 8192;
        fabric_engine(Ok(RUST_DIFF)).run(&c).await.unwrap();

        let reqs = fake.requests.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let req = &reqs[0];
        assert_eq!(req.commit, head_sha());
        assert_eq!(req.repo_url, "https://example.test/fork.git");
        assert!(!req.sealed);
        assert_eq!(
            (req.timeout_secs, req.vcpus, req.memory_mib),
            (900, 4, 8192)
        );
        assert_eq!(
            req.steps,
            vec![Step::Mutants {
                diff: RUST_DIFF.to_string(),
                timeout_secs: 120,
                jobs: 4,
            }]
        );
    }

    #[tokio::test]
    async fn baseline_failure_is_silent_not_inconclusive() {
        let fake = FakeExec::new(4, FIXTURE);
        let r = fabric_engine(Ok(RUST_DIFF))
            .run(&ctx(fake.clone()))
            .await
            .unwrap();
        assert!(r.findings.is_empty() && r.unreproduced.is_empty());
        assert!(r.inconclusive.is_none());
        assert_eq!(r.vm_seconds, 43, "time spent is still accounted");
    }

    #[tokio::test]
    async fn missing_or_garbage_outcomes_and_timeouts_are_silent() {
        for (code, stdout) in [
            (2, ""),
            (2, "  \n"),
            (0, "not json"),
            (2, "{\"outcomes\": 3}"),
        ] {
            let r = fabric_engine(Ok(RUST_DIFF))
                .run(&ctx(FakeExec::new(code, stdout)))
                .await
                .unwrap();
            assert!(
                r.unreproduced.is_empty() && r.inconclusive.is_none(),
                "{stdout:?}"
            );
        }
        let killed = Arc::new(FakeExec {
            exit_code: None,
            timed_out: true,
            stdout: FIXTURE.to_string(),
            requests: Default::default(),
        });
        let r = fabric_engine(Ok(RUST_DIFF))
            .run(&ctx(killed))
            .await
            .unwrap();
        assert!(r.unreproduced.is_empty() && r.inconclusive.is_none());
        assert_eq!(r.vm_seconds, 43);
    }

    #[tokio::test]
    async fn skips_without_rust_changes_or_without_a_diff() {
        let docs_only = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n";
        for diff in [Ok(""), Ok(docs_only), Err("git failed")] {
            let fake = FakeExec::new(2, FIXTURE);
            let r = fabric_engine(diff).run(&ctx(fake.clone())).await.unwrap();
            assert_eq!(r, EngineReport::default());
            assert!(fake.requests.lock().unwrap().is_empty(), "{diff:?}");
        }
    }

    #[test]
    fn detects_rust_files_in_diffs() {
        assert!(touches_rust(RUST_DIFF));
        assert!(touches_rust("--- a/src/old.rs\n+++ /dev/null\n"));
        assert!(touches_rust(
            "--- /dev/null\n+++ b/src/new.rs\t2026-01-01\n"
        ));
        assert!(!touches_rust("diff --git a/Cargo.toml b/Cargo.toml\n"));
        assert!(!touches_rust("diff --git a/x.rsx b/x.rsx\n"));
        assert!(!touches_rust(""));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_outcomes("{\"outcomes\": 3}").is_err());
    }
}
