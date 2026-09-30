//! Mutation engine (phase 2): `cargo-mutants` scoped to the diff.
//!
//! A mutant that *survives* the test suite in code the PR changed means "the
//! tests do not pin this behavior". That is useful to a reviewer, but it is
//! not a bug: nothing was shown to be wrong, only unobserved. Per ADR-6 a
//! surviving mutant is therefore a [`Hypothesis`] (source
//! [`HypothesisSource::Generator`]), reported in
//! [`EngineReport::unreproduced`], and never a [`verifier_core::Finding`].
//!
//! # What exists now and what lands in phase 2
//!
//! * [`MutantsInvocation`] builds the exact `cargo mutants` argv, scoped with
//!   `--in-diff`.
//! * [`parse_outcomes`] parses cargo-mutants' `mutants.out/outcomes.json`.
//! * [`surviving_mutants`] / [`hypotheses_from_outcomes`] turn it into
//!   hypotheses restricted to the files the diff touches.
//!
//! What is missing is the *executor step*: `cargo mutants` builds and runs the
//! PR's code (so `build.rs` and proc-macros execute) and must only ever run
//! inside the fabric's microVM. The core [`verifier_core::Step`] enum has only
//! `Build`, `Test` and `Harness`; none of them returns an artifact such as
//! `outcomes.json`. Phase 2 adds a `Step::Mutants { diff: String,
//! timeout_secs: u64 }` variant (diff passed in, `outcomes.json` returned on
//! stdout). Until then, [`MutationEngine::run`] only reports hypotheses when it
//! was given an `outcomes.json` produced elsewhere (e.g. by the maintainer's
//! own trusted CI), and otherwise returns an empty report — never an
//! `inconclusive` one, so enabling the engine in a policy cannot turn a
//! verdict into `Inconclusive`.

use std::collections::BTreeSet;

use serde::Deserialize;
use verifier_core::{
    Engine, EngineContext, EngineKind, EngineReport, FnSignature, Hypothesis, HypothesisSource,
};

/// Explanation logged when the engine runs without the phase-2 executor step.
pub const PHASE2_NOTE: &str = "mutation engine: running cargo-mutants inside the microVM needs a \
     `Step::Mutants` executor step (phase 2); no outcomes were supplied, so no hypotheses were produced";

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

/// The mutation engine. See the crate docs for what runs today.
#[derive(Debug, Clone, Default)]
pub struct MutationEngine {
    outcomes_json: Option<String>,
}

impl MutationEngine {
    /// Engine with no outcomes source: returns an empty report until the
    /// phase-2 executor step exists.
    pub fn new() -> Self {
        Self::default()
    }

    /// Engine that interprets an `outcomes.json` produced elsewhere, e.g. by
    /// the maintainer's trusted CI. Never feed it output of a run that
    /// happened outside a VM on untrusted code.
    pub fn from_outcomes_json(json: impl Into<String>) -> Self {
        MutationEngine {
            outcomes_json: Some(json.into()),
        }
    }

    /// The invocation the phase-2 step will run for this context.
    pub fn invocation(ctx: &EngineContext) -> MutantsInvocation {
        MutantsInvocation {
            diff_file: "/work/pr.diff".to_string(),
            output_dir: "/work/mutants".to_string(),
            timeout_secs: ctx.policy.budget.vm_timeout_secs.clamp(10, 120),
            jobs: ctx.policy.budget.vcpus.max(1),
            packages: vec![],
        }
    }
}

#[async_trait::async_trait]
impl Engine for MutationEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::Mutation
    }

    async fn run(&self, ctx: &EngineContext) -> anyhow::Result<EngineReport> {
        let Some(json) = &self.outcomes_json else {
            tracing::info!(argv = ?Self::invocation(ctx).run_argv(), "{PHASE2_NOTE}");
            return Ok(EngineReport::default());
        };
        let outcomes = parse_outcomes(json)?;
        Ok(EngineReport {
            findings: vec![],
            unreproduced: hypotheses_from_outcomes(
                &outcomes,
                &ctx.plan.changed_files,
                &ctx.plan.changed_functions,
            ),
            inconclusive: None,
            vm_seconds: 0,
        })
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

    struct NoExec;
    #[async_trait::async_trait]
    impl verifier_core::Executor for NoExec {
        async fn execute(
            &self,
            _: verifier_core::ExecutionRequest,
        ) -> anyhow::Result<verifier_core::ExecutionResult> {
            anyhow::bail!("mutation engine must not execute anything in phase 1")
        }
    }

    fn ctx() -> EngineContext {
        let sha = verifier_core::CommitSha::new("a".repeat(40)).unwrap();
        EngineContext {
            pr: verifier_core::PullRequest {
                repo: verifier_core::RepoId {
                    owner: "o".into(),
                    name: "n".into(),
                },
                number: 1,
                base_sha: sha.clone(),
                head_sha: sha,
                head_clone_url: String::new(),
                base_clone_url: String::new(),
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
            executor: std::sync::Arc::new(NoExec),
        }
    }

    #[tokio::test]
    async fn engine_reports_hypotheses_never_findings() {
        let r = MutationEngine::from_outcomes_json(FIXTURE)
            .run(&ctx())
            .await
            .unwrap();
        assert!(r.findings.is_empty());
        assert_eq!(r.unreproduced.len(), 1);
        assert!(r.inconclusive.is_none());

        let empty = MutationEngine::new().run(&ctx()).await.unwrap();
        assert_eq!(empty, EngineReport::default());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_outcomes("{\"outcomes\": 3}").is_err());
    }
}
