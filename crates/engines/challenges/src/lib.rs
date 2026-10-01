//! The challenge engine (ADR-7).
//!
//! Maintainers write challenge specs ([`spec`]): a target function, argument
//! generators and an oracle. Inputs are generated from the PR's drand-derived
//! [`Seed`] (see [`drand`]), so they are unpredictable before the push and
//! reproducible by anyone afterwards. Public specs come from
//! `.rebut/challenges.toml` on the base branch; sealed specs are supplied
//! privately, must match a commitment in the policy, run in sealed requests,
//! and produce [`Visibility::Sealed`] findings.
//!
//! Only the head commit is executed. As in the differential engine, a
//! screening request (all cases of a challenge in one harness step) runs
//! twice; cases that fail identically in both runs are re-run one per step in
//! a confirmation request, and a finding is built with
//! [`Reproduction::confirm`] against that single-case step, whose expected
//! observation is exactly what a passing single-case run reports
//! (`#harness-start` then `case 0 pass`, exit 0), in the canonical form of
//! the authenticated result channel ([`rebut_core::channel`]): nonce-free,
//! so expectations and findings stay reproducible. Output the code under
//! test prints is not part of it, and forged channel lines make the engine
//! inconclusive rather than let a failing case pass.

pub mod drand;
pub mod spec;

use std::path::Path;

use anyhow::Context;
use rebut_core::{
    Digest, Engine, EngineContext, EngineKind, EngineReport, ExecutionResult, Finding, Hypothesis,
    HypothesisSource, Reproduction, Step, StepOutcome, Visibility,
};
use rebut_differential::harness::{self, HarnessOutput, START_MARKER};
use rebut_differential::run::{consistent_success, execute, outcome, Side};

pub use drand::{BeaconSource, DrandClient, FixedBeacon};
pub use spec::{Challenge, SpecError};

/// Where public specs live in the base checkout.
pub const PUBLIC_SPECS_PATH: &str = ".rebut/challenges.toml";

#[derive(Debug, Clone)]
pub struct ChallengesConfig {
    /// Failing cases confirmed (and reported) per challenge.
    pub max_findings_per_challenge: usize,
    pub build_profile: String,
}

impl Default for ChallengesConfig {
    fn default() -> Self {
        ChallengesConfig {
            max_findings_per_challenge: 3,
            build_profile: "dev".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ChallengesEngine {
    /// Contents of `.rebut/challenges.toml` from the base branch.
    public_specs: Option<String>,
    config: ChallengesConfig,
}

/// A challenge with its encoded input lines.
struct Planned {
    ch: Challenge,
    lines: Vec<String>,
}

impl Planned {
    fn step(&self, lines: &[String]) -> Step {
        Step::Harness {
            name: format!("challenge_{}", self.ch.spec.id.replace('-', "_")),
            source: spec::harness_source(&self.ch),
            input: harness::encode_input(lines),
        }
    }
}

struct Candidate {
    planned: usize,
    line: String,
    /// `None`: the harness died on this case.
    payload: Option<String>,
}

fn is_failure(payload: &str) -> bool {
    payload == "fail" || payload == "panic"
}

/// What a passing single-case harness step looks like to
/// [`Reproduction::confirm`]. Checked against core on every use: if the
/// observation format ever changed, every case would look like a failure, so
/// we refuse to run rather than emit false findings.
fn pass_expectation() -> anyhow::Result<Vec<u8>> {
    let stdout = format!("{START_MARKER}\ncase 0 pass\n").into_bytes();
    let expected = [b"exit:Some(0)\n".as_slice(), &stdout].concat();
    let probe = ExecutionResult {
        request_id: Default::default(),
        outcomes: vec![StepOutcome {
            step_index: 0,
            exit_code: Some(0),
            timed_out: false,
            stdout,
            stderr: vec![],
            duration_ms: 0,
        }],
        transcript: Digest::of(b"probe"),
        environment: Digest::of(b"probe"),
    };
    if Reproduction::confirm(&probe, 0, vec![], expected.clone()).is_some() {
        anyhow::bail!("core's observation format changed; refusing to judge challenge results");
    }
    Ok(expected)
}

impl ChallengesEngine {
    /// No public specs (sealed specs still come from the context).
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_public_specs(toml_src: impl Into<String>) -> Self {
        ChallengesEngine {
            public_specs: Some(toml_src.into()),
            ..Self::default()
        }
    }

    /// Reads [`PUBLIC_SPECS_PATH`] from a base-branch checkout, if present.
    /// Never pass the head checkout: a PR must not choose its own challenges.
    pub fn from_base_checkout(base: &Path) -> std::io::Result<Self> {
        match std::fs::read_to_string(base.join(PUBLIC_SPECS_PATH)) {
            Ok(s) => Ok(Self::with_public_specs(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(e),
        }
    }

    pub fn with_config(mut self, config: ChallengesConfig) -> Self {
        self.config = config;
        self
    }

    /// Public and sealed challenges for this PR. Fails on malformed specs
    /// and on sealed specs that match no commitment.
    pub fn challenges(&self, ctx: &EngineContext) -> anyhow::Result<Vec<Challenge>> {
        let mut out = match &self.public_specs {
            Some(s) => spec::parse_public(s).context("public challenge specs")?,
            None => vec![],
        };
        for s in &ctx.sealed_specs {
            out.extend(spec::parse_sealed(s, &ctx.policy.sealed_commitments)?);
        }
        Ok(out)
    }

    /// Runs one visibility group. Returns `Some(reason)` if inconclusive.
    async fn run_group(
        &self,
        ctx: &EngineContext,
        group: &[Planned],
        sealed: bool,
        report: &mut EngineReport,
    ) -> anyhow::Result<Option<String>> {
        let build = Step::Build {
            profile: self.config.build_profile.clone(),
        };
        let mut steps = vec![build.clone()];
        steps.extend(group.iter().map(|p| p.step(&p.lines)));
        let mut runs = Vec::new();
        for _ in 0..2 {
            runs.push(
                execute(
                    ctx,
                    Side::Head,
                    steps.clone(),
                    sealed,
                    &mut report.vm_seconds,
                )
                .await?,
            );
        }
        match consistent_success(&runs, 0) {
            Some(true) => {}
            Some(false) => return Ok(Some("head does not build".into())),
            None => return Ok(Some("build result is nondeterministic".into())),
        }

        let note = |p: &Planned, claim: String, line: Option<&String>| Hypothesis {
            source: HypothesisSource::Generator,
            target: p.ch.spec.target.clone(),
            claim: format!("challenge `{}`: {claim}", p.ch.spec.id),
            // Never copy sealed inputs anywhere but a sealed finding.
            candidate_input: line.filter(|_| !sealed).map(|l| l.as_bytes().to_vec()),
        };

        let mut candidates = Vec::new();
        let mut tampered = Vec::new();
        for (pi, p) in group.iter().enumerate() {
            let outs: Vec<HarnessOutput> = runs
                .iter()
                .map(|r| {
                    outcome(r, 1 + pi)
                        .map(|o| HarnessOutput::parse(&o.stdout))
                        .unwrap_or_default()
                })
                .collect();
            if outs.iter().any(|o| o.tampered) {
                tampered.push(p.ch.spec.id.clone());
                continue;
            }
            if !outs.iter().all(|o| o.started) {
                report.unreproduced.push(note(
                    p,
                    "harness did not compile or start on head (spec error or API change); not evaluated".into(),
                    None,
                ));
                continue;
            }
            let mut flaky = 0;
            let mut found = 0;
            for (ci, line) in p.lines.iter().enumerate() {
                if found >= self.config.max_findings_per_challenge {
                    break;
                }
                let payload = match (outs[0].cases.get(&ci), outs[1].cases.get(&ci)) {
                    (Some(a), Some(b)) if a == b => Some(a),
                    (None, None) => None,
                    (Some(_), Some(_)) => {
                        flaky += 1;
                        continue;
                    }
                    _ => {
                        flaky += 1;
                        break;
                    }
                };
                if payload.is_some_and(|p| !is_failure(p)) {
                    continue;
                }
                found += 1;
                candidates.push(Candidate {
                    planned: pi,
                    line: line.clone(),
                    payload: payload.cloned(),
                });
                if payload.is_none() {
                    break;
                }
            }
            if flaky > 0 {
                report.unreproduced.push(note(
                    p,
                    format!("{flaky} case(s) gave different results on identical runs; excluded"),
                    None,
                ));
            }
        }
        if candidates.is_empty() {
            return Ok(tamper_reason(&tampered, sealed));
        }

        let expected = pass_expectation()?;
        let mut steps = vec![build];
        for c in &candidates {
            steps.push(group[c.planned].step(std::slice::from_ref(&c.line)));
        }
        let confirm = execute(ctx, Side::Head, steps, sealed, &mut report.vm_seconds).await?;
        let rebuilt = consistent_success(std::slice::from_ref(&confirm), 0) == Some(true);
        for (i, c) in candidates.iter().enumerate() {
            let step = 1 + i;
            let p = &group[c.planned];
            let parsed = outcome(&confirm, step).map(|o| (o, HarnessOutput::parse(&o.stdout)));
            if parsed.as_ref().is_some_and(|(_, h)| h.tampered) {
                tampered.push(p.ch.spec.id.clone());
                continue;
            }
            let consistent = rebuilt
                && parsed.is_some_and(|(o, h)| {
                    !o.timed_out && h.started && h.cases.get(&0) == c.payload.as_ref()
                });
            let input = harness::encode_input(std::slice::from_ref(&c.line));
            let repro = consistent
                .then(|| Reproduction::confirm(&confirm, step, input, expected.clone()))
                .flatten();
            match repro {
                Some(r) => report.findings.push(Finding::new(
                    EngineKind::Challenges,
                    p.ch.category(),
                    p.ch.title(),
                    p.ch.visibility,
                    Some(p.ch.spec.target.clone()),
                    false,
                    r,
                )),
                None => report.unreproduced.push(note(
                    p,
                    "failure seen during screening did not reproduce in a single-case run".into(),
                    Some(&c.line),
                )),
            }
        }
        Ok(tamper_reason(&tampered, sealed))
    }
}

/// Why a group is inconclusive when some harness output was forged. Sealed
/// challenge ids are not named: the reason reaches the contributor.
fn tamper_reason(ids: &[String], sealed: bool) -> Option<String> {
    let mut ids = ids.to_vec();
    ids.dedup();
    let which = if sealed {
        "a sealed challenge".to_string()
    } else {
        format!("challenge(s) {}", ids.join(", "))
    };
    (!ids.is_empty()).then(|| {
        format!("harness result channel tampered with in {which}; results cannot be trusted")
    })
}

#[async_trait::async_trait]
impl Engine for ChallengesEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::Challenges
    }

    async fn run(&self, ctx: &EngineContext) -> anyhow::Result<EngineReport> {
        let mut report = EngineReport::default();
        let challenges = self.challenges(ctx)?;
        if challenges.is_empty() {
            return Ok(report);
        }
        let Some(seed) = ctx.seed else {
            report.inconclusive =
                Some("no drand seed available; challenges need a public seed (ADR-7)".into());
            return Ok(report);
        };

        let mut public_budget = ctx.policy.budget.public_challenges as usize;
        let (mut public, mut sealed) = (Vec::new(), Vec::new());
        for ch in challenges {
            let wanted = ch.spec.cases as usize;
            let n = match ch.visibility {
                Visibility::Public => {
                    let n = wanted.min(public_budget);
                    public_budget -= n;
                    n
                }
                Visibility::Sealed => wanted,
            };
            if n == 0 {
                report.unreproduced.push(Hypothesis {
                    source: HypothesisSource::Generator,
                    target: ch.spec.target.clone(),
                    claim: format!(
                        "challenge `{}` skipped: public case budget exhausted",
                        ch.spec.id
                    ),
                    candidate_input: None,
                });
                continue;
            }
            let lines = spec::generate_cases(&ch, &seed, n)
                .iter()
                .map(|c| harness::encode_case(c))
                .collect();
            let planned = Planned { ch, lines };
            match planned.ch.visibility {
                Visibility::Public => public.push(planned),
                Visibility::Sealed => sealed.push(planned),
            }
        }

        // Public and sealed cases never share a request.
        for (group, is_sealed) in [(&public, false), (&sealed, true)] {
            if group.is_empty() {
                continue;
            }
            if let Some(reason) = self.run_group(ctx, group, is_sealed, &mut report).await? {
                report.inconclusive = Some(reason);
                return Ok(report);
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
