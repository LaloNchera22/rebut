//! The rival agent.
//!
//! A [`HypothesisGenerator`] (an LLM, a heuristic, a fuzzer's corpus) reads a
//! PR and guesses where it breaks. Its output is untrusted: a guess is a
//! [`Hypothesis`], never a [`Finding`] (ADR-6). [`AdversaryEngine`] is the
//! [`Engine`] the orchestrator runs: it asks the generator, then hands the
//! guesses to [`Adversary::triage`], which deduplicates them and, for each one
//! that targets a changed, harnessable function and carries a concrete
//! `candidate_input`, runs a harness through the [`Executor`] (the microVM
//! fabric). Only an execution that actually misbehaves, twice in a row, and
//! not already on base, becomes a `Finding`, via [`Reproduction::confirm`] /
//! [`Reproduction::confirm_divergence`]. Everything else (hallucinations,
//! inputs that don't reproduce, targets we can't harness, replays cut by the
//! budget) ends in [`EngineReport::unreproduced`] with the reason appended to
//! its claim, for tuning.
//!
//! The model never chooses what runs. The harness source is generated here
//! from the planner's [`FnSignature`], the step list is fixed
//! (`Build`, `Harness`), and the only model-controlled bytes that reach the
//! executor are the harness's stdin.
//!
//! The rival agent is an extra, never a reason to withhold a pass. A failing
//! generator (network, rate limit, malformed answer, timeout) or an executor
//! error mid-triage yields a report with whatever was confirmed so far and no
//! `inconclusive` reason: the orchestrator turns any inconclusive engine into
//! an `Inconclusive` verdict, and a flaky LLM must not do that to a PR. The
//! cost is a possibly missed bug, which the Skeptic's rule accepts. The one
//! exception is a harness whose result channel ([`rebut_core::channel`]) was
//! forged: that is the PR's doing, and an untrusted result is never a pass.
//!
//! The consequence the ML engineer accepted when proposing ADR-6: a rival
//! agent that hallucinates costs VM-seconds, never a contributor's reputation.
//! And a prompt-injected agent (the PR body is attacker-controlled) can at
//! worst *miss* bugs; it cannot fabricate one.

pub mod anthropic;
pub mod openai;
pub mod prompt;
pub mod provider;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

pub use anthropic::{AnthropicGenerator, ANTHROPIC_VERSION, DEFAULT_MODEL};
pub use openai::{OpenAiCompatGenerator, DEFAULT_LOCAL_MODEL, OLLAMA_URL};
pub use prompt::{parse_hypotheses, parse_hypotheses_lenient};
pub use provider::{AdversaryConfig, Provider};
use rebut_core::{
    channel, CommitSha, Engine, EngineContext, EngineKind, EngineReport, ExecutionRequest,
    ExecutionResult, Executor, Finding, FnSignature, Hypothesis, Reproduction, Step, StepOutcome,
    Visibility,
};

/// Anything that proposes hypotheses about a PR.
#[async_trait::async_trait]
pub trait HypothesisGenerator: Send + Sync {
    /// Cheap reachability check (e.g. a local model server that isn't
    /// running), so callers can warn and skip the engine instead of waiting
    /// on [`propose`](Self::propose).
    async fn ready(&self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn propose(&self, ctx: &EngineContext) -> anyhow::Result<Vec<Hypothesis>>;
}

/// What a replay is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Oracle {
    /// The head must not panic (or exit non-zero) on the input, unless base
    /// fails on it too (a pre-existing bug is not this PR's).
    NoPanic,
    /// The head must behave like the base on the input. A divergence the
    /// declared intent allows is recorded as informational, never actionable.
    Differential,
}

/// How a target function takes its single input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputShape {
    Bytes,
    ByteVec,
    Str,
    OwnedString,
}

impl InputShape {
    pub fn of(sig: &FnSignature) -> Option<Self> {
        match sig.args.as_slice() {
            [a] => match a.replace(' ', "").as_str() {
                "&[u8]" => Some(InputShape::Bytes),
                "Vec<u8>" => Some(InputShape::ByteVec),
                "&str" => Some(InputShape::Str),
                "String" => Some(InputShape::OwnedString),
                _ => None,
            },
            _ => None,
        }
    }

    fn is_text(self) -> bool {
        matches!(self, InputShape::Str | InputShape::OwnedString)
    }
}

const START: &[u8] = b"rebut:start\n";

/// Harness program feeding stdin (after the nonce line of the authenticated
/// result channel, [`rebut_core::channel`]) to `sig`. Protocol, in canonical
/// form: `rebut:start` right before the call, then (differential)
/// `rebut:ret:{ret:?}`, then `rebut:done`. A panic exits 101 after
/// `rebut:start`.
pub fn harness_source(sig: &FnSignature, shape: InputShape, oracle: Oracle) -> String {
    let arg = match shape {
        InputShape::Bytes => "&buf",
        InputShape::ByteVec => "buf",
        InputShape::Str => "&text",
        InputShape::OwnedString => "text",
    };
    let mut s = format!(
        "// Harness generated by rebut-adversary for `{}`.\nuse std::io::Read as _;\n{}\nfn main() {{\n    let mut __ch = __RebutChannel::open();\n    let mut buf = Vec::new();\n    std::io::stdin().read_to_end(&mut buf).expect(\"stdin\");\n",
        sig.path,
        channel::HARNESS_SOURCE
    );
    if shape.is_text() {
        s.push_str(
            "    let text = String::from_utf8(buf).expect(\"utf-8 checked by the host\");\n",
        );
    }
    s.push_str("    __ch.send(\"rebut:start\");\n");
    s.push_str(&format!("    let ret = {}({arg});\n", sig.path));
    match oracle {
        Oracle::Differential => s.push_str(
            "    __ch.send(&format!(\"rebut:ret:{:?}\", ret).replace('\\n', \"\\\\n\"));\n",
        ),
        Oracle::NoPanic => s.push_str("    let _ = ret;\n"),
    }
    s.push_str("    __ch.send(\"rebut:done\");\n}\n");
    s
}

/// Triage of untrusted hypotheses.
#[derive(Debug, Clone)]
pub struct Adversary {
    pub oracle: Oracle,
    /// Max hypotheses replayed per PR.
    pub max_runs: usize,
    /// Share of `policy.budget.pr_vm_seconds` this engine may spend, in
    /// percent. Checked before each replay; a replay in progress finishes.
    pub vm_share_percent: u8,
    /// Max candidate input size accepted, in bytes.
    pub max_input_bytes: usize,
}

impl Default for Adversary {
    fn default() -> Self {
        Adversary {
            oracle: Oracle::NoPanic,
            max_runs: 8,
            vm_share_percent: 25,
            max_input_bytes: 64 * 1024,
        }
    }
}

fn request(
    ctx: &EngineContext,
    repo_url: &str,
    commit: &CommitSha,
    name: String,
    source: String,
    input: Vec<u8>,
) -> ExecutionRequest {
    let b = &ctx.policy.budget;
    ExecutionRequest {
        id: uuid::Uuid::new_v4(),
        repo_url: repo_url.to_string(),
        commit: commit.clone(),
        steps: vec![
            Step::Build {
                profile: "dev".to_string(),
            },
            Step::Harness {
                name,
                source,
                input,
            },
        ],
        timeout_secs: b.vm_timeout_secs,
        vcpus: b.vcpus,
        memory_mib: b.memory_mib,
        sealed: false,
        env: BTreeMap::new(),
    }
}

fn harness_step(r: &ExecutionResult) -> Option<&StepOutcome> {
    r.outcomes.iter().find(|o| o.step_index == 1)
}

/// Why a replay is dropped when its harness output was forged.
const FORGED: &str = "harness output forged";

/// Whether the harness's canonical output (step 1) is a sequence it can
/// report: `rebut:start`, then for a full run `rebut:ret:..` (differential
/// only) and `rebut:done`. Anything else was written by someone else.
fn well_formed(r: &ExecutionResult, oracle: Oracle) -> bool {
    let Some(o) = harness_step(r) else {
        return true;
    };
    let lines: Vec<&[u8]> = o.stdout.split(|&b| b == b'\n').collect();
    match (lines.as_slice(), oracle) {
        ([b""] | [b"rebut:start", b""], _) => true,
        ([b"rebut:start", b"rebut:done", b""], Oracle::NoPanic) => true,
        ([b"rebut:start", ret, b"rebut:done", b""], Oracle::Differential) => {
            ret.starts_with(b"rebut:ret:")
        }
        _ => false,
    }
}

/// The call returned and the harness reported it: a clean exit alone is not
/// enough (the code under test can call `process::exit(0)`).
fn completed(r: &ExecutionResult) -> bool {
    harness_step(r).is_some_and(|o| o.success() && o.stdout.ends_with(b"rebut:done\n"))
}

/// The harness (step 1) started, finished or panicked, but did not time out
/// and did not fail before reaching the call.
fn harness_ran(r: &ExecutionResult) -> bool {
    let built = r.outcomes.iter().any(|o| o.step_index == 0 && o.success());
    built && matches!(harness_step(r), Some(o) if !o.timed_out && o.stdout.starts_with(START))
}

/// Two runs of the same request observed the same thing (exit status and
/// stdout, like `Reproduction`; stderr and timings are noise).
fn same_observation(a: &ExecutionResult, b: &ExecutionResult) -> bool {
    match (harness_step(a), harness_step(b)) {
        (Some(a), Some(b)) => {
            a.exit_code == b.exit_code && a.timed_out == b.timed_out && a.stdout == b.stdout
        }
        _ => false,
    }
}

fn vm_secs(r: &ExecutionResult) -> u64 {
    // Rounded up: under-counting would let the engine overrun its share.
    r.outcomes
        .iter()
        .map(|o| o.duration_ms)
        .sum::<u64>()
        .div_ceil(1000)
}

/// One replay's outcome: a confirmed finding, or why the hypothesis did not
/// make it.
type Replay = Result<Finding, &'static str>;

impl Adversary {
    /// VM-seconds this engine may spend on `ctx`'s PR.
    pub fn vm_budget_secs(&self, ctx: &EngineContext) -> u64 {
        ctx.policy.budget.pr_vm_seconds * u64::from(self.vm_share_percent.min(100)) / 100
    }

    /// Replay the hypotheses that can be replayed, within budget; only
    /// confirmed executions become findings. Never fails: an executor error
    /// stops the replays and the rest go to `unreproduced`.
    pub async fn triage(
        &self,
        hypotheses: Vec<Hypothesis>,
        executor: &dyn Executor,
        ctx: &EngineContext,
    ) -> EngineReport {
        let mut report = EngineReport::default();
        let mut seen = BTreeSet::new();
        let mut runs = 0usize;
        let mut halted: Option<String> = None;
        let budget = self.vm_budget_secs(ctx);
        for mut h in hypotheses {
            if !seen.insert((h.target.clone(), h.candidate_input.clone())) {
                tracing::debug!(target = %h.target, "dropping duplicate hypothesis");
                continue;
            }
            let why_not = |h: &mut Hypothesis, why: &str| h.claim.push_str(&format!(" [{why}]"));
            let Some(input) = h.candidate_input.clone() else {
                why_not(&mut h, "no candidate input");
                report.unreproduced.push(h);
                continue;
            };
            let Some(sig) = ctx
                .plan
                .changed_functions
                .iter()
                .find(|s| s.path == h.target)
            else {
                why_not(&mut h, "target is not a changed function");
                report.unreproduced.push(h);
                continue;
            };
            let Some(shape) = InputShape::of(sig).filter(|_| sig.is_pub) else {
                why_not(&mut h, "no harness for this signature");
                report.unreproduced.push(h);
                continue;
            };
            if input.len() > self.max_input_bytes
                || (shape.is_text() && std::str::from_utf8(&input).is_err())
            {
                why_not(&mut h, "candidate input rejected");
                report.unreproduced.push(h);
                continue;
            }
            if let Some(reason) = &halted {
                why_not(&mut h, &format!("replays halted: {reason}"));
                report.unreproduced.push(h);
                continue;
            }
            if runs >= self.max_runs {
                why_not(&mut h, "adversary replay cap reached");
                report.unreproduced.push(h);
                continue;
            }
            if report.vm_seconds >= budget {
                why_not(&mut h, "adversary VM budget share exhausted");
                report.unreproduced.push(h);
                continue;
            }
            runs += 1;
            let replay = self
                .replay(
                    sig,
                    shape,
                    input,
                    runs,
                    executor,
                    ctx,
                    &mut report.vm_seconds,
                )
                .await;
            match replay {
                Ok(Ok(f)) => report.findings.push(f),
                Ok(Err(why)) => {
                    if why == FORGED {
                        report.inconclusive = Some(format!(
                            "adversary harness result channel tampered with while testing \
                             `{}`; results cannot be trusted",
                            sig.path
                        ));
                    }
                    why_not(&mut h, why);
                    report.unreproduced.push(h);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "executor failed; stopping adversary replays");
                    let reason = format!("executor error: {e:#}");
                    why_not(&mut h, &reason);
                    report.unreproduced.push(h);
                    halted = Some(reason);
                }
            }
        }
        report
    }

    /// Run one hypothesis. The outer error is an executor failure; the inner
    /// one a hypothesis that did not hold up.
    #[allow(clippy::too_many_arguments)]
    async fn replay(
        &self,
        sig: &FnSignature,
        shape: InputShape,
        input: Vec<u8>,
        n: usize,
        executor: &dyn Executor,
        ctx: &EngineContext,
        vm_seconds: &mut u64,
    ) -> anyhow::Result<Replay> {
        let name = format!("adversary_{n}");
        let source = harness_source(sig, shape, self.oracle);
        let pr = &ctx.pr;
        let req = |head: bool| {
            let (url, sha) = if head {
                (&pr.head_clone_url, &pr.head_sha)
            } else {
                (&pr.base_clone_url, &pr.base_sha)
            };
            request(ctx, url, sha, name.clone(), source.clone(), input.clone())
        };
        let run = |head: bool| {
            let req = req(head);
            async move { channel::execute(executor, req).await }
        };
        let oracle = self.oracle;
        let mut charge = |r: ExecutionResult| {
            *vm_seconds += vm_secs(&r);
            well_formed(&r, oracle).then_some(r).ok_or(FORGED)
        };

        let head = match charge(run(true).await?) {
            Ok(r) => r,
            Err(forged) => return Ok(Err(forged)),
        };
        if !harness_ran(&head) {
            return Ok(Err("harness did not reach the call on head"));
        }
        match self.oracle {
            Oracle::NoPanic => {
                // Only a failing call counts. Comparing the whole stdout with
                // a fixed expectation would flag functions that print.
                if completed(&head) {
                    return Ok(Err("did not reproduce"));
                }
                let base = match charge(run(false).await?) {
                    Ok(r) => r,
                    Err(forged) => return Ok(Err(forged)),
                };
                if harness_ran(&base) && !completed(&base) {
                    return Ok(Err("also fails on base: not introduced by this PR"));
                }
                let again = match charge(run(true).await?) {
                    Ok(r) => r,
                    Err(forged) => return Ok(Err(forged)),
                };
                if !same_observation(&head, &again) {
                    return Ok(Err("not deterministic on head"));
                }
                let expected = b"exit:Some(0)\nrebut:start\nrebut:done\n".to_vec();
                Ok(Reproduction::confirm(&head, 1, input, expected)
                    .map(|r| {
                        Finding::new(
                            EngineKind::Adversary,
                            "panic",
                            format!("`{}` panics on an adversarial input", sig.path),
                            Visibility::Public,
                            Some(sig.path.clone()),
                            false,
                            r,
                        )
                    })
                    .ok_or("did not reproduce"))
            }
            Oracle::Differential => {
                let base = match charge(run(false).await?) {
                    Ok(r) => r,
                    Err(forged) => return Ok(Err(forged)),
                };
                if !harness_ran(&base) {
                    return Ok(Err("harness did not reach the call on base"));
                }
                let Some(repro) =
                    Reproduction::confirm_divergence(&base, 1, &head, 1, input.clone())
                else {
                    return Ok(Err("did not reproduce"));
                };
                let (head2, base2) = match (charge(run(true).await?), charge(run(false).await?)) {
                    (Ok(h), Ok(b)) => (h, b),
                    _ => return Ok(Err(FORGED)),
                };
                if !same_observation(&head, &head2) || !same_observation(&base, &base2) {
                    return Ok(Err("not deterministic"));
                }
                Ok(Ok(Finding::new(
                    EngineKind::Adversary,
                    "divergence",
                    format!(
                        "`{}` behaves differently from base on an adversarial input",
                        sig.path
                    ),
                    Visibility::Public,
                    Some(sig.path.clone()),
                    ctx.intent.allows_behavior_change(&sig.path),
                    repro,
                )))
            }
        }
    }
}

/// The rival agent as an [`Engine`]: generator, then [`Adversary::triage`].
pub struct AdversaryEngine {
    generator: Arc<dyn HypothesisGenerator>,
    pub adversary: Adversary,
    /// Wall-clock limit for the generator. Past it, the engine carries on as
    /// if the generator had proposed nothing, before the orchestrator's own
    /// timeout would mark the whole verdict inconclusive.
    pub generator_timeout: Duration,
}

impl std::fmt::Debug for AdversaryEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdversaryEngine")
            .field("adversary", &self.adversary)
            .field("generator_timeout", &self.generator_timeout)
            .finish_non_exhaustive()
    }
}

impl AdversaryEngine {
    pub fn new(generator: Arc<dyn HypothesisGenerator>) -> Self {
        AdversaryEngine {
            generator,
            adversary: Adversary::default(),
            generator_timeout: Duration::from_secs(180),
        }
    }

    /// Backed by [`AnthropicGenerator::from_env`] (`ANTHROPIC_API_KEY`,
    /// optional `REBUT_ADVERSARY_MODEL`).
    pub fn anthropic_from_env() -> anyhow::Result<Self> {
        Ok(Self::new(Arc::new(AnthropicGenerator::from_env()?)))
    }
}

#[async_trait::async_trait]
impl Engine for AdversaryEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::Adversary
    }

    async fn run(&self, ctx: &EngineContext) -> anyhow::Result<EngineReport> {
        let proposed = tokio::time::timeout(self.generator_timeout, self.generator.propose(ctx));
        let hyps = match proposed.await {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "hypothesis generator failed; nothing to replay");
                return Ok(EngineReport::default());
            }
            Err(_) => {
                tracing::warn!(timeout = ?self.generator_timeout,
                    "hypothesis generator timed out; nothing to replay");
                return Ok(EngineReport::default());
            }
        };
        Ok(self
            .adversary
            .triage(hyps, ctx.executor.as_ref(), ctx)
            .await)
    }
}

#[cfg(test)]
mod tests;
