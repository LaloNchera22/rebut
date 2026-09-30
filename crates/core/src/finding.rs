//! ADR-6: the output of an LLM is never evidence.
//!
//! [`Hypothesis`] is what generators (the rival agent, LLM-proposed Kani
//! invariants, heuristics) produce. It carries no weight in a verdict.
//! [`Finding`] is what a verdict is made of, and the only constructor takes a
//! [`Reproduction`], whose only constructor takes an [`ExecutionResult`] that
//! actually showed the divergence.

use serde::{Deserialize, Serialize};

use crate::{Digest, EngineKind, ExecutionResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisSource {
    Llm,
    Heuristic,
    Generator,
}

/// A claim that something *might* be wrong. Not evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub source: HypothesisSource,
    pub target: String,
    pub claim: String,
    /// Proposed concrete input, if the generator produced one.
    pub candidate_input: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// Contributor sees everything.
    Public,
    /// Contributor sees only the category; maintainer sees the case.
    Sealed,
}

/// A concrete, deterministic, recorded counterexample.
///
/// Fields are private: the only way to obtain one is [`Reproduction::confirm`],
/// which checks the execution actually disagreed with the expectation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reproduction {
    input: Vec<u8>,
    expected: Vec<u8>,
    observed: Vec<u8>,
    transcript: Digest,
}

impl Reproduction {
    /// Confirms a counterexample from a real run. `observed` must be taken from
    /// `result`'s outcomes (the caller selects which step's stdout); this
    /// returns `None` if the step does not exist or if the observation matches
    /// the expectation — i.e. there is nothing to report.
    pub fn confirm(
        result: &ExecutionResult,
        step_index: usize,
        input: Vec<u8>,
        expected: Vec<u8>,
    ) -> Option<Reproduction> {
        let outcome = result
            .outcomes
            .iter()
            .find(|o| o.step_index == step_index)?;
        let observed = observation(outcome);
        if observed == expected {
            return None;
        }
        Some(Reproduction {
            input,
            expected,
            observed,
            transcript: result.transcript,
        })
    }

    /// Confirms a divergence between two real runs on the same input
    /// (differential testing: base vs head). Expected = base behavior.
    pub fn confirm_divergence(
        base: &ExecutionResult,
        base_step: usize,
        head: &ExecutionResult,
        head_step: usize,
        input: Vec<u8>,
    ) -> Option<Reproduction> {
        let b = base.outcomes.iter().find(|o| o.step_index == base_step)?;
        let h = head.outcomes.iter().find(|o| o.step_index == head_step)?;
        let (expected, observed) = (observation(b), observation(h));
        if expected == observed {
            return None;
        }
        Some(Reproduction {
            input,
            expected,
            observed,
            transcript: Digest::of_parts(&[&base.transcript.0, &head.transcript.0]),
        })
    }

    pub fn input(&self) -> &[u8] {
        &self.input
    }
    pub fn expected(&self) -> &[u8] {
        &self.expected
    }
    pub fn observed(&self) -> &[u8] {
        &self.observed
    }
    pub fn transcript(&self) -> Digest {
        self.transcript
    }
}

/// Canonical observable behavior of a step: exit status plus stdout. Stderr and
/// timings are excluded on purpose — they are noisy and would create false
/// positives (the Skeptic's rule).
fn observation(o: &crate::StepOutcome) -> Vec<u8> {
    let status = if o.timed_out {
        "timeout".to_string()
    } else {
        format!("exit:{:?}", o.exit_code)
    };
    let mut v = status.into_bytes();
    v.push(b'\n');
    v.extend_from_slice(&o.stdout);
    v
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub engine: EngineKind,
    /// Stable category shown even for sealed findings, e.g. `integer-overflow`.
    pub category: String,
    pub title: String,
    pub visibility: Visibility,
    /// Function or test the finding is about, if known.
    pub target: Option<String>,
    /// Whether the declared intent permits this behavior change. Findings that
    /// the intent explains are informational, never counted against the PR.
    pub explained_by_intent: bool,
    reproduction: Reproduction,
}

impl Finding {
    pub fn new(
        engine: EngineKind,
        category: impl Into<String>,
        title: impl Into<String>,
        visibility: Visibility,
        target: Option<String>,
        explained_by_intent: bool,
        reproduction: Reproduction,
    ) -> Self {
        Finding {
            engine,
            category: category.into(),
            title: title.into(),
            visibility,
            target,
            explained_by_intent,
            reproduction,
        }
    }

    pub fn reproduction(&self) -> &Reproduction {
        &self.reproduction
    }

    /// Counts against the PR (not explained by the declared intent).
    pub fn is_actionable(&self) -> bool {
        !self.explained_by_intent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecutionResult, StepOutcome};

    fn result(stdout: &[u8]) -> ExecutionResult {
        ExecutionResult {
            request_id: uuid::Uuid::nil(),
            outcomes: vec![StepOutcome {
                step_index: 0,
                exit_code: Some(0),
                timed_out: false,
                stdout: stdout.to_vec(),
                stderr: b"noise".to_vec(),
                duration_ms: 7,
            }],
            transcript: Digest::of(stdout),
            environment: Digest::of(b"env"),
        }
    }

    #[test]
    fn matching_output_is_not_a_reproduction() {
        let r = result(b"42");
        assert!(Reproduction::confirm(&r, 0, vec![], b"exit:Some(0)\n42".to_vec()).is_none());
        assert!(Reproduction::confirm(&r, 0, vec![], b"exit:Some(0)\n41".to_vec()).is_some());
        assert!(Reproduction::confirm(&r, 9, vec![], vec![]).is_none());
    }

    #[test]
    fn divergence_ignores_stderr_and_timing() {
        let a = result(b"1");
        let mut b = result(b"1");
        b.outcomes[0].stderr = b"different".to_vec();
        b.outcomes[0].duration_ms = 9999;
        assert!(Reproduction::confirm_divergence(&a, 0, &b, 0, vec![]).is_none());
        let c = result(b"2");
        assert!(Reproduction::confirm_divergence(&a, 0, &c, 0, vec![]).is_some());
    }
}
