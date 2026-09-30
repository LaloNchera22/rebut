use serde::{Deserialize, Serialize};

use crate::{EnforcementMode, EngineKind, Finding, PullRequest, Seed, Visibility};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    /// No actionable findings.
    Pass,
    /// Actionable findings, mark mode: annotate, do not fail.
    Flagged,
    /// Actionable findings, block mode.
    Fail,
    /// The PR could not be evaluated (build failure, budget exhausted...).
    /// Never counted against the contributor.
    Inconclusive,
}

/// Full verdict. Maintainer-visible; stored and hashed into the receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub pr: PullRequest,
    pub seed: Option<Seed>,
    pub engines_run: Vec<EngineKind>,
    pub findings: Vec<Finding>,
    pub inconclusive_reason: Option<String>,
    pub mode: EnforcementMode,
}

impl Verdict {
    pub fn status(&self) -> VerdictStatus {
        if self.inconclusive_reason.is_some() {
            return VerdictStatus::Inconclusive;
        }
        if !self.findings.iter().any(Finding::is_actionable) {
            return VerdictStatus::Pass;
        }
        match self.mode {
            EnforcementMode::Mark => VerdictStatus::Flagged,
            EnforcementMode::Block => VerdictStatus::Fail,
        }
    }

    /// The only projection that may be shown to the contributor.
    pub fn for_contributor(&self) -> ContributorReport {
        let mut public = Vec::new();
        let mut sealed_categories = Vec::new();
        for f in &self.findings {
            match f.visibility {
                Visibility::Public => public.push(f.clone()),
                Visibility::Sealed => {
                    if f.is_actionable() {
                        sealed_categories.push(f.category.clone());
                    }
                }
            }
        }
        sealed_categories.sort();
        sealed_categories.dedup();
        ContributorReport {
            status: self.status(),
            seed: self.seed,
            engines_run: self.engines_run.clone(),
            public_findings: public,
            failed_sealed_categories: sealed_categories,
            inconclusive_reason: self.inconclusive_reason.clone(),
        }
    }
}

/// What the contributor sees: public findings in full, sealed findings only as
/// "you failed a challenge of category X". No stdout, stderr, inputs or
/// timings from sealed runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributorReport {
    pub status: VerdictStatus,
    pub seed: Option<Seed>,
    pub engines_run: Vec<EngineKind>,
    pub public_findings: Vec<Finding>,
    pub failed_sealed_categories: Vec<String>,
    pub inconclusive_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    fn repro(secret: &[u8]) -> Reproduction {
        let r = ExecutionResult {
            request_id: uuid::Uuid::nil(),
            outcomes: vec![StepOutcome {
                step_index: 0,
                exit_code: Some(1),
                timed_out: false,
                stdout: secret.to_vec(),
                stderr: vec![],
                duration_ms: 1,
            }],
            transcript: Digest::of(b"t"),
            environment: Digest::of(b"e"),
        };
        Reproduction::confirm(&r, 0, secret.to_vec(), b"ok".to_vec()).unwrap()
    }

    fn verdict(findings: Vec<Finding>, mode: EnforcementMode) -> Verdict {
        let sha = CommitSha::new("b".repeat(40)).unwrap();
        Verdict {
            pr: PullRequest {
                repo: RepoId {
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
            seed: None,
            engines_run: vec![EngineKind::Challenges],
            findings,
            inconclusive_reason: None,
            mode,
        }
    }

    #[test]
    fn sealed_details_never_reach_contributor() {
        let f = Finding::new(
            EngineKind::Challenges,
            "overflow",
            "sealed challenge failed",
            Visibility::Sealed,
            None,
            false,
            repro(b"SECRET-INPUT"),
        );
        let v = verdict(vec![f], EnforcementMode::Mark);
        let report = v.for_contributor();
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("SECRET"));
        assert_eq!(
            report.failed_sealed_categories,
            vec!["overflow".to_string()]
        );
        assert_eq!(report.status, VerdictStatus::Flagged);
    }

    #[test]
    fn mark_mode_never_fails() {
        let f = Finding::new(
            EngineKind::Differential,
            "divergence",
            "t",
            Visibility::Public,
            None,
            false,
            repro(b"x"),
        );
        assert_eq!(
            verdict(vec![f.clone()], EnforcementMode::Mark).status(),
            VerdictStatus::Flagged
        );
        assert_eq!(
            verdict(vec![f], EnforcementMode::Block).status(),
            VerdictStatus::Fail
        );
    }

    #[test]
    fn intent_explained_findings_pass() {
        let f = Finding::new(
            EngineKind::Differential,
            "divergence",
            "t",
            Visibility::Public,
            None,
            true,
            repro(b"x"),
        );
        assert_eq!(
            verdict(vec![f], EnforcementMode::Block).status(),
            VerdictStatus::Pass
        );
    }
}
