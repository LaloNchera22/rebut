//! The forge (GitHub today): read files at a commit, publish check runs.
//!
//! Everything shown on the forge is rendered from a [`ContributorReport`],
//! never from a [`rebut_core::Verdict`], so sealed challenge details cannot
//! leak through the check run.

use std::fmt::Write as _;

use rebut_core::{CommitSha, ContributorReport, EnforcementMode, RepoId, VerdictStatus};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CHECK_NAME: &str = "rebut / verify";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conclusion {
    Success,
    Neutral,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckRun {
    pub name: String,
    pub head_sha: CommitSha,
    pub conclusion: Conclusion,
    pub title: String,
    pub summary: String,
    pub details_url: Option<String>,
}

#[async_trait::async_trait]
pub trait Forge: Send + Sync {
    /// Contents of `path` at `commit`, or `None` if the file does not exist.
    async fn file_at(
        &self,
        repo: &RepoId,
        commit: &CommitSha,
        path: &str,
    ) -> anyhow::Result<Option<String>>;
    async fn publish_check_run(&self, repo: &RepoId, run: &CheckRun) -> anyhow::Result<()>;
}

/// Check-run conclusion. Mark mode never fails a PR (the Skeptic's rule):
/// only a `Fail` verdict under `Block` mode maps to `failure`.
pub fn conclusion(status: VerdictStatus, mode: EnforcementMode) -> Conclusion {
    match (status, mode) {
        (VerdictStatus::Pass, _) => Conclusion::Success,
        (VerdictStatus::Fail, EnforcementMode::Block) => Conclusion::Failure,
        (VerdictStatus::Fail, EnforcementMode::Mark)
        | (VerdictStatus::Flagged, _)
        | (VerdictStatus::Inconclusive, _) => Conclusion::Neutral,
    }
}

/// Where the receipt for a run can be fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptRef {
    pub id: Uuid,
    pub log_index: u64,
    pub url: Option<String>,
}

const MAX_BYTES_SHOWN: usize = 256;
/// GitHub rejects check-run summaries above 65535 characters.
const MAX_SUMMARY: usize = 60_000;

fn show_bytes(b: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(&b[..b.len().min(MAX_BYTES_SHOWN)]).into_owned();
    if b.len() > MAX_BYTES_SHOWN {
        s.push_str(" …");
    }
    // Keep contributor-controlled text inside its code block.
    s.replace("```", "`\u{200b}``")
}

/// Title and Markdown summary of a check run.
pub fn render(report: &ContributorReport, receipt: Option<&ReceiptRef>) -> (String, String) {
    let title = match report.status {
        VerdictStatus::Pass => "No behavior problems found".to_string(),
        VerdictStatus::Inconclusive => "Verification inconclusive".to_string(),
        VerdictStatus::Flagged | VerdictStatus::Fail => {
            let n = report
                .public_findings
                .iter()
                .filter(|f| f.is_actionable())
                .count()
                + report.failed_sealed_categories.len();
            format!("{n} finding(s) need attention")
        }
    };

    let mut s = String::new();
    let engines: Vec<String> = report.engines_run.iter().map(|e| e.to_string()).collect();
    let _ = writeln!(s, "**Engines run:** {}", engines.join(", "));
    if let Some(seed) = &report.seed {
        let _ = writeln!(s, "\n**Seed:** `{}`", seed.0.to_hex());
    }
    if let Some(reason) = &report.inconclusive_reason {
        let _ = writeln!(
            s,
            "\n**Inconclusive:** {reason}\n\nThis is never counted against the PR."
        );
    }
    if !report.public_findings.is_empty() {
        let _ = writeln!(s, "\n### Findings");
    }
    for f in &report.public_findings {
        let r = f.reproduction();
        let note = if f.explained_by_intent {
            " (explained by the declared intent; informational)"
        } else {
            ""
        };
        let _ = writeln!(s, "\n#### [{}] {}: {}{note}", f.engine, f.category, f.title);
        if let Some(t) = &f.target {
            let _ = writeln!(s, "Target: `{t}`");
        }
        let _ = writeln!(
            s,
            "\n```\ninput:    {}\nexpected: {}\nobserved: {}\n```\nTranscript: `{}`",
            show_bytes(r.input()),
            show_bytes(r.expected()),
            show_bytes(r.observed()),
            r.transcript()
        );
    }
    if !report.failed_sealed_categories.is_empty() {
        let _ = writeln!(s, "\n### Sealed challenges");
        for c in &report.failed_sealed_categories {
            let _ = writeln!(s, "- Failed a sealed challenge of category `{c}`.");
        }
        let _ = writeln!(
            s,
            "\nSealed challenge inputs are withheld by design; the maintainer can see them."
        );
    }
    if let Some(r) = receipt {
        let _ = write!(
            s,
            "\n---\nSigned receipt `{}` (log index {})",
            r.id, r.log_index
        );
        if let Some(url) = &r.url {
            let _ = write!(s, ": {url}");
        }
        s.push('\n');
    }
    if s.len() > MAX_SUMMARY {
        let mut cut = MAX_SUMMARY;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("\n\n… (truncated)");
    }
    (title, s)
}

pub fn check_run(
    report: &ContributorReport,
    mode: EnforcementMode,
    head_sha: CommitSha,
    receipt: Option<&ReceiptRef>,
) -> CheckRun {
    let (title, summary) = render(report, receipt);
    CheckRun {
        name: CHECK_NAME.to_string(),
        head_sha,
        conclusion: conclusion(report.status, mode),
        title,
        summary,
        details_url: receipt.and_then(|r| r.url.clone()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rebut_core::*;

    pub fn finding(visibility: Visibility, secret: &[u8], explained: bool) -> Finding {
        let result = ExecutionResult {
            request_id: uuid::Uuid::nil(),
            outcomes: vec![StepOutcome {
                step_index: 0,
                exit_code: Some(101),
                timed_out: false,
                stdout: secret.to_vec(),
                stderr: secret.to_vec(),
                duration_ms: 1,
            }],
            transcript: Digest::of(b"t"),
            environment: Digest::of(b"env"),
        };
        let repro =
            Reproduction::confirm(&result, 0, secret.to_vec(), b"exit:Some(0)\n".to_vec()).unwrap();
        Finding::new(
            EngineKind::Challenges,
            "integer-overflow",
            format!("title {}", String::from_utf8_lossy(secret)),
            visibility,
            Some("lib::parse".into()),
            explained,
            repro,
        )
    }

    #[test]
    fn conclusion_mapping() {
        use EnforcementMode::*;
        use VerdictStatus::*;
        assert_eq!(conclusion(Pass, Mark), Conclusion::Success);
        assert_eq!(conclusion(Pass, Block), Conclusion::Success);
        assert_eq!(conclusion(Flagged, Mark), Conclusion::Neutral);
        assert_eq!(conclusion(Flagged, Block), Conclusion::Neutral);
        assert_eq!(conclusion(Fail, Block), Conclusion::Failure);
        assert_eq!(conclusion(Fail, Mark), Conclusion::Neutral);
        assert_eq!(conclusion(Inconclusive, Mark), Conclusion::Neutral);
        assert_eq!(conclusion(Inconclusive, Block), Conclusion::Neutral);
    }

    #[test]
    fn rendering_never_contains_sealed_bytes() {
        let pr = crate::queue::tests::pr(3, 'b');
        for mode in [EnforcementMode::Mark, EnforcementMode::Block] {
            let verdict = Verdict {
                pr: pr.clone(),
                seed: Some(Seed(Digest::of(b"s"))),
                engines_run: vec![EngineKind::Challenges, EngineKind::Differential],
                findings: vec![
                    finding(Visibility::Sealed, b"SEALED-SECRET-42", false),
                    finding(Visibility::Public, b"public-input-7", false),
                ],
                inconclusive_reason: None,
                mode,
            };
            let run = check_run(&verdict.for_contributor(), mode, pr.head_sha.clone(), None);
            assert!(!run.summary.contains("SEALED-SECRET"), "{}", run.summary);
            assert!(!run.title.contains("SEALED-SECRET"));
            assert!(run
                .summary
                .contains("Failed a sealed challenge of category `integer-overflow`"));
            assert!(run.summary.contains("public-input-7"));
            assert_eq!(run.title, "2 finding(s) need attention");
        }
    }

    #[test]
    fn contributor_text_cannot_escape_code_block() {
        assert!(!show_bytes(b"a```b").contains("```"));
        assert!(show_bytes(&[b'x'; 1000]).ends_with('…'));
    }
}
