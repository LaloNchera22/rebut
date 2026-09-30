//! The in-toto Statement v1 carried by a receipt.

use std::collections::BTreeMap;

use rebut_core::{
    Digest, DrandBeacon, EnforcementMode, EngineKind, Verdict, VerdictStatus, Visibility,
};
use serde::{Deserialize, Serialize};

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// Placeholder domain until the project has a permanent one.
pub const PREDICATE_TYPE: &str = "https://rebut.dev/verification/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub type_: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: VerificationPredicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationPredicate {
    pub status: VerdictStatus,
    pub mode: EnforcementMode,
    pub repo: String,
    pub pr_number: u64,
    pub base_commit: String,
    pub engines_run: Vec<EngineKind>,
    pub seed: Option<SeedRecord>,
    pub findings: Vec<FindingRecord>,
    pub inconclusive_reason: Option<String>,
    pub policy_digest: Digest,
    /// Digests of every microVM environment (rootfs/kernel/snapshot) used.
    pub environment_digests: Vec<Digest>,
    pub rebut_version: String,
}

/// Everything needed to recompute the seed (ADR-7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedRecord {
    pub value: Digest,
    pub generator_version: String,
    pub drand: Option<DrandBeacon>,
}

/// A finding reduced to what is safe to publish. Deliberately has no field
/// that could carry a sealed input, output or title.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingRecord {
    pub engine: EngineKind,
    pub category: String,
    pub visibility: Visibility,
    pub target: Option<String>,
    pub explained_by_intent: bool,
    pub transcript: Digest,
}

/// Facts about the run that are not part of [`Verdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptContext {
    pub policy_digest: Digest,
    pub environment_digests: Vec<Digest>,
    pub beacon: Option<DrandBeacon>,
    pub generator_version: String,
    pub rebut_version: String,
}

pub fn build_statement(verdict: &Verdict, ctx: &ReceiptContext) -> Statement {
    let pr = &verdict.pr;
    let repo_url = if pr.base_clone_url.is_empty() {
        pr.repo.to_string()
    } else {
        pr.base_clone_url.clone()
    };
    let mut environment_digests = ctx.environment_digests.clone();
    environment_digests.sort();
    environment_digests.dedup();

    Statement {
        type_: STATEMENT_TYPE.to_string(),
        subject: vec![Subject {
            name: format!("git+{repo_url}@{}", pr.head_sha),
            digest: BTreeMap::from([("gitCommit".to_string(), pr.head_sha.to_string())]),
        }],
        predicate_type: PREDICATE_TYPE.to_string(),
        predicate: VerificationPredicate {
            status: verdict.status(),
            mode: verdict.mode,
            repo: pr.repo.to_string(),
            pr_number: pr.number,
            base_commit: pr.base_sha.to_string(),
            engines_run: verdict.engines_run.clone(),
            seed: verdict.seed.map(|s| SeedRecord {
                value: s.0,
                generator_version: ctx.generator_version.clone(),
                drand: ctx.beacon.clone(),
            }),
            findings: verdict
                .findings
                .iter()
                .map(|f| FindingRecord {
                    engine: f.engine,
                    category: f.category.clone(),
                    visibility: f.visibility,
                    target: f.target.clone(),
                    explained_by_intent: f.explained_by_intent,
                    transcript: f.reproduction().transcript(),
                })
                .collect(),
            inconclusive_reason: verdict.inconclusive_reason.clone(),
            policy_digest: ctx.policy_digest,
            environment_digests,
            rebut_version: ctx.rebut_version.clone(),
        },
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rebut_core::*;

    pub fn sample_verdict(secret: &[u8]) -> Verdict {
        let result = ExecutionResult {
            request_id: uuid::Uuid::nil(),
            outcomes: vec![StepOutcome {
                step_index: 0,
                exit_code: Some(101),
                timed_out: false,
                stdout: secret.to_vec(),
                stderr: secret.to_vec(),
                duration_ms: 3,
            }],
            transcript: Digest::of(b"transcript"),
            environment: Digest::of(b"env"),
        };
        let repro = Reproduction::confirm(&result, 0, secret.to_vec(), b"ok".to_vec()).unwrap();
        let sha = CommitSha::new("c".repeat(40)).unwrap();
        Verdict {
            pr: PullRequest {
                repo: RepoId {
                    owner: "acme".into(),
                    name: "lib".into(),
                },
                number: 7,
                base_sha: CommitSha::new("a".repeat(40)).unwrap(),
                head_sha: sha.clone(),
                head_clone_url: "https://github.com/fork/lib.git".into(),
                base_clone_url: "https://github.com/acme/lib.git".into(),
                author: "mallory".into(),
                body: String::new(),
            },
            seed: Some(Seed(Digest::of(b"seed"))),
            engines_run: vec![EngineKind::Challenges],
            findings: vec![Finding::new(
                EngineKind::Challenges,
                "integer-overflow",
                "sealed title SECRET",
                Visibility::Sealed,
                Some("lib::parse".into()),
                false,
                repro,
            )],
            inconclusive_reason: None,
            mode: EnforcementMode::Mark,
        }
    }

    pub fn sample_ctx() -> ReceiptContext {
        ReceiptContext {
            policy_digest: Digest::of(b"policy"),
            environment_digests: vec![Digest::of(b"env"), Digest::of(b"env")],
            beacon: Some(DrandBeacon {
                chain_hash: "52db9ba7".into(),
                round: 42,
                randomness: "ab".into(),
                signature: "cd".into(),
            }),
            generator_version: GENERATOR_VERSION.into(),
            rebut_version: "0.1.0".into(),
        }
    }

    #[test]
    fn statement_shape_and_no_sealed_bytes() {
        let st = build_statement(&sample_verdict(b"SECRET-INPUT"), &sample_ctx());
        let json = serde_json::to_value(&st).unwrap();
        assert_eq!(json["_type"], STATEMENT_TYPE);
        assert_eq!(json["predicateType"], PREDICATE_TYPE);
        let sha = "c".repeat(40);
        assert_eq!(
            json["subject"][0]["name"],
            format!("git+https://github.com/acme/lib.git@{sha}")
        );
        assert_eq!(json["subject"][0]["digest"]["gitCommit"], sha);
        assert_eq!(json["predicate"]["status"], "flagged");
        assert_eq!(json["predicate"]["seed"]["drand"]["round"], 42);
        assert_eq!(
            json["predicate"]["environment_digests"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let text = json.to_string();
        assert!(!text.contains("SECRET"));
    }
}
