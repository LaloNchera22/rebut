//! Independent auditing: seeds (ADR-7), public challenges and receipts (ADR-5).

use anyhow::{bail, Context};
use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use rebut_challenges::drand::{self, BeaconSource};
use rebut_challenges::spec;
use rebut_core::{CommitSha, DrandBeacon, Seed, GENERATOR_VERSION};
use rebut_differential::harness::encode_case;
use rebut_receipts::{verify_envelope, Envelope, LogEntry, Statement};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SeedInfo {
    pub commit: CommitSha,
    pub beacon: DrandBeacon,
    pub generator_version: String,
    pub seed: String,
}

/// Fetches drand `round` (or uses `beacon` when given, for offline audits),
/// checks it, and derives the seed exactly as the control plane does.
pub async fn derive_seed(
    commit: &CommitSha,
    round: u64,
    beacon: Option<DrandBeacon>,
    source: &dyn BeaconSource,
) -> anyhow::Result<SeedInfo> {
    let beacon = match beacon {
        Some(b) => b,
        None => source.round(round).await?,
    };
    if beacon.round != round {
        bail!("beacon is for round {}, expected {round}", beacon.round);
    }
    drand::verify_randomness(&beacon)?;
    let seed = Seed::derive(commit, &beacon, GENERATOR_VERSION);
    Ok(SeedInfo {
        commit: commit.clone(),
        beacon,
        generator_version: GENERATOR_VERSION.to_string(),
        seed: seed.0.to_hex(),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct RegeneratedChallenge {
    pub id: String,
    pub target: String,
    /// One harness stdin line per case, exactly as fed to the PR's code.
    pub cases: Vec<String>,
}

/// Regenerates the public challenges for a seed. Anyone holding the seed and
/// the base branch's `.rebut/challenges.toml` gets the same inputs.
pub fn regenerate_challenges(
    spec_toml: &str,
    seed: &Seed,
    max_cases: Option<usize>,
) -> anyhow::Result<Vec<RegeneratedChallenge>> {
    let challenges = spec::parse_public(spec_toml)?;
    Ok(challenges
        .iter()
        .map(|ch| {
            let n = max_cases.unwrap_or(ch.spec.cases as usize);
            RegeneratedChallenge {
                id: ch.spec.id.clone(),
                target: ch.spec.target.clone(),
                cases: spec::generate_cases(ch, seed, n)
                    .iter()
                    .map(|c| encode_case(c))
                    .collect(),
            }
        })
        .collect())
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptCheck {
    pub statement: Statement,
    /// Present when a log entry was supplied and it checks out.
    pub log_index: Option<u64>,
    pub trust_note: &'static str,
}

pub fn parse_public_key(s: &str) -> anyhow::Result<VerifyingKey> {
    let s = s.trim();
    let bytes = hex::decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .context("public key must be hex or base64")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}

/// Verifies the DSSE signature and, when given, that the log entry holds this
/// exact envelope under a correctly signed tree head.
pub fn verify_receipt(
    envelope: &Envelope,
    key: &VerifyingKey,
    entry: Option<&LogEntry>,
) -> anyhow::Result<ReceiptCheck> {
    let statement = verify_envelope(envelope, key)?;
    let log_index = match entry {
        None => None,
        Some(e) => {
            e.verify_inclusion()?;
            e.signed_tree_head.verify(key)?;
            let body = base64::engine::general_purpose::STANDARD.decode(&e.body)?;
            let logged: Envelope =
                serde_json::from_slice(&body).context("log entry body is not an envelope")?;
            if &logged != envelope {
                bail!("log entry {} holds a different envelope", e.index);
            }
            Some(e.index)
        }
    };
    Ok(ReceiptCheck {
        statement,
        log_index,
        trust_note: "Phase 1: receipts are signed by the operator's key; you are trusting the \
                     operator. Phase 2 moves the signer into a TEE (ADR-5).",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rebut_challenges::FixedBeacon;
    use rebut_receipts::{Ed25519Signer, InMemoryLog, Signer, TransparencyLog};
    use std::sync::Arc;

    const SPEC: &str = r#"
[[challenge]]
id = "parse"
target = "demo::parse"
cases = 5
args = [{ ty = "u32", min = 0, max = 100 }]
oracle = { kind = "no_panic" }
"#;

    #[test]
    fn regeneration_is_deterministic_and_seed_sensitive() {
        let s1 = Seed(rebut_core::Digest::of(b"1"));
        let s2 = Seed(rebut_core::Digest::of(b"2"));
        let a = regenerate_challenges(SPEC, &s1, None).unwrap();
        assert_eq!(a[0].cases.len(), 5);
        assert_eq!(
            a[0].cases,
            regenerate_challenges(SPEC, &s1, None).unwrap()[0].cases
        );
        assert_ne!(
            a[0].cases,
            regenerate_challenges(SPEC, &s2, None).unwrap()[0].cases
        );
    }

    #[tokio::test]
    async fn seed_matches_core_derivation() {
        use sha2::{Digest as _, Sha256};
        let signature = "ab".repeat(48);
        let beacon = DrandBeacon {
            chain_hash: "c".into(),
            round: 7,
            randomness: hex::encode(Sha256::digest(hex::decode(&signature).unwrap())),
            signature,
        };
        let commit = CommitSha::new("c".repeat(40)).unwrap();
        let src = FixedBeacon(beacon.clone());
        let info = derive_seed(&commit, 7, None, &src).await.unwrap();
        assert_eq!(
            info.seed,
            Seed::derive(&commit, &beacon, GENERATOR_VERSION).0.to_hex()
        );
        assert!(derive_seed(&commit, 8, Some(beacon), &src).await.is_err());
    }

    fn verdict() -> rebut_core::Verdict {
        let sha = CommitSha::new("d".repeat(40)).unwrap();
        rebut_core::Verdict {
            pr: rebut_core::PullRequest {
                repo: rebut_core::RepoId {
                    owner: "o".into(),
                    name: "r".into(),
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
            engines_run: vec![],
            findings: vec![],
            inconclusive_reason: None,
            mode: rebut_core::EnforcementMode::Mark,
        }
    }

    #[tokio::test]
    async fn receipt_and_log_entry_verify_and_tampering_fails() {
        let signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::generate());
        let ctx = rebut_receipts::ReceiptContext {
            policy_digest: rebut_core::Digest::of(b"policy"),
            environment_digests: vec![],
            beacon: None,
            generator_version: GENERATOR_VERSION.into(),
            rebut_version: "test".into(),
        };
        let env = rebut_receipts::sign_verdict(&verdict(), &ctx, signer.as_ref())
            .await
            .unwrap();
        let log = InMemoryLog::new(signer.clone());
        let entry = log.append(&env).await.unwrap();
        let key = parse_public_key(&hex::encode(signer.public_key().as_bytes())).unwrap();

        let check = verify_receipt(&env, &key, Some(&entry)).unwrap();
        assert_eq!(check.log_index, Some(0));

        // Flip the recorded mode from mark to block, keeping the signature.
        let b64 = base64::engine::general_purpose::STANDARD;
        let payload = String::from_utf8(b64.decode(&env.payload).unwrap()).unwrap();
        assert!(payload.contains("\"mark\""));
        let mut tampered = env.clone();
        tampered.payload = b64.encode(payload.replace("\"mark\"", "\"block\""));
        assert!(verify_receipt(&tampered, &key, None).is_err());
        let wrong = Ed25519Signer::generate().public_key();
        assert!(verify_receipt(&env, &wrong, None).is_err());
    }
}
