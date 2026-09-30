//! Transparency log for receipts.
//!
//! Every entry carries `body`, the base64 of the exact bytes that were hashed
//! into the leaf, so an auditor can recompute the leaf hash, check the
//! inclusion proof against the signed tree head, and decode the envelope.

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use verifier_core::Digest;

use crate::merkle::{leaf_hash, verify_inclusion, MerkleTree};
use crate::{key_id, Envelope, Signer};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Index of the leaf in the tree the proof is for (for sharded logs such
    /// as Rekor this may differ from the global [`LogEntry::index`]).
    pub leaf_index: u64,
    pub tree_size: u64,
    pub hashes: Vec<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root_hash: Digest,
    /// Unix seconds.
    pub timestamp: i64,
    pub key_id: String,
    /// Base64 signature over [`SignedTreeHead::signed_message`] for
    /// [`InMemoryLog`]; the signed entry timestamp for Rekor.
    pub signature: String,
    /// Rekor's signed checkpoint note, when the log provides one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<String>,
}

impl SignedTreeHead {
    pub fn signed_message(tree_size: u64, root: &Digest, timestamp: i64) -> Vec<u8> {
        format!(
            "rebut-log/v1\n{tree_size}\n{}\n{timestamp}\n",
            root.to_hex()
        )
        .into_bytes()
    }

    /// Verify a tree head produced by [`InMemoryLog`].
    pub fn verify(&self, key: &VerifyingKey) -> anyhow::Result<()> {
        if self.key_id != key_id(key) {
            bail!("tree head signed by a different key");
        }
        let sig = Signature::from_slice(&B64.decode(&self.signature)?)?;
        let msg = Self::signed_message(self.tree_size, &self.root_hash, self.timestamp);
        key.verify(&msg, &sig).context("bad tree head signature")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub index: u64,
    pub leaf_hash: Digest,
    /// Base64 of the leaf bytes.
    pub body: String,
    pub inclusion_proof: InclusionProof,
    pub signed_tree_head: SignedTreeHead,
}

impl LogEntry {
    /// Checks that `body` hashes to `leaf_hash` and that the leaf is included
    /// under the tree head's root. Does not check the tree head signature.
    pub fn verify_inclusion(&self) -> anyhow::Result<()> {
        let body = B64.decode(&self.body).context("body is not base64")?;
        if leaf_hash(&body) != self.leaf_hash {
            bail!("leaf hash does not match body");
        }
        let p = &self.inclusion_proof;
        if p.tree_size != self.signed_tree_head.tree_size {
            bail!("proof and tree head are for different tree sizes");
        }
        if !verify_inclusion(
            &self.leaf_hash,
            p.leaf_index,
            p.tree_size,
            &p.hashes,
            &self.signed_tree_head.root_hash,
        ) {
            bail!("inclusion proof does not verify");
        }
        Ok(())
    }
}

#[async_trait::async_trait]
pub trait TransparencyLog: Send + Sync {
    async fn append(&self, envelope: &Envelope) -> anyhow::Result<LogEntry>;
    /// The entry with a proof against the current tree head.
    async fn get(&self, index: u64) -> anyhow::Result<Option<LogEntry>>;
}

/// Append-only RFC 6962 log held in memory. Leaves are the JSON encoding of
/// the envelope; tree heads are signed by the operator's [`Signer`].
pub struct InMemoryLog {
    signer: Arc<dyn Signer>,
    state: Mutex<(MerkleTree, Vec<Vec<u8>>)>,
}

impl InMemoryLog {
    pub fn new(signer: Arc<dyn Signer>) -> Self {
        InMemoryLog {
            signer,
            state: Mutex::new((MerkleTree::new(), Vec::new())),
        }
    }

    async fn entry(&self, index: u64) -> anyhow::Result<Option<LogEntry>> {
        let (body, leaf, proof, size, root) = {
            let state = self.state.lock().expect("log lock poisoned");
            let (tree, bodies) = &*state;
            let Some(leaf) = tree.leaf(index) else {
                return Ok(None);
            };
            let size = tree.size();
            let proof = tree.inclusion_proof(index, size).expect("index below size");
            (
                bodies[index as usize].clone(),
                leaf,
                proof,
                size,
                tree.root(),
            )
        };
        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
        let sig = self
            .signer
            .sign(&SignedTreeHead::signed_message(size, &root, timestamp))
            .await?;
        Ok(Some(LogEntry {
            index,
            leaf_hash: leaf,
            body: B64.encode(body),
            inclusion_proof: InclusionProof {
                leaf_index: index,
                tree_size: size,
                hashes: proof,
            },
            signed_tree_head: SignedTreeHead {
                tree_size: size,
                root_hash: root,
                timestamp,
                key_id: self.signer.key_id(),
                signature: B64.encode(sig),
                checkpoint: None,
            },
        }))
    }
}

#[async_trait::async_trait]
impl TransparencyLog for InMemoryLog {
    async fn append(&self, envelope: &Envelope) -> anyhow::Result<LogEntry> {
        let body = serde_json::to_vec(envelope)?;
        let index = {
            let mut state = self.state.lock().expect("log lock poisoned");
            let index = state.0.push(&body);
            state.1.push(body);
            index
        };
        self.entry(index)
            .await?
            .ok_or_else(|| anyhow!("entry {index} vanished"))
    }

    async fn get(&self, index: u64) -> anyhow::Result<Option<LogEntry>> {
        self.entry(index).await
    }
}

/// Thin client for Sigstore Rekor's `dsse` entry type.
///
/// **Untested against a live Rekor instance.** It follows the documented
/// `/api/v1/log/entries` API; note that Rekor's leaf is its own canonical
/// entry body (which stores hashes of the envelope), not the envelope itself.
pub struct RekorLog {
    base_url: String,
    public_key: VerifyingKey,
    http: reqwest::Client,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RekorEntry {
    body: String,
    #[serde(rename = "logID")]
    log_id: String,
    log_index: u64,
    integrated_time: i64,
    verification: RekorVerification,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RekorVerification {
    inclusion_proof: RekorProof,
    #[serde(default)]
    signed_entry_timestamp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RekorProof {
    log_index: u64,
    tree_size: u64,
    root_hash: String,
    hashes: Vec<String>,
    #[serde(default)]
    checkpoint: Option<String>,
}

impl RekorLog {
    pub fn new(base_url: impl Into<String>, public_key: VerifyingKey) -> Self {
        RekorLog {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            public_key,
            http: reqwest::Client::new(),
        }
    }

    /// PEM (SubjectPublicKeyInfo) of the ed25519 key, as Rekor expects.
    fn public_key_pem(&self) -> String {
        // DER prefix of an Ed25519 SPKI: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }.
        let mut der = hex::decode("302a300506032b6570032100").expect("static hex");
        der.extend_from_slice(self.public_key.as_bytes());
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            B64.encode(der)
        )
    }

    fn to_entry(resp: serde_json::Value) -> anyhow::Result<LogEntry> {
        let map: std::collections::BTreeMap<String, RekorEntry> =
            serde_json::from_value(resp).context("unexpected Rekor response")?;
        let (_, e) = map
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("empty Rekor response"))?;
        let body = B64.decode(&e.body).context("Rekor body is not base64")?;
        let p = e.verification.inclusion_proof;
        let hashes = p
            .hashes
            .into_iter()
            .map(Digest::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("bad proof hash: {e}"))?;
        Ok(LogEntry {
            index: e.log_index,
            leaf_hash: leaf_hash(&body),
            body: e.body,
            inclusion_proof: InclusionProof {
                leaf_index: p.log_index,
                tree_size: p.tree_size,
                hashes,
            },
            signed_tree_head: SignedTreeHead {
                tree_size: p.tree_size,
                root_hash: Digest::try_from(p.root_hash).map_err(|e| anyhow!(e))?,
                timestamp: e.integrated_time,
                key_id: e.log_id,
                signature: e.verification.signed_entry_timestamp,
                checkpoint: p.checkpoint,
            },
        })
    }
}

#[async_trait::async_trait]
impl TransparencyLog for RekorLog {
    async fn append(&self, envelope: &Envelope) -> anyhow::Result<LogEntry> {
        let request = serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": { "proposedContent": {
                "envelope": serde_json::to_string(envelope)?,
                "verifiers": [B64.encode(self.public_key_pem())],
            }},
        });
        let resp = self
            .http
            .post(format!("{}/api/v1/log/entries", self.base_url))
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Self::to_entry(resp)
    }

    async fn get(&self, index: u64) -> anyhow::Result<Option<LogEntry>> {
        let resp = self
            .http
            .get(format!("{}/api/v1/log/entries", self.base_url))
            .query(&[("logIndex", index)])
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::to_entry(resp.error_for_status()?.json().await?).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ed25519Signer;

    async fn envelope(signer: &dyn Signer, n: u8) -> Envelope {
        Envelope::sign(crate::PAYLOAD_TYPE_IN_TOTO, &[b'{', n, b'}'], signer)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn in_memory_log_append_and_prove() {
        let signer = Arc::new(Ed25519Signer::generate());
        let log = InMemoryLog::new(signer.clone());
        let mut envs = Vec::new();
        for i in 0..5u8 {
            let env = envelope(signer.as_ref(), i).await;
            let entry = log.append(&env).await.unwrap();
            assert_eq!(entry.index, i as u64);
            entry.verify_inclusion().unwrap();
            entry.signed_tree_head.verify(&signer.public_key()).unwrap();
            envs.push(env);
        }
        // Old entries are provable against the grown tree.
        for (i, env) in envs.iter().enumerate() {
            let entry = log.get(i as u64).await.unwrap().unwrap();
            assert_eq!(entry.signed_tree_head.tree_size, 5);
            entry.verify_inclusion().unwrap();
            let decoded: Envelope =
                serde_json::from_slice(&B64.decode(&entry.body).unwrap()).unwrap();
            assert_eq!(&decoded, env);
        }
        assert!(log.get(5).await.unwrap().is_none());

        // A forged body or tree head is rejected.
        let mut entry = log.get(2).await.unwrap().unwrap();
        entry.body = B64.encode(b"forged");
        assert!(entry.verify_inclusion().is_err());
        let mut entry = log.get(2).await.unwrap().unwrap();
        entry.signed_tree_head.tree_size += 1;
        assert!(entry.signed_tree_head.verify(&signer.public_key()).is_err());
    }

    #[test]
    fn rekor_response_parsing() {
        let body = B64.encode(b"{\"kind\":\"dsse\"}");
        let leaf = leaf_hash(b"{\"kind\":\"dsse\"}");
        let resp = serde_json::json!({ "24296fb2": {
            "body": body, "integratedTime": 1700000000, "logID": "c0d23d6a", "logIndex": 99,
            "verification": {
                "inclusionProof": {
                    "logIndex": 3, "treeSize": 1, "rootHash": leaf.to_hex(),
                    "hashes": [], "checkpoint": "rekor.sigstore.dev\n1\n..."
                },
                "signedEntryTimestamp": "c2V0"
            }
        }});
        let entry = RekorLog::to_entry(resp).unwrap();
        assert_eq!(entry.index, 99);
        assert_eq!(entry.inclusion_proof.leaf_index, 3);
        assert_eq!(entry.leaf_hash, leaf);
    }

    #[test]
    fn rekor_pem_shape() {
        let log = RekorLog::new("http://x/", Ed25519Signer::generate().public_key());
        assert_eq!(log.base_url, "http://x");
        let pem = log.public_key_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA"));
    }
}
