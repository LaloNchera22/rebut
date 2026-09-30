//! DSSE envelopes (<https://github.com/secure-systems-lab/dsse/blob/master/protocol.md>)
//! with ed25519 signatures.

use std::path::Path;

use anyhow::{anyhow, bail, Context};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{SignerIdentity, Statement};

pub const PAYLOAD_TYPE_IN_TOTO: &str = "application/vnd.in-toto+json";

/// Pre-Authentication Encoding:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, lengths as ASCII decimal.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload_type.len() + payload.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Key id: lowercase hex SHA-256 of the raw 32-byte ed25519 public key.
pub fn key_id(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

/// Produces signatures over PAE bytes. Async so that phase 2 can implement it
/// with a remote enclave (TEE) without changing callers.
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    fn public_key(&self) -> VerifyingKey;
    fn key_id(&self) -> String {
        key_id(&self.public_key())
    }
    /// What kind of key this is; recorded in every statement it signs.
    fn identity(&self) -> SignerIdentity {
        SignerIdentity::OperatorKey
    }
    async fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// Phase-1 signer: an ed25519 key held by the operator.
pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    pub fn new(key: SigningKey) -> Self {
        Ed25519Signer { key }
    }

    pub fn generate() -> Self {
        Self::new(SigningKey::generate(&mut rand::rngs::OsRng))
    }

    /// Load a 32-byte seed, either raw or as 64 hex characters.
    pub fn from_key_file(path: &Path) -> anyhow::Result<Self> {
        let bytes =
            std::fs::read(path).with_context(|| format!("reading key {}", path.display()))?;
        let seed: [u8; 32] = match bytes.len() {
            32 => bytes.try_into().expect("length checked"),
            _ => hex::decode(String::from_utf8_lossy(&bytes).trim())
                .context("key file is neither 32 raw bytes nor hex")?
                .try_into()
                .map_err(|_| anyhow!("key seed must be 32 bytes"))?,
        };
        Ok(Self::new(SigningKey::from_bytes(&seed)))
    }
}

#[async_trait::async_trait]
impl Signer for Ed25519Signer {
    fn public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
    async fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.key.sign(message).to_bytes().to_vec())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeSignature {
    pub keyid: String,
    /// Base64 (standard, padded) signature over the PAE.
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Base64 (standard, padded) payload.
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<EnvelopeSignature>,
}

impl Envelope {
    pub async fn sign(
        payload_type: &str,
        payload: &[u8],
        signer: &dyn Signer,
    ) -> anyhow::Result<Envelope> {
        let sig = signer.sign(&pae(payload_type, payload)).await?;
        Ok(Envelope {
            payload: B64.encode(payload),
            payload_type: payload_type.to_string(),
            signatures: vec![EnvelopeSignature {
                keyid: signer.key_id(),
                sig: B64.encode(sig),
            }],
        })
    }

    /// Signs `st` with its `predicate.signer` set to `signer.identity()`
    /// (whatever `st` carried is replaced).
    pub async fn sign_statement(st: &Statement, signer: &dyn Signer) -> anyhow::Result<Envelope> {
        let mut st = st.clone();
        st.predicate.signer = signer.identity();
        let payload = serde_json::to_vec(&st)?;
        Self::sign(PAYLOAD_TYPE_IN_TOTO, &payload, signer).await
    }

    pub fn payload_bytes(&self) -> anyhow::Result<Vec<u8>> {
        B64.decode(&self.payload).context("payload is not base64")
    }
}

/// Verify that `env` carries a valid signature by `key` over an in-toto
/// payload, and return the decoded statement. Signatures by other keys are
/// ignored; at least one must come from `key`.
///
/// This trusts `key` as given and does **not** evaluate the statement's
/// [`SignerIdentity`] or attestation: a `tee` receipt checked this way proves
/// no more than an operator-key one. Use
/// [`verify_receipt_with_policy`](crate::verify_receipt_with_policy) for that.
pub fn verify_envelope(env: &Envelope, key: &VerifyingKey) -> anyhow::Result<Statement> {
    if env.payload_type != PAYLOAD_TYPE_IN_TOTO {
        bail!("unexpected payloadType {:?}", env.payload_type);
    }
    let payload = env.payload_bytes()?;
    let message = pae(&env.payload_type, &payload);
    let kid = key_id(key);
    let verified = env.signatures.iter().filter(|s| s.keyid == kid).any(|s| {
        B64.decode(&s.sig)
            .ok()
            .and_then(|b| Signature::from_slice(&b).ok())
            .is_some_and(|sig| key.verify(&message, &sig).is_ok())
    });
    if !verified {
        bail!("no valid signature for key {kid}");
    }
    serde_json::from_slice(&payload).context("payload is not an in-toto statement")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statement::tests::{sample_ctx, sample_verdict};
    use crate::{build_statement, sign_verdict};

    #[test]
    fn pae_known_answer() {
        // Example from the DSSE protocol specification.
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
        assert_eq!(pae("", b""), b"DSSEv1 0  0 ".to_vec());
    }

    #[tokio::test]
    async fn sign_verify_roundtrip() {
        let signer = Ed25519Signer::generate();
        let verdict = sample_verdict(b"x");
        let env = sign_verdict(&verdict, &sample_ctx(), &signer)
            .await
            .unwrap();
        assert_eq!(env.payload_type, PAYLOAD_TYPE_IN_TOTO);
        assert_eq!(env.signatures[0].keyid, signer.key_id());
        assert_eq!(env.signatures[0].keyid.len(), 64);
        let st = verify_envelope(&env, &signer.public_key()).unwrap();
        assert_eq!(st, build_statement(&verdict, &sample_ctx()));
    }

    #[tokio::test]
    async fn tampering_is_detected() {
        let signer = Ed25519Signer::generate();
        let env = sign_verdict(&sample_verdict(b"x"), &sample_ctx(), &signer)
            .await
            .unwrap();

        // Payload flipped from flagged to pass.
        let mut tampered = env.clone();
        let text = String::from_utf8(env.payload_bytes().unwrap()).unwrap();
        tampered.payload = B64.encode(text.replace("\"flagged\"", "\"pass\""));
        assert_ne!(tampered.payload, env.payload);
        assert!(verify_envelope(&tampered, &signer.public_key()).is_err());

        // Payload type changed: PAE differs, so the signature breaks too.
        let mut tampered = env.clone();
        tampered.payload_type = "application/json".into();
        assert!(verify_envelope(&tampered, &signer.public_key()).is_err());

        // Correct envelope, wrong key.
        let other = Ed25519Signer::generate();
        assert!(verify_envelope(&env, &other.public_key()).is_err());

        // Signature bytes corrupted.
        let mut tampered = env.clone();
        let mut sig = B64.decode(&tampered.signatures[0].sig).unwrap();
        sig[0] ^= 1;
        tampered.signatures[0].sig = B64.encode(sig);
        assert!(verify_envelope(&tampered, &signer.public_key()).is_err());
    }

    #[test]
    fn key_file_formats() {
        let dir = std::env::temp_dir().join(format!("receipts-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = dir.join("raw");
        let hexf = dir.join("hex");
        std::fs::write(&raw, [7u8; 32]).unwrap();
        std::fs::write(&hexf, format!("{}\n", hex::encode([7u8; 32]))).unwrap();
        let a = Ed25519Signer::from_key_file(&raw).unwrap();
        let b = Ed25519Signer::from_key_file(&hexf).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
