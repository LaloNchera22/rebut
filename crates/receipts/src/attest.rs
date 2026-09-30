//! TEE attestations that bind a receipt signing key to a measured signer build
//! (ADR-5, phase 2).
//!
//! An [`Attestation`] is a platform report whose report data (SNP
//! `REPORT_DATA`, Nitro `user_data`, TDX `REPORTDATA`) starts with
//! [`key_binding`]: SHA-256 of a domain-separated message holding the ed25519
//! public key. Verifying it takes two steps:
//!
//! 1. [`AttestationVerifier::verify_report`] (platform-specific) checks the
//!    report is genuine and returns its measurement and report data;
//! 2. [`AttestationVerifier::verify`] (platform-neutral, provided) checks the
//!    report data binds the claimed key and returns an [`AttestedKey`].
//!
//! Whether the measurement is one you expect is policy, not attestation; see
//! [`crate::policy`].
//!
//! Implemented platforms:
//!
//! - [`SoftwareAttestation`]: **offers no security.** The "platform" is an
//!   ed25519 key held by whoever runs the signer. For tests and development.
//! - AMD SEV-SNP ([`crate::snp`]): report parsing and policy checks only.
//!   The report signature and VCEK certificate chain are **not verified**, so
//!   its verifier always returns [`AttestationError::Unimplemented`].

use std::fmt;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::key_id;

/// Platform id of [`SoftwareAttestation`]. Offers no security.
pub const PLATFORM_SOFTWARE_INSECURE: &str = "software-insecure";
/// Platform id of AMD SEV-SNP attestation reports.
pub const PLATFORM_AMD_SEV_SNP: &str = "amd-sev-snp";

/// Domain separator for [`key_binding`].
pub const KEY_BINDING_DOMAIN: &[u8] = b"rebut/receipt-signer-key/v1\0ed25519\0";

/// The 32 bytes a signer puts at the start of its report data:
/// `SHA-256(KEY_BINDING_DOMAIN || public_key)`. Platforms with a longer report
/// data field (SNP: 64 bytes) zero-pad it.
pub fn key_binding(key: &VerifyingKey) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KEY_BINDING_DOMAIN);
    h.update(key.as_bytes());
    h.finalize().into()
}

/// A launch measurement of the signer build (SNP `MEASUREMENT`, Nitro PCR0,
/// TDX `MRTD`). Serialized as lowercase hex.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Measurement(pub Vec<u8>);

impl Measurement {
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        hex::decode(s.trim()).map(Measurement)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl fmt::Debug for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Measurement({})", self.to_hex())
    }
}

impl fmt::Display for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Measurement {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Measurement {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Measurement::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Evidence, carried in the receipt, that `public_key` was generated inside a
/// TEE running a particular signer build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    /// Platform id, e.g. [`PLATFORM_AMD_SEV_SNP`]. A string rather than an
    /// enum so that receipts from new platforms still decode everywhere.
    pub platform: String,
    /// Lowercase hex of the raw 32-byte ed25519 public key the report binds.
    pub public_key: String,
    /// Base64 (standard, padded) of the platform's raw report.
    pub report: String,
}

impl Attestation {
    pub fn verifying_key(&self) -> Result<VerifyingKey, AttestationError> {
        let bytes: [u8; 32] = hex::decode(&self.public_key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| AttestationError::Malformed("public_key is not 32 hex bytes".into()))?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|_| AttestationError::Malformed("public_key is not an ed25519 point".into()))
    }

    pub fn report_bytes(&self) -> Result<Vec<u8>, AttestationError> {
        B64.decode(&self.report)
            .map_err(|_| AttestationError::Malformed("report is not base64".into()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("attestation is for platform {found:?}, verifier handles {expected:?}")]
    WrongPlatform { expected: String, found: String },
    #[error("malformed attestation: {0}")]
    Malformed(String),
    #[error("attestation report signature does not verify")]
    BadSignature,
    #[error("attestation report data does not bind the claimed public key")]
    KeyNotBound,
    #[error("attestation rejected: {0}")]
    Rejected(String),
    /// The platform verifier is incomplete and refuses to vouch for anything.
    #[error("attestation verification not implemented: {0}")]
    Unimplemented(&'static str),
}

/// What a platform verifier learned from a report it authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportClaims {
    pub measurement: Measurement,
    /// The report's full report-data field.
    pub report_data: Vec<u8>,
}

/// A public key proven to live in a TEE running `measurement`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedKey {
    pub platform: String,
    pub measurement: Measurement,
    pub public_key: VerifyingKey,
    pub key_id: String,
}

/// Produces platform reports inside the TEE. Async because real providers
/// talk to the platform firmware (SNP `/dev/sev-guest`, Nitro NSM).
#[async_trait::async_trait]
pub trait AttestationProvider: Send + Sync {
    fn platform(&self) -> &str;
    /// A raw report whose report data starts with `report_data`.
    async fn report(&self, report_data: [u8; 32]) -> anyhow::Result<Vec<u8>>;
}

/// Attests that `key` belongs to the signer running inside `provider`'s TEE.
pub async fn attest_key(
    provider: &dyn AttestationProvider,
    key: &VerifyingKey,
) -> anyhow::Result<Attestation> {
    let report = provider.report(key_binding(key)).await?;
    Ok(Attestation {
        platform: provider.platform().to_string(),
        public_key: hex::encode(key.as_bytes()),
        report: B64.encode(report),
    })
}

/// Checks reports of one platform.
pub trait AttestationVerifier: Send + Sync {
    fn platform(&self) -> &str;

    /// Platform-specific: authenticate `report` (signature, certificate chain
    /// to the vendor root, debug/TCB policy) and return its claims. Must never
    /// return `Ok` for a report it has not authenticated.
    fn verify_report(&self, report: &[u8]) -> Result<ReportClaims, AttestationError>;

    /// Platform-neutral: authenticate the report, then check that its report
    /// data is [`key_binding`] of the attestation's public key (zero-padded).
    fn verify(&self, att: &Attestation) -> Result<AttestedKey, AttestationError> {
        if att.platform != self.platform() {
            return Err(AttestationError::WrongPlatform {
                expected: self.platform().to_string(),
                found: att.platform.clone(),
            });
        }
        let public_key = att.verifying_key()?;
        let claims = self.verify_report(&att.report_bytes()?)?;
        let rd = &claims.report_data;
        let bound = rd.len() >= 32
            && rd[..32] == key_binding(&public_key)
            && rd[32..].iter().all(|b| *b == 0);
        if !bound {
            return Err(AttestationError::KeyNotBound);
        }
        Ok(AttestedKey {
            platform: att.platform.clone(),
            measurement: claims.measurement,
            key_id: key_id(&public_key),
            public_key,
        })
    }
}

/// **Offers no security.** A stand-in TEE for tests and development: the
/// "platform" is an ed25519 key, and the measurement is whatever the caller
/// says. Anyone holding the platform key can attest any key to any
/// measurement. A verifier accepts these only if it is handed a
/// [`SoftwareAttestationVerifier`] and allowlists a
/// [`PLATFORM_SOFTWARE_INSECURE`] build.
pub struct SoftwareAttestation {
    platform_key: SigningKey,
    measurement: Measurement,
}

#[derive(Serialize, Deserialize)]
struct SoftwareReport {
    measurement: Measurement,
    /// Hex.
    report_data: String,
    platform_key_id: String,
    /// Base64 ed25519 signature over [`SoftwareReport::signed_message`].
    signature: String,
}

impl SoftwareReport {
    fn signed_message(measurement: &Measurement, report_data: &str) -> Vec<u8> {
        format!("rebut-software-attestation/v1\n{measurement}\n{report_data}\n").into_bytes()
    }
}

impl SoftwareAttestation {
    pub fn new(platform_key: SigningKey, measurement: Measurement) -> Self {
        SoftwareAttestation {
            platform_key,
            measurement,
        }
    }

    /// The verifier for reports from this (insecure) platform.
    pub fn verifier(&self) -> SoftwareAttestationVerifier {
        SoftwareAttestationVerifier::new(self.platform_key.verifying_key())
    }
}

#[async_trait::async_trait]
impl AttestationProvider for SoftwareAttestation {
    fn platform(&self) -> &str {
        PLATFORM_SOFTWARE_INSECURE
    }

    async fn report(&self, report_data: [u8; 32]) -> anyhow::Result<Vec<u8>> {
        let report_data = hex::encode(report_data);
        let sig = self.platform_key.sign(&SoftwareReport::signed_message(
            &self.measurement,
            &report_data,
        ));
        Ok(serde_json::to_vec(&SoftwareReport {
            measurement: self.measurement.clone(),
            report_data,
            platform_key_id: key_id(&self.platform_key.verifying_key()),
            signature: B64.encode(sig.to_bytes()),
        })?)
    }
}

/// Verifies [`SoftwareAttestation`] reports against a dev platform key.
/// **Offers no security**; see [`SoftwareAttestation`].
pub struct SoftwareAttestationVerifier {
    platform_key: VerifyingKey,
}

impl SoftwareAttestationVerifier {
    pub fn new(platform_key: VerifyingKey) -> Self {
        SoftwareAttestationVerifier { platform_key }
    }
}

impl AttestationVerifier for SoftwareAttestationVerifier {
    fn platform(&self) -> &str {
        PLATFORM_SOFTWARE_INSECURE
    }

    fn verify_report(&self, report: &[u8]) -> Result<ReportClaims, AttestationError> {
        let r: SoftwareReport = serde_json::from_slice(report)
            .map_err(|e| AttestationError::Malformed(format!("software report: {e}")))?;
        if r.platform_key_id != key_id(&self.platform_key) {
            return Err(AttestationError::BadSignature);
        }
        let sig = B64
            .decode(&r.signature)
            .ok()
            .and_then(|b| Signature::from_slice(&b).ok())
            .ok_or(AttestationError::BadSignature)?;
        self.platform_key
            .verify(
                &SoftwareReport::signed_message(&r.measurement, &r.report_data),
                &sig,
            )
            .map_err(|_| AttestationError::BadSignature)?;
        let report_data = hex::decode(&r.report_data)
            .map_err(|_| AttestationError::Malformed("report_data is not hex".into()))?;
        Ok(ReportClaims {
            measurement: r.measurement,
            report_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform() -> SoftwareAttestation {
        SoftwareAttestation::new(
            SigningKey::from_bytes(&[1; 32]),
            Measurement(vec![0xaa; 48]),
        )
    }

    #[test]
    fn key_binding_is_domain_separated() {
        let key = SigningKey::from_bytes(&[2; 32]).verifying_key();
        assert_ne!(
            key_binding(&key).as_slice(),
            Sha256::digest(key.as_bytes()).as_slice()
        );
        let other = SigningKey::from_bytes(&[3; 32]).verifying_key();
        assert_ne!(key_binding(&key), key_binding(&other));
    }

    #[test]
    fn measurement_serializes_as_hex() {
        let m = Measurement(vec![0xab, 0x01]);
        assert_eq!(serde_json::to_string(&m).unwrap(), "\"ab01\"");
        assert_eq!(serde_json::from_str::<Measurement>("\"ab01\"").unwrap(), m);
        assert!(serde_json::from_str::<Measurement>("\"zz\"").is_err());
    }

    #[tokio::test]
    async fn software_attestation_roundtrip_and_tampering() {
        let p = platform();
        let key = SigningKey::from_bytes(&[2; 32]).verifying_key();
        let att = attest_key(&p, &key).await.unwrap();
        let got = p.verifier().verify(&att).unwrap();
        assert_eq!(got.public_key, key);
        assert_eq!(got.measurement, Measurement(vec![0xaa; 48]));
        assert_eq!(got.key_id, key_id(&key));

        // Claimed key swapped: the report binds the original key.
        let mut t = att.clone();
        t.public_key = hex::encode(SigningKey::from_bytes(&[3; 32]).verifying_key().as_bytes());
        assert!(matches!(
            p.verifier().verify(&t),
            Err(AttestationError::KeyNotBound)
        ));

        // Measurement edited inside the report: platform signature breaks.
        let mut report: serde_json::Value =
            serde_json::from_slice(&att.report_bytes().unwrap()).unwrap();
        report["measurement"] = serde_json::json!("bb".repeat(48));
        let mut t = att.clone();
        t.report = B64.encode(serde_json::to_vec(&report).unwrap());
        assert!(matches!(
            p.verifier().verify(&t),
            Err(AttestationError::BadSignature)
        ));

        // A different dev platform key.
        let other =
            SoftwareAttestationVerifier::new(SigningKey::from_bytes(&[9; 32]).verifying_key());
        assert!(other.verify(&att).is_err());

        // Wrong platform label.
        let mut t = att.clone();
        t.platform = PLATFORM_AMD_SEV_SNP.into();
        assert!(matches!(
            p.verifier().verify(&t),
            Err(AttestationError::WrongPlatform { .. })
        ));

        // Garbage.
        let mut t = att;
        t.report = B64.encode(b"not json");
        assert!(matches!(
            p.verifier().verify(&t),
            Err(AttestationError::Malformed(_))
        ));
    }
}
