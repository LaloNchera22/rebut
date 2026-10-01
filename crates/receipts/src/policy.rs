//! Receipt verification against a rebut-supplied trust policy.
//!
//! [`verify_envelope`] answers "did this key sign it?". A
//! [`ReceiptPolicy`] answers "do I accept who signed it?":
//!
//! - an `operator-key` receipt must be signed by one of
//!   [`ReceiptPolicy::operator_keys`] (phase-1 behavior);
//! - a `tee` receipt must carry an attestation that a configured
//!   [`AttestationVerifier`] authenticates, whose measurement is in
//!   [`TeePolicy::allowed_builds`], and whose bound key signed the envelope.
//!
//! Leave `operator_keys` empty to require TEE-signed receipts.

use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use ed25519_dalek::VerifyingKey;

use crate::attest::{AttestationVerifier, Measurement, PLATFORM_SOFTWARE_INSECURE};
use crate::{key_id, verify_envelope, Envelope, SignerIdentity, Statement, PAYLOAD_TYPE_IN_TOTO};

/// A signer build the verifier expects: a platform id and launch measurement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerBuild {
    pub platform: String,
    pub measurement: Measurement,
}

#[derive(Clone, Default)]
pub struct TeePolicy {
    /// One verifier per platform accepted.
    pub verifiers: Vec<Arc<dyn AttestationVerifier>>,
    /// Signer builds whose receipts are accepted. Empty accepts none.
    pub allowed_builds: Vec<SignerBuild>,
}

#[derive(Clone, Default)]
pub struct ReceiptPolicy {
    /// Operator keys accepted for `operator-key` receipts. Empty rejects them.
    pub operator_keys: Vec<VerifyingKey>,
    /// Accepted TEE signers. `None` rejects `tee` receipts.
    pub tee: Option<TeePolicy>,
}

impl ReceiptPolicy {
    /// Phase-1 policy: trust one operator key, no TEE.
    pub fn operator(key: VerifyingKey) -> Self {
        ReceiptPolicy {
            operator_keys: vec![key],
            tee: None,
        }
    }
}

/// Who signed a receipt, as established by the policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedSigner {
    OperatorKey {
        key_id: String,
    },
    Tee {
        platform: String,
        measurement: Measurement,
        key_id: String,
    },
}

impl VerifiedSigner {
    /// What the signature is worth, in one sentence for humans.
    pub fn trust_note(&self) -> &'static str {
        match self {
            VerifiedSigner::OperatorKey { .. } => {
                "Signed by the operator's key: you are trusting the operator (ADR-5 phase 1)."
            }
            VerifiedSigner::Tee { platform, .. } if platform == PLATFORM_SOFTWARE_INSECURE => {
                "Signed with a SOFTWARE attestation: development only, offers no security."
            }
            VerifiedSigner::Tee { .. } => {
                "Signed by a key attested to an allowlisted signer build in a TEE: you are \
                 trusting that build and the TEE vendor, not the operator's key."
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReceipt {
    pub statement: Statement,
    pub signer: VerifiedSigner,
}

/// Verify `env` under `policy`; see the module docs.
pub fn verify_receipt_with_policy(
    env: &Envelope,
    policy: &ReceiptPolicy,
) -> anyhow::Result<VerifiedReceipt> {
    if env.payload_type != PAYLOAD_TYPE_IN_TOTO {
        bail!("unexpected payloadType {:?}", env.payload_type);
    }
    // Read the claimed identity from the not-yet-authenticated payload only
    // to decide which key to check; the statement returned is the one
    // `verify_envelope` decodes after the signature checks out.
    let claimed: Statement = serde_json::from_slice(&env.payload_bytes()?)
        .context("payload is not an in-toto statement")?;
    match &claimed.predicate.signer {
        SignerIdentity::OperatorKey => {
            for key in &policy.operator_keys {
                if let Ok(statement) = verify_envelope(env, key) {
                    return Ok(VerifiedReceipt {
                        statement,
                        signer: VerifiedSigner::OperatorKey {
                            key_id: key_id(key),
                        },
                    });
                }
            }
            bail!("no valid signature by an accepted operator key")
        }
        SignerIdentity::Tee { attestation } => {
            let tee = policy
                .tee
                .as_ref()
                .ok_or_else(|| anyhow!("TEE-signed receipts are not accepted by this policy"))?;
            let verifier = tee
                .verifiers
                .iter()
                .find(|v| v.platform() == attestation.platform)
                .ok_or_else(|| {
                    anyhow!("no verifier for TEE platform {:?}", attestation.platform)
                })?;
            let attested = verifier
                .verify(attestation)
                .context("attestation does not verify")?;
            let allowed = tee
                .allowed_builds
                .iter()
                .any(|b| b.platform == attested.platform && b.measurement == attested.measurement);
            if !allowed {
                bail!(
                    "signer build {} on {} is not in the allowlist",
                    attested.measurement,
                    attested.platform
                );
            }
            // The envelope must be signed by the attested key itself.
            let statement = verify_envelope(env, &attested.public_key)
                .context("envelope is not signed by the attested key")?;
            Ok(VerifiedReceipt {
                statement,
                signer: VerifiedSigner::Tee {
                    platform: attested.platform,
                    measurement: attested.measurement,
                    key_id: attested.key_id,
                },
            })
        }
        SignerIdentity::Unknown => bail!("unknown signer identity type"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use ed25519_dalek::{Signer as _, SigningKey};

    use crate::attest::{Attestation, AttestationProvider, PLATFORM_AMD_SEV_SNP};
    use crate::statement::tests::{sample_ctx, sample_verdict};
    use crate::{
        build_statement, sign_verdict, Ed25519Signer, InMemoryLog, Signer, SoftwareAttestation,
        TeeSigner, TransparencyLog,
    };

    const GOOD: [u8; 48] = [0xaa; 48];

    fn platform(measurement: [u8; 48]) -> SoftwareAttestation {
        SoftwareAttestation::new(
            SigningKey::from_bytes(&[1; 32]),
            Measurement(measurement.to_vec()),
        )
    }

    fn tee_policy() -> ReceiptPolicy {
        ReceiptPolicy {
            operator_keys: vec![],
            tee: Some(TeePolicy {
                verifiers: vec![Arc::new(platform(GOOD).verifier())],
                allowed_builds: vec![SignerBuild {
                    platform: PLATFORM_SOFTWARE_INSECURE.into(),
                    measurement: Measurement(GOOD.to_vec()),
                }],
            }),
        }
    }

    /// Signs with `key` but claims `identity`: what an operator holding its
    /// own key (or a copied attestation) could produce.
    struct Forger {
        key: SigningKey,
        identity: SignerIdentity,
    }

    #[async_trait::async_trait]
    impl Signer for Forger {
        fn public_key(&self) -> VerifyingKey {
            self.key.verifying_key()
        }
        fn identity(&self) -> SignerIdentity {
            self.identity.clone()
        }
        async fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(self.key.sign(message).to_bytes().to_vec())
        }
    }

    async fn tee_receipt(signer: &dyn Signer) -> Envelope {
        sign_verdict(&sample_verdict(b"x"), &sample_ctx(), signer)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn tee_receipt_roundtrip() {
        let signer = TeeSigner::generate(&platform(GOOD)).await.unwrap();
        let env = tee_receipt(&signer).await;
        let got = verify_receipt_with_policy(&env, &tee_policy()).unwrap();
        assert_eq!(
            got.signer,
            VerifiedSigner::Tee {
                platform: PLATFORM_SOFTWARE_INSECURE.into(),
                measurement: Measurement(GOOD.to_vec()),
                key_id: signer.key_id(),
            }
        );
        assert!(got.signer.trust_note().contains("no security"));
        assert_eq!(
            got.statement.predicate.signer,
            SignerIdentity::Tee {
                attestation: signer.attestation().clone()
            }
        );
        // Apart from the identity, the statement is the phase-1 one.
        let mut expected = build_statement(&sample_verdict(b"x"), &sample_ctx());
        expected.predicate.signer = signer.identity();
        assert_eq!(got.statement, expected);

        // The attestation is not accepted by an operator-only policy, even
        // one that trusts the enclave key directly...
        assert!(
            verify_receipt_with_policy(&env, &ReceiptPolicy::operator(signer.public_key()))
                .is_err()
        );
        // ...but the plain DSSE check with that key still passes.
        verify_envelope(&env, &signer.public_key()).unwrap();
    }

    #[tokio::test]
    async fn wrong_measurement_rejected() {
        let signer = TeeSigner::generate(&platform([0xbb; 48])).await.unwrap();
        let env = tee_receipt(&signer).await;
        let err = verify_receipt_with_policy(&env, &tee_policy()).unwrap_err();
        assert!(err.to_string().contains("allowlist"), "{err:#}");

        // Right measurement, but allowlisted for another platform.
        let signer = TeeSigner::generate(&platform(GOOD)).await.unwrap();
        let env = tee_receipt(&signer).await;
        let mut policy = tee_policy();
        policy.tee.as_mut().unwrap().allowed_builds[0].platform = PLATFORM_AMD_SEV_SNP.into();
        assert!(verify_receipt_with_policy(&env, &policy).is_err());
    }

    #[tokio::test]
    async fn attestation_for_another_key_rejected() {
        let genuine = TeeSigner::generate(&platform(GOOD)).await.unwrap();
        // Operator signs with its own key and pastes the enclave's attestation.
        let forger = Forger {
            key: SigningKey::from_bytes(&[5; 32]),
            identity: genuine.identity(),
        };
        let env = tee_receipt(&forger).await;
        let err = verify_receipt_with_policy(&env, &tee_policy()).unwrap_err();
        assert!(format!("{err:#}").contains("attested key"), "{err:#}");

        // Or edits the attestation's public_key to its own: the report still
        // binds the enclave key.
        let mut att = genuine.attestation().clone();
        att.public_key = hex::encode(forger.key.verifying_key().as_bytes());
        let forger = Forger {
            identity: SignerIdentity::Tee { attestation: att },
            ..forger
        };
        let env = tee_receipt(&forger).await;
        let err = verify_receipt_with_policy(&env, &tee_policy()).unwrap_err();
        assert!(format!("{err:#}").contains("bind"), "{err:#}");
    }

    #[tokio::test]
    async fn tampered_attestation_rejected() {
        let genuine = TeeSigner::generate(&platform(GOOD)).await.unwrap();
        let mut report: serde_json::Value =
            serde_json::from_slice(&genuine.attestation().report_bytes().unwrap()).unwrap();
        report["measurement"] = serde_json::json!(hex::encode([0xcc; 48]));
        let att = Attestation {
            report: B64.encode(serde_json::to_vec(&report).unwrap()),
            ..genuine.attestation().clone()
        };
        let forger = Forger {
            key: SigningKey::from_bytes(&[5; 32]),
            identity: SignerIdentity::Tee { attestation: att },
        };
        let mut policy = tee_policy();
        policy.tee.as_mut().unwrap().allowed_builds[0].measurement = Measurement(vec![0xcc; 48]);
        let env = tee_receipt(&forger).await;
        let err = verify_receipt_with_policy(&env, &policy).unwrap_err();
        assert!(
            format!("{err:#}").contains("signature does not verify"),
            "{err:#}"
        );

        // Attestation from a different "platform" key (a self-made TEE).
        let rogue =
            SoftwareAttestation::new(SigningKey::from_bytes(&[6; 32]), Measurement(GOOD.to_vec()));
        let signer = TeeSigner::generate(&rogue).await.unwrap();
        let env = tee_receipt(&signer).await;
        assert!(verify_receipt_with_policy(&env, &tee_policy()).is_err());

        // Payload edited after signing (identity stripped to downgrade).
        let signer = TeeSigner::generate(&platform(GOOD)).await.unwrap();
        let env = tee_receipt(&signer).await;
        let mut json: serde_json::Value =
            serde_json::from_slice(&env.payload_bytes().unwrap()).unwrap();
        json["predicate"]["signer"] = serde_json::json!({"type": "operator-key"});
        let mut tampered = env.clone();
        tampered.payload = B64.encode(serde_json::to_vec(&json).unwrap());
        let mut policy = tee_policy();
        policy.operator_keys = vec![Ed25519Signer::generate().public_key()];
        assert!(verify_receipt_with_policy(&tampered, &policy).is_err());
    }

    #[tokio::test]
    async fn policy_selects_by_identity() {
        let op = Ed25519Signer::generate();
        let env = tee_receipt(&op).await;
        let got =
            verify_receipt_with_policy(&env, &ReceiptPolicy::operator(op.public_key())).unwrap();
        assert_eq!(
            got.signer,
            VerifiedSigner::OperatorKey {
                key_id: op.key_id()
            }
        );
        assert_eq!(
            got.statement,
            verify_envelope(&env, &op.public_key()).unwrap()
        );
        // TEE-only policy rejects operator receipts.
        assert!(verify_receipt_with_policy(&env, &tee_policy()).is_err());
        // TEE receipts need a TEE policy.
        let tee = TeeSigner::generate(&platform(GOOD)).await.unwrap();
        let env = tee_receipt(&tee).await;
        assert!(
            verify_receipt_with_policy(&env, &ReceiptPolicy::operator(op.public_key())).is_err()
        );
        // Unknown identity types are never accepted.
        let forger = Forger {
            key: SigningKey::from_bytes(&[5; 32]),
            identity: SignerIdentity::Unknown,
        };
        let env = tee_receipt(&forger).await;
        let policy = ReceiptPolicy {
            operator_keys: vec![forger.public_key()],
            ..tee_policy()
        };
        assert!(verify_receipt_with_policy(&env, &policy).is_err());
    }

    /// SNP attestations are parsed but never accepted while the report
    /// signature is unverified, even if the measurement is allowlisted.
    #[tokio::test]
    async fn snp_attestation_is_not_accepted_yet() {
        struct FakeSnp;
        #[async_trait::async_trait]
        impl AttestationProvider for FakeSnp {
            fn platform(&self) -> &str {
                PLATFORM_AMD_SEV_SNP
            }
            async fn report(&self, rd: [u8; 32]) -> anyhow::Result<Vec<u8>> {
                Ok(crate::snp::tests::synthetic_report(rd, GOOD, 0x30000))
            }
        }
        let signer = TeeSigner::generate(&FakeSnp).await.unwrap();
        let env = tee_receipt(&signer).await;
        let policy = ReceiptPolicy {
            operator_keys: vec![],
            tee: Some(TeePolicy {
                verifiers: vec![Arc::new(crate::SevSnpVerifier::new())],
                allowed_builds: vec![SignerBuild {
                    platform: PLATFORM_AMD_SEV_SNP.into(),
                    measurement: Measurement(GOOD.to_vec()),
                }],
            }),
        };
        let err = verify_receipt_with_policy(&env, &policy).unwrap_err();
        assert!(format!("{err:#}").contains("not implemented"), "{err:#}");
    }

    #[tokio::test]
    async fn tee_envelope_is_plain_dsse() {
        let signer = TeeSigner::generate(&platform(GOOD)).await.unwrap();
        let env = tee_receipt(&signer).await;
        let json = serde_json::to_value(&env).unwrap();
        let mut keys: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["payload", "payloadType", "signatures"]);
        let sig = json["signatures"][0].as_object().unwrap();
        assert_eq!(sig.len(), 2);
        assert_eq!(sig["keyid"], signer.key_id());
        // Signature is plain ed25519 over the standard PAE.
        let pae = crate::pae(&env.payload_type, &env.payload_bytes().unwrap());
        let raw: [u8; 64] = B64
            .decode(sig["sig"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        use ed25519_dalek::Verifier as _;
        signer
            .public_key()
            .verify(&pae, &ed25519_dalek::Signature::from_bytes(&raw))
            .unwrap();
        // Payload is an in-toto Statement with the identity in the predicate.
        let st: serde_json::Value = serde_json::from_slice(&env.payload_bytes().unwrap()).unwrap();
        assert_eq!(st["_type"], crate::STATEMENT_TYPE);
        assert_eq!(st["predicate"]["signer"]["type"], "tee");
        assert_eq!(
            st["predicate"]["signer"]["attestation"]["platform"],
            PLATFORM_SOFTWARE_INSECURE
        );
        // And it goes into the transparency log like any other envelope.
        let log = InMemoryLog::new(Arc::new(Ed25519Signer::generate()));
        log.append(&env).await.unwrap().verify_inclusion().unwrap();
    }
}
