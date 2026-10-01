//! Signed verification receipts (ADR-5).
//!
//! A receipt is an [in-toto Statement v1](https://in-toto.io/Statement/v1)
//! about the PR head commit, wrapped in a [DSSE](https://github.com/secure-systems-lab/dsse)
//! envelope signed with ed25519 and appended to a transparency log. The
//! statement's `predicate.signer` records the signer identity type
//! ([`SignerIdentity`]); phase-1 receipts, which lack it, decode as
//! `operator-key`.
//!
//! # Trust assumption (phase 1: `operator-key`)
//!
//! **You must trust the operator's signing key.** A receipt proves that the
//! holder of that key attested to the verdict and that the attestation was
//! logged; it does not prove the verifier actually ran as described.
//!
//! # Phase 2: `tee` (partial)
//!
//! A [`TeeSigner`] generates its key inside a TEE, and the receipt carries an
//! [`Attestation`] binding that key to a measured signer build.
//! [`verify_receipt_with_policy`] checks the attestation, that the attested
//! key signed the envelope, and that the build is on the verifier's
//! allowlist. What is and isn't secured today:
//!
//! - [`SoftwareAttestation`] is for tests and development and **offers no
//!   security**: anyone with its dev platform key can attest anything.
//! - AMD SEV-SNP ([`snp`]) reports are parsed and policy-checked, but the
//!   report signature and VCEK chain are **not verified**, so
//!   [`SevSnpVerifier`] rejects every report. No hardware TEE receipt is
//!   accepted yet.
//! - Even with a real TEE, a signer that signs whatever the host asks is a
//!   signing oracle for the operator. The attestation removes operator trust
//!   only if the measured build itself produces or checks the verdict (see
//!   [`tee`]).
//! - [`verify_envelope`] checks a signature by a key you already trust and
//!   ignores the signer identity; it never evaluates attestations.
//!
//! What a receipt never contains: sealed challenge inputs, expected or
//! observed outputs, stdout/stderr, or finding titles. Findings are reduced
//! to engine, category, visibility, target, intent flag and the digest of the
//! reproduction transcript.

pub mod attest;
pub mod dsse;
pub mod log;
pub mod merkle;
pub mod policy;
pub mod snp;
pub mod statement;
pub mod tee;

pub use attest::{
    attest_key, key_binding, Attestation, AttestationError, AttestationProvider,
    AttestationVerifier, AttestedKey, Measurement, ReportClaims, SoftwareAttestation,
    SoftwareAttestationVerifier, PLATFORM_AMD_SEV_SNP, PLATFORM_SOFTWARE_INSECURE,
};
pub use dsse::{
    key_id, pae, verify_envelope, Ed25519Signer, Envelope, EnvelopeSignature, Signer,
    PAYLOAD_TYPE_IN_TOTO,
};
pub use log::{InMemoryLog, InclusionProof, LogEntry, RekorLog, SignedTreeHead, TransparencyLog};
pub use merkle::{leaf_hash, node_hash, root_hash, verify_inclusion, MerkleTree};
pub use policy::{
    verify_receipt_with_policy, ReceiptPolicy, SignerBuild, TeePolicy, VerifiedReceipt,
    VerifiedSigner,
};
pub use snp::{SevSnpReport, SevSnpTsmProvider, SevSnpVerifier};
pub use statement::{
    build_statement, FindingRecord, ReceiptContext, SeedRecord, SignerIdentity, Statement, Subject,
    VerificationPredicate, PREDICATE_TYPE, STATEMENT_TYPE,
};
pub use tee::TeeSigner;

/// Build, sign and wrap a statement for `verdict` in one call. The statement
/// records `signer.identity()`.
pub async fn sign_verdict(
    verdict: &verifier_core::Verdict,
    ctx: &ReceiptContext,
    signer: &dyn Signer,
) -> anyhow::Result<Envelope> {
    let statement = build_statement(verdict, ctx);
    Envelope::sign_statement(&statement, signer).await
}
