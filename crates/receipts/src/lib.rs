//! Signed verification receipts (ADR-5, phase 1).
//!
//! A receipt is an [in-toto Statement v1](https://in-toto.io/Statement/v1)
//! about the PR head commit, wrapped in a [DSSE](https://github.com/secure-systems-lab/dsse)
//! envelope signed with ed25519 and appended to a transparency log.
//!
//! # Trust assumption (phase 1)
//!
//! **You must trust the operator's signing key.** A receipt proves that the
//! holder of that key attested to the verdict and that the attestation was
//! logged; it does not prove the Rebut actually ran as described. Phase 2
//! moves the [`Signer`] into a TEE so the signature additionally attests to
//! the code that produced it. The [`Signer`] trait is the seam for that move.
//!
//! What a receipt never contains: sealed challenge inputs, expected or
//! observed outputs, stdout/stderr, or finding titles. Findings are reduced
//! to engine, category, visibility, target, intent flag and the digest of the
//! reproduction transcript.

pub mod dsse;
pub mod log;
pub mod merkle;
pub mod statement;

pub use dsse::{
    key_id, pae, verify_envelope, Ed25519Signer, Envelope, EnvelopeSignature, Signer,
    PAYLOAD_TYPE_IN_TOTO,
};
pub use log::{InMemoryLog, InclusionProof, LogEntry, RekorLog, SignedTreeHead, TransparencyLog};
pub use merkle::{leaf_hash, node_hash, root_hash, verify_inclusion, MerkleTree};
pub use statement::{
    build_statement, FindingRecord, ReceiptContext, SeedRecord, Statement, Subject,
    VerificationPredicate, PREDICATE_TYPE, STATEMENT_TYPE,
};

/// Build, sign and wrap a statement for `verdict` in one call.
pub async fn sign_verdict(
    verdict: &rebut_core::Verdict,
    ctx: &ReceiptContext,
    signer: &dyn Signer,
) -> anyhow::Result<Envelope> {
    let statement = build_statement(verdict, ctx);
    Envelope::sign_statement(&statement, signer).await
}
