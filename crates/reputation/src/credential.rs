//! Anonymous credentials — interface sketch (ADR-8, phase 3).
//!
//! # Why
//!
//! A contributor with a long record of verified merges on project A should be
//! able to show project B "I have at least 20 verified merges, none reverted"
//! *without* revealing their identity or which merges those were, and without
//! B being able to link two presentations to the same person.
//!
//! # Decision (ADR-8)
//!
//! * **BBS signatures** (IETF CFRG draft `draft-irtf-cfrg-bbs-signatures`):
//!   the issuer (the verifier service) signs a vector of attributes derived
//!   from the [`crate::TrustGraph`]; the holder derives zero-knowledge proofs
//!   that disclose a chosen subset of attributes and prove predicates over
//!   the rest. Presentations are unlinkable to each other and to issuance.
//! * **Nullifiers**: each presentation carries a pseudonym deterministically
//!   derived from the holder's secret and a verifier-chosen *scope* (e.g.
//!   `"repo:owner/name:bounty-2026-10"`). Same holder + same scope ⇒ same
//!   nullifier, so one person cannot claim a scoped benefit twice; different
//!   scopes are unlinkable.
//! * **zkVMs later**: aggregation that BBS predicates can't express (e.g.
//!   "merges across ≥ 3 distinct organizations, weighted by project size")
//!   moves to a zkVM proof (SP1 / RISC Zero) over the receipts themselves.
//!   That is heavier and is only adopted when a concrete need appears.
//!
//! Nothing here implements cryptography. An implementation must use a
//! reviewed BBS library; until one is integrated this module is a contract,
//! not a feature.

use verifier_core::Digest;

/// A signed attribute. Attributes are ordered; indices are part of the
/// credential schema and must never be reused with a different meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    /// Total verified merges at issuance.
    VerifiedMerges(u64),
    /// Merges later reverted for a verified defect.
    RevertedMerges(u64),
    /// Unix time of the first verified merge (coarsened to a day).
    FirstMergeDay(u64),
    /// Commitment to the set of receipt digests backing this credential,
    /// so an auditor holding the receipts can check issuance was honest.
    ReceiptsCommitment(Digest),
}

/// A predicate proven over an undisclosed attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    AtLeast { attribute_index: usize, value: u64 },
    AtMost { attribute_index: usize, value: u64 },
}

/// Scope-bound pseudonym; see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nullifier(pub [u8; 32]);

/// What a verifier learns from a valid presentation — and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPresentation {
    pub disclosed: Vec<(usize, Attribute)>,
    pub predicates: Vec<Predicate>,
    pub nullifier: Nullifier,
}

/// The credential scheme. Associated types are opaque byte-level objects of
/// the concrete scheme (BBS keys, signatures and proofs).
pub trait CredentialScheme {
    type IssuerSecretKey;
    type IssuerPublicKey;
    /// Holder's long-term secret; nullifiers are derived from it.
    type HolderSecret;
    /// Commitment to `HolderSecret`, sent at issuance (blind issuance), so the
    /// issuer never learns the secret.
    type HolderCommitment;
    type Credential;
    type Presentation;
    type Error: std::error::Error;

    /// Issuer signs `attributes` bound to the holder's committed secret.
    fn issue(
        sk: &Self::IssuerSecretKey,
        holder: &Self::HolderCommitment,
        attributes: &[Attribute],
    ) -> Result<Self::Credential, Self::Error>;

    /// Holder derives an unlinkable presentation disclosing `disclose`
    /// (attribute indices), proving `predicates` over the rest, bound to
    /// `scope` (nullifier domain) and `nonce` (verifier challenge, prevents
    /// replay).
    fn present(
        pk: &Self::IssuerPublicKey,
        credential: &Self::Credential,
        holder: &Self::HolderSecret,
        disclose: &[usize],
        predicates: &[Predicate],
        scope: &[u8],
        nonce: &[u8],
    ) -> Result<Self::Presentation, Self::Error>;

    /// Verifier checks a presentation for its own `scope` and `nonce`.
    fn verify(
        pk: &Self::IssuerPublicKey,
        presentation: &Self::Presentation,
        scope: &[u8],
        nonce: &[u8],
    ) -> Result<VerifiedPresentation, Self::Error>;
}
