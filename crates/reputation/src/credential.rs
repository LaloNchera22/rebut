//! Anonymous credentials over the trust graph (ADR-8, phase 3).
//!
//! # Why
//!
//! A contributor with a long record of verified merges on project A should be
//! able to show project B "I have at least 20 verified merges, none reverted"
//! *without* revealing their identity or which merges those were, and without
//! B being able to link two presentations to the same person.
//!
//! # What is implemented
//!
//! All cryptography comes from [`zkryptium`] (pinned to `=0.7.1`), which
//! implements the IETF CFRG drafts on the BLS12-381-SHA-256 ciphersuite:
//!
//! * BBS signatures and proofs (`draft-irtf-cfrg-bbs-signatures`);
//! * blind issuance (`draft-irtf-cfrg-bbs-blind-signatures`);
//! * pseudonyms, i.e. per-verifier linkability
//!   (`draft-irtf-cfrg-bbs-per-verifier-linkability`).
//!
//! Nothing in this module does curve arithmetic. It fixes the credential
//! schema, encodes attributes as BBS messages, and checks every untrusted
//! byte string before handing it to the library (see "Input checks" below).
//! zkryptium describes itself as an experimental implementation for research
//! purposes and has not had a public audit. Treat these credentials as
//! experimental until it has.
//!
//! # Protocol
//!
//! 1. The holder generates a [`HolderSecret`] once and keeps it.
//! 2. [`request_issuance`]: the holder commits to the secret and sends the
//!    [`IssuanceRequest`] (a Pedersen commitment with a proof of knowledge).
//!    The issuer never sees the secret (blind issuance).
//! 3. [`issue`]: the issuer checks the commitment proof and signs the
//!    attributes it derived from the [`crate::TrustGraph`]
//!    ([`CredentialAttributes::from_trust_graph`]) together with the committed
//!    secret.
//! 4. [`accept`]: the holder verifies the signature and gets a [`Credential`].
//! 5. [`present`]: for a verifier's `scope` and fresh `nonce`, the holder
//!    derives a zero-knowledge [`Presentation`] that discloses chosen
//!    attributes and proves chosen [`Predicate`]s. Each presentation is
//!    freshly randomized, so two presentations can't be linked by their bytes.
//! 6. [`verify`]: the verifier checks it against the issuer's public key, its
//!    own scope and nonce, and learns a [`VerifiedPresentation`].
//!
//! [`Bbs`] implements the [`CredentialScheme`] trait with these functions.
//!
//! # Predicates: threshold buckets, not range proofs
//!
//! BBS proves knowledge of signed messages and discloses some of them. It
//! can't prove `merges ≥ 20` about an undisclosed number. So the issuer signs
//! extra boolean attributes, one per threshold in the schema:
//! `verified_merges ≥ t` for every `t` in [`MERGE_THRESHOLDS`] and
//! `reverted_merges ≤ t` for every `t` in [`REVERT_CEILINGS`]. To prove a
//! predicate the holder discloses the matching boolean, and the verifier
//! rebuilds it as "true" before checking the proof, so a holder can't claim a
//! bucket that was signed as false.
//!
//! The trade-offs:
//!
//! * Only predicates on those two attributes, with a value from those lists,
//!   can be proven. Anything else is rejected by [`present`] with
//!   [`CredentialError::UnsupportedPredicate`]; we never round a request to a
//!   nearby bucket and we never report a predicate we did not prove.
//! * A verifier learns exactly which bucket was proven (`≥ 20`), and nothing
//!   about the other buckets or the underlying count. Asking for several
//!   buckets in one presentation narrows the count to an interval.
//! * The thresholds are part of the schema ([`SCHEMA_ID`]); changing them is a
//!   new schema version.
//!
//! # Nullifiers
//!
//! Every presentation carries a pseudonym `OP(scope) * nym_secret`, proven
//! inside the same BBS proof. [`Nullifier`] is its SHA-256. For one credential,
//! the same scope always gives the same nullifier, and different scopes give
//! unlinkable ones. The issuer contributes random entropy to `nym_secret`
//! but can't compute it, because it never sees the holder's secret.
//!
//! **Limit.** The nullifier is per *credential*, not per person. Blind
//! issuance means the issuer can't check that a holder reused their secret, so
//! a holder who obtains two credentials gets two nullifiers per scope. "One
//! claim per person per scope" therefore also needs the issuer to hand out at
//! most one credential per author for the lifetime of a scope. That policy is
//! not enforced here.
//!
//! # Input checks
//!
//! zkryptium 0.7.1 slices its inputs without checking lengths (short input
//! panics), and its proof decoding does not reject the identity point. With
//! `Abar` and `Bbar` both the identity the pairing check passes trivially,
//! and what remains looks like a Schnorr proof a forger could simulate. We
//! did not build that exploit; we close the door instead. This module checks
//! exact lengths from the schema and rejects identity points in keys,
//! commitments, proofs and pseudonyms before calling the library.
//!
//! # zkVMs later
//!
//! Aggregation that BBS predicates can't express (e.g. "merges across ≥ 3
//! distinct organizations, weighted by project size") moves to a zkVM proof
//! (SP1 / RISC Zero) over the receipts themselves, and only when a concrete
//! need appears.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use verifier_core::Digest;
use zkryptium::bbsplus::commitment::BlindFactor;
use zkryptium::bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey};
use zkryptium::bbsplus::pseudonym::{BBSplusPseudonym, PseudonymSecret};
use zkryptium::keys::pair::KeyPair;
use zkryptium::schemes::algorithms::BbsBls12381Sha256 as Suite;
use zkryptium::schemes::generics::{BlindSignature, Commitment, PoKSignature};

use crate::TrustGraph;

/// Schema identifier, signed as the BBS header of every credential. It pins
/// the attribute order and the threshold lists below.
pub const SCHEMA_ID: &[u8] = b"rebut/credential/bbs-bls12381-sha256/v1";

/// `verified_merges ≥ t` buckets the issuer signs.
pub const MERGE_THRESHOLDS: [u64; 9] = [1, 5, 10, 20, 50, 100, 200, 500, 1000];

/// `reverted_merges ≤ t` buckets the issuer signs.
pub const REVERT_CEILINGS: [u64; 4] = [0, 1, 2, 5];

/// Attribute indices. They are part of the schema and never reused.
pub const VERIFIED_MERGES: usize = 0;
pub const REVERTED_MERGES: usize = 1;
pub const FIRST_MERGE_DAY: usize = 2;
pub const RECEIPTS_COMMITMENT: usize = 3;
const ATTRIBUTE_COUNT: usize = 4;
/// Total signed messages: attributes, then merge buckets, then revert buckets.
const MESSAGE_COUNT: usize = ATTRIBUTE_COUNT + MERGE_THRESHOLDS.len() + REVERT_CEILINGS.len();

/// One secret scalar in the pseudonym vector (the draft allows several).
const NYM_LEN: usize = 1;

const SECONDS_PER_DAY: u64 = 86_400;
const G1_LEN: usize = 48;
const G2_LEN: usize = 96;
const SCALAR_LEN: usize = 32;
const SIGNATURE_LEN: usize = 80;
/// Commitment to (secret_prover_blind, nym): point + proof (s^, m^ for the
/// nym, challenge).
const COMMITMENT_LEN: usize = G1_LEN + SCALAR_LEN * (NYM_LEN + 2);

/// A signed attribute. Attributes are ordered; indices are part of the
/// credential schema and must never be reused with a different meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum Attribute {
    /// Total verified merges at issuance, reverted ones included.
    VerifiedMerges(u64),
    /// Merges later reverted for a verified defect.
    RevertedMerges(u64),
    /// Unix time of the first verified merge, rounded down to a day.
    FirstMergeDay(u64),
    /// Commitment to the set of receipt digests backing this credential,
    /// so an auditor holding the receipts can check issuance was honest.
    ///
    /// It is a plain hash of receipts that are public in the transparency
    /// log, so it is *not* hiding: disclosing it identifies the holder to
    /// anyone who recomputes it. Disclose it only to an auditor.
    ReceiptsCommitment(Digest),
}

impl Attribute {
    /// Schema index of this attribute.
    pub fn index(&self) -> usize {
        match self {
            Attribute::VerifiedMerges(_) => VERIFIED_MERGES,
            Attribute::RevertedMerges(_) => REVERTED_MERGES,
            Attribute::FirstMergeDay(_) => FIRST_MERGE_DAY,
            Attribute::ReceiptsCommitment(_) => RECEIPTS_COMMITMENT,
        }
    }

    /// BBS message bytes: a per-attribute tag, then the value.
    fn encode(&self) -> Vec<u8> {
        let (tag, value): (&[u8], Vec<u8>) = match self {
            Attribute::VerifiedMerges(n) => (b"verified_merges", n.to_be_bytes().to_vec()),
            Attribute::RevertedMerges(n) => (b"reverted_merges", n.to_be_bytes().to_vec()),
            Attribute::FirstMergeDay(d) => (b"first_merge_day", d.to_be_bytes().to_vec()),
            Attribute::ReceiptsCommitment(d) => (b"receipts_commitment", d.0.to_vec()),
        };
        [b"rebut/attr/v1/".as_slice(), tag, b"=", &value].concat()
    }
}

/// The attributes of one credential, in schema order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialAttributes {
    pub verified_merges: u64,
    pub reverted_merges: u64,
    pub first_merge_day: u64,
    pub receipts_commitment: Digest,
}

impl CredentialAttributes {
    /// Derive the attributes for `author` from the trust graph.
    ///
    /// Fails if the author has no verified merge, or if none of their merges
    /// has a recorded time ([`TrustGraph::record_merge_at`]).
    pub fn from_trust_graph(graph: &TrustGraph, author: &str) -> Result<Self, CredentialError> {
        let receipts = graph.verified_merges(author);
        if receipts.is_empty() {
            return Err(CredentialError::InvalidAttributes(
                "author has no verified merges",
            ));
        }
        let first = graph
            .first_merge_time(author)
            .ok_or(CredentialError::InvalidAttributes(
                "no merge of this author has a recorded time",
            ))?;
        Ok(Self {
            verified_merges: receipts.len() as u64,
            reverted_merges: graph.reverted_count(author) as u64,
            first_merge_day: first - first % SECONDS_PER_DAY,
            receipts_commitment: receipts_commitment(&receipts),
        })
    }

    /// The attributes as a vector indexed by schema index.
    pub fn to_vec(&self) -> Vec<Attribute> {
        vec![
            Attribute::VerifiedMerges(self.verified_merges),
            Attribute::RevertedMerges(self.reverted_merges),
            Attribute::FirstMergeDay(self.first_merge_day),
            Attribute::ReceiptsCommitment(self.receipts_commitment),
        ]
    }

    fn check(&self) -> Result<(), CredentialError> {
        if self.reverted_merges > self.verified_merges {
            return Err(CredentialError::InvalidAttributes(
                "more reverted merges than verified merges",
            ));
        }
        Ok(())
    }

    /// All signed BBS messages: attributes, then the bucket booleans.
    fn messages(&self) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = self.to_vec().iter().map(Attribute::encode).collect();
        for t in MERGE_THRESHOLDS {
            out.push(bucket_message(
                BucketKind::MergesAtLeast,
                t,
                self.verified_merges >= t,
            ));
        }
        for t in REVERT_CEILINGS {
            out.push(bucket_message(
                BucketKind::RevertsAtMost,
                t,
                self.reverted_merges <= t,
            ));
        }
        out
    }
}

/// Commitment to a set of receipt digests: SHA-256 over the sorted,
/// length-framed digests with a domain tag. Auditors recompute it from the
/// receipts.
pub fn receipts_commitment(receipts: &[Digest]) -> Digest {
    let mut sorted = receipts.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut parts: Vec<&[u8]> = vec![b"rebut/receipts-commitment/v1"];
    parts.extend(sorted.iter().map(|d| d.0.as_slice()));
    Digest::of_parts(&parts)
}

#[derive(Clone, Copy)]
enum BucketKind {
    MergesAtLeast,
    RevertsAtMost,
}

fn bucket_message(kind: BucketKind, threshold: u64, holds: bool) -> Vec<u8> {
    let tag: &[u8] = match kind {
        BucketKind::MergesAtLeast => b"verified_merges>=",
        BucketKind::RevertsAtMost => b"reverted_merges<=",
    };
    [
        b"rebut/bucket/v1/".as_slice(),
        tag,
        &threshold.to_be_bytes(),
        &[u8::from(holds)],
    ]
    .concat()
}

/// A predicate proven over an undisclosed attribute. Supported: `AtLeast` on
/// [`VERIFIED_MERGES`] with a value in [`MERGE_THRESHOLDS`], and `AtMost` on
/// [`REVERTED_MERGES`] with a value in [`REVERT_CEILINGS`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    AtLeast { attribute_index: usize, value: u64 },
    AtMost { attribute_index: usize, value: u64 },
}

impl Predicate {
    /// Index of the signed bucket message that proves this predicate.
    fn message_index(&self) -> Result<usize, CredentialError> {
        let position = |list: &[u64], v: u64| list.iter().position(|&t| t == v);
        match *self {
            Predicate::AtLeast {
                attribute_index: VERIFIED_MERGES,
                value,
            } => position(&MERGE_THRESHOLDS, value).map(|j| ATTRIBUTE_COUNT + j),
            Predicate::AtMost {
                attribute_index: REVERTED_MERGES,
                value,
            } => position(&REVERT_CEILINGS, value)
                .map(|j| ATTRIBUTE_COUNT + MERGE_THRESHOLDS.len() + j),
            _ => None,
        }
        .ok_or_else(|| CredentialError::UnsupportedPredicate(self.clone()))
    }

    /// The bucket message as it must have been signed for the predicate to
    /// hold.
    fn true_message(&self) -> Vec<u8> {
        match *self {
            Predicate::AtLeast { value, .. } => {
                bucket_message(BucketKind::MergesAtLeast, value, true)
            }
            Predicate::AtMost { value, .. } => {
                bucket_message(BucketKind::RevertsAtMost, value, true)
            }
        }
    }

    fn holds_for(&self, attrs: &CredentialAttributes) -> bool {
        match *self {
            Predicate::AtLeast { value, .. } => attrs.verified_merges >= value,
            Predicate::AtMost { value, .. } => attrs.reverted_merges <= value,
        }
    }
}

/// Scope-bound pseudonym; see the module docs. SHA-256 of the BBS pseudonym.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    fn of_pseudonym(pseudonym: &[u8]) -> Self {
        Nullifier(Sha256::digest([b"rebut/nullifier/v1/".as_slice(), pseudonym].concat()).into())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl Serialize for Nullifier {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

/// What a verifier learns from a valid presentation — and nothing more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedPresentation {
    /// Disclosed attributes, sorted by index.
    pub disclosed: Vec<(usize, Attribute)>,
    /// Predicates proven, exactly as claimed (each one checked).
    pub predicates: Vec<Predicate>,
    pub nullifier: Nullifier,
}

impl VerifiedPresentation {
    /// Whether `predicate` was proven. Only an exact match counts: a proven
    /// `AtLeast 20` does not answer `AtLeast 15` here; ask for a bucket.
    pub fn proves(&self, predicate: &Predicate) -> bool {
        self.predicates.contains(predicate)
    }

    pub fn attribute(&self, index: usize) -> Option<&Attribute> {
        self.disclosed
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, a)| a)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("invalid attributes: {0}")]
    InvalidAttributes(&'static str),
    #[error("predicate {0:?} is not in the credential schema")]
    UnsupportedPredicate(Predicate),
    #[error("the credential does not satisfy {0:?}")]
    PredicateNotSatisfied(Predicate),
    #[error("attribute index {0} is not in the credential schema")]
    UnknownAttribute(usize),
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("issuance failed: {0}")]
    Issuance(String),
    #[error("presentation failed: {0}")]
    Presentation(String),
    /// The presentation does not verify. Deliberately carries no detail.
    #[error("presentation is not valid")]
    Invalid,
}

// ---------------------------------------------------------------- keys

/// The issuer's BBS secret key.
pub struct IssuerSecretKey(BBSplusSecretKey);

/// The issuer's BBS public key (compressed G2 point, 96 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct IssuerPublicKey(BBSplusPublicKey);

impl IssuerSecretKey {
    /// A fresh key from the operating system's randomness.
    pub fn generate() -> Result<Self, CredentialError> {
        let kp =
            KeyPair::<Suite>::random().map_err(|e| CredentialError::Issuance(e.to_string()))?;
        let (sk, _) = kp.into_parts();
        Ok(Self(sk))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CredentialError> {
        let sk = BBSplusSecretKey::from_bytes(bytes)
            .map_err(|_| CredentialError::Malformed("issuer secret key"))?;
        if sk.to_bytes() == [0u8; SCALAR_LEN] {
            return Err(CredentialError::Malformed("issuer secret key"));
        }
        Ok(Self(sk))
    }

    pub fn to_bytes(&self) -> [u8; SCALAR_LEN] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> IssuerPublicKey {
        IssuerPublicKey(self.0.public_key())
    }
}

impl std::fmt::Debug for IssuerSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuerSecretKey(<redacted>)")
    }
}

impl IssuerPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CredentialError> {
        if bytes.len() != G2_LEN || is_identity(bytes) {
            return Err(CredentialError::Malformed("issuer public key"));
        }
        BBSplusPublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CredentialError::Malformed("issuer public key"))
    }

    pub fn to_bytes(&self) -> [u8; G2_LEN] {
        self.0.to_bytes()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl std::fmt::Debug for IssuerPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IssuerPublicKey({})", self.to_hex())
    }
}

/// The compressed encoding of the identity point: infinity flag set, all
/// other bits zero. It is the only valid encoding of the identity.
fn is_identity(compressed: &[u8]) -> bool {
    compressed.first() == Some(&0xc0) && compressed[1..].iter().all(|&b| b == 0)
}

// ---------------------------------------------------------------- holder

/// The holder's long-term secret. Nullifiers are derived from it (plus the
/// issuer's entropy). Never leaves the holder.
pub struct HolderSecret(PseudonymSecret);

impl HolderSecret {
    pub fn generate() -> Self {
        Self(PseudonymSecret::random())
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CredentialError> {
        PseudonymSecret::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CredentialError::Malformed("holder secret"))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl std::fmt::Debug for HolderSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HolderSecret(<redacted>)")
    }
}

/// Sent by the holder to the issuer: a commitment to the holder secret with a
/// proof of knowledge of its opening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceRequest {
    #[serde(with = "hex_bytes")]
    pub commitment: Vec<u8>,
}

/// Kept by the holder between [`request_issuance`] and [`accept`]: the
/// commitment's blinding factor. Secret.
pub struct PendingIssuance(BlindFactor);

impl std::fmt::Debug for PendingIssuance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingIssuance(<redacted>)")
    }
}

/// Sent by the issuer to the holder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedCredential {
    pub attributes: CredentialAttributes,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
    /// The issuer's share of the pseudonym secret.
    #[serde(with = "hex_bytes")]
    pub signer_nym_entropy: Vec<u8>,
}

/// A credential in the holder's hands. It contains the pseudonym secret and
/// must be kept private; it is `Serialize` so the holder can store it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    attributes: CredentialAttributes,
    #[serde(with = "hex_bytes")]
    signature: Vec<u8>,
    #[serde(with = "hex_bytes")]
    nym_secret: Vec<u8>,
    #[serde(with = "hex_bytes")]
    prover_blind: Vec<u8>,
}

impl Credential {
    pub fn attributes(&self) -> &CredentialAttributes {
        &self.attributes
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("attributes", &self.attributes)
            .finish_non_exhaustive()
    }
}

/// What a holder shows a verifier. Carries no nonce or scope: the verifier
/// supplies its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presentation {
    pub disclosed: Vec<(usize, Attribute)>,
    pub predicates: Vec<Predicate>,
    /// Compressed G1 pseudonym for the verifier's scope.
    #[serde(with = "hex_bytes")]
    pub pseudonym: Vec<u8>,
    /// BBS proof of knowledge with pseudonym.
    #[serde(with = "hex_bytes")]
    pub proof: Vec<u8>,
}

impl Presentation {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("presentation serializes")
    }

    pub fn from_json(s: &str) -> Result<Self, CredentialError> {
        serde_json::from_str(s).map_err(|_| CredentialError::Malformed("presentation JSON"))
    }
}

// ---------------------------------------------------------------- protocol

/// Holder: commit to `holder` for blind issuance.
pub fn request_issuance(
    holder: &HolderSecret,
) -> Result<(IssuanceRequest, PendingIssuance), CredentialError> {
    let (commitment, blind) = Commitment::<Suite>::commit_with_nym(None, vec![holder.0.clone()])
        .map_err(|e| CredentialError::Issuance(e.to_string()))?;
    Ok((
        IssuanceRequest {
            commitment: commitment.to_bytes(),
        },
        PendingIssuance(blind),
    ))
}

/// Issuer: check the holder's commitment and sign `attributes` with it.
///
/// The caller is responsible for deciding *whom* it issues to and how often
/// (see "Limit" in the module docs).
pub fn issue(
    sk: &IssuerSecretKey,
    request: &IssuanceRequest,
    attributes: &CredentialAttributes,
) -> Result<IssuedCredential, CredentialError> {
    attributes.check()?;
    // An empty commitment is valid in the draft and would leave the issuer
    // knowing the whole pseudonym secret; require one of the exact length.
    if request.commitment.len() != COMMITMENT_LEN || is_identity(&request.commitment[..G1_LEN]) {
        return Err(CredentialError::Malformed("issuance commitment"));
    }
    let pk = sk.0.public_key();
    let entropy = PseudonymSecret::random();
    let messages = attributes.messages();
    let sig = BlindSignature::<Suite>::blind_sign_with_nym(
        &sk.0,
        &pk,
        Some(&request.commitment),
        NYM_LEN,
        Some(SCHEMA_ID),
        &entropy,
        Some(&messages),
    )
    .map_err(|e| CredentialError::Issuance(e.to_string()))?;
    Ok(IssuedCredential {
        attributes: attributes.clone(),
        signature: sig.to_bytes().to_vec(),
        signer_nym_entropy: entropy.to_bytes().to_vec(),
    })
}

/// Holder: verify the issuer's signature and finish the credential.
pub fn accept(
    pk: &IssuerPublicKey,
    holder: &HolderSecret,
    pending: PendingIssuance,
    issued: &IssuedCredential,
) -> Result<Credential, CredentialError> {
    issued.attributes.check()?;
    let sig: [u8; SIGNATURE_LEN] = issued
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| CredentialError::Malformed("signature"))?;
    let sig = BlindSignature::<Suite>::from_bytes(&sig)
        .map_err(|_| CredentialError::Malformed("signature"))?;
    let entropy: [u8; SCALAR_LEN] = issued
        .signer_nym_entropy
        .as_slice()
        .try_into()
        .map_err(|_| CredentialError::Malformed("signer nym entropy"))?;
    let entropy = PseudonymSecret::from_bytes(&entropy)
        .map_err(|_| CredentialError::Malformed("signer nym entropy"))?;
    let messages = issued.attributes.messages();
    let nym_secrets = sig
        .verify_finalize_with_nym(
            &pk.0,
            Some(SCHEMA_ID),
            Some(&messages),
            None,
            vec![holder.0.clone()],
            Some(&entropy),
            Some(&pending.0),
        )
        .map_err(|_| CredentialError::Issuance("issuer signature does not verify".into()))?;
    let nym = nym_secrets
        .first()
        .ok_or(CredentialError::Issuance("no pseudonym secret".into()))?;
    Ok(Credential {
        attributes: issued.attributes.clone(),
        signature: sig.to_bytes().to_vec(),
        nym_secret: nym.to_bytes().to_vec(),
        prover_blind: pending.0.to_bytes().to_vec(),
    })
}

/// Holder: derive a presentation that discloses the attributes at
/// `disclose` and proves `predicates`, bound to the verifier's `scope`
/// (nullifier domain) and `nonce` (fresh challenge, prevents replay).
///
/// Fails, rather than producing something that won't verify, when a
/// predicate is unsupported or not satisfied by the credential.
pub fn present(
    pk: &IssuerPublicKey,
    credential: &Credential,
    disclose: &[usize],
    predicates: &[Predicate],
    scope: &[u8],
    nonce: &[u8],
) -> Result<Presentation, CredentialError> {
    if scope.is_empty() {
        return Err(CredentialError::Empty("scope"));
    }
    if nonce.is_empty() {
        return Err(CredentialError::Empty("nonce"));
    }
    let attrs = credential.attributes.to_vec();
    let mut disclose = disclose.to_vec();
    disclose.sort_unstable();
    disclose.dedup();
    if let Some(&i) = disclose.iter().find(|&&i| i >= ATTRIBUTE_COUNT) {
        return Err(CredentialError::UnknownAttribute(i));
    }
    let mut predicates = predicates.to_vec();
    predicates.dedup();
    let mut indexes = disclose.clone();
    for p in &predicates {
        let idx = p.message_index()?;
        if !p.holds_for(&credential.attributes) {
            return Err(CredentialError::PredicateNotSatisfied(p.clone()));
        }
        indexes.push(idx);
    }
    indexes.sort_unstable();
    indexes.dedup();

    let nym: [u8; SCALAR_LEN] = credential
        .nym_secret
        .as_slice()
        .try_into()
        .map_err(|_| CredentialError::Malformed("credential"))?;
    let nym =
        PseudonymSecret::from_bytes(&nym).map_err(|_| CredentialError::Malformed("credential"))?;
    let blind: [u8; SCALAR_LEN] = credential
        .prover_blind
        .as_slice()
        .try_into()
        .map_err(|_| CredentialError::Malformed("credential"))?;
    let blind =
        BlindFactor::from_bytes(&blind).map_err(|_| CredentialError::Malformed("credential"))?;

    let messages = credential.attributes.messages();
    let (proof, pseudonym) = PoKSignature::<Suite>::proof_gen_with_nym(
        &pk.0,
        &credential.signature,
        Some(SCHEMA_ID),
        Some(nonce),
        &vec![nym],
        scope,
        Some(&messages),
        None,
        Some(&indexes),
        None,
        Some(&blind),
    )
    .map_err(|e| CredentialError::Presentation(e.to_string()))?;

    Ok(Presentation {
        disclosed: disclose.iter().map(|&i| (i, attrs[i].clone())).collect(),
        predicates,
        pseudonym: pseudonym.to_bytes(),
        proof: proof.to_bytes(),
    })
}

/// Verifier: check `presentation` for its own `scope` and `nonce`.
pub fn verify(
    pk: &IssuerPublicKey,
    presentation: &Presentation,
    scope: &[u8],
    nonce: &[u8],
) -> Result<VerifiedPresentation, CredentialError> {
    if scope.is_empty() {
        return Err(CredentialError::Empty("scope"));
    }
    if nonce.is_empty() {
        return Err(CredentialError::Empty("nonce"));
    }

    // Rebuild the disclosed messages from the claims. Bucket messages are
    // rebuilt as "true", so a claim over a bucket signed as false fails the
    // proof.
    let mut disclosed: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut attributes = presentation.disclosed.clone();
    attributes.sort_by_key(|(i, _)| *i);
    for (i, attr) in &attributes {
        if *i != attr.index() {
            return Err(CredentialError::Invalid);
        }
        disclosed.push((*i, attr.encode()));
    }
    for p in &presentation.predicates {
        let idx = p.message_index().map_err(|_| CredentialError::Invalid)?;
        disclosed.push((idx, p.true_message()));
    }
    disclosed.sort_by_key(|(i, _)| *i);
    if disclosed.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(CredentialError::Invalid);
    }
    let indexes: Vec<usize> = disclosed.iter().map(|(i, _)| *i).collect();
    let messages: Vec<Vec<u8>> = disclosed.into_iter().map(|(_, m)| m).collect();

    // Exact lengths and no identity points before the library sees the bytes.
    let undisclosed = MESSAGE_COUNT - indexes.len() + 1 /* blind */ + NYM_LEN;
    let proof_len = 3 * G1_LEN + 3 * SCALAR_LEN + SCALAR_LEN * (undisclosed + 1);
    let proof = &presentation.proof;
    if proof.len() != proof_len || proof[..3 * G1_LEN].chunks(G1_LEN).any(is_identity) {
        return Err(CredentialError::Invalid);
    }
    let pseudonym = &presentation.pseudonym;
    if pseudonym.len() != G1_LEN || is_identity(pseudonym) {
        return Err(CredentialError::Invalid);
    }
    let proof = PoKSignature::<Suite>::from_bytes(proof).map_err(|_| CredentialError::Invalid)?;
    let nym = BBSplusPseudonym::from_bytes(pseudonym).map_err(|_| CredentialError::Invalid)?;

    proof
        .proof_verify_with_nym(
            &pk.0,
            Some(SCHEMA_ID),
            Some(nonce),
            &nym,
            scope,
            NYM_LEN,
            Some(MESSAGE_COUNT),
            Some(&messages),
            None,
            Some(&indexes),
            None,
        )
        .map_err(|_| CredentialError::Invalid)?;

    Ok(VerifiedPresentation {
        disclosed: attributes,
        predicates: presentation.predicates.clone(),
        nullifier: Nullifier::of_pseudonym(pseudonym),
    })
}

// ---------------------------------------------------------------- trait

/// The credential scheme, as a contract other code can depend on.
pub trait CredentialScheme {
    type IssuerSecretKey;
    type IssuerPublicKey;
    /// Holder's long-term secret; nullifiers are derived from it.
    type HolderSecret;
    /// Commitment to `HolderSecret`, sent at issuance (blind issuance), so the
    /// issuer never learns the secret.
    type IssuanceRequest;
    /// Holder-side state between request and acceptance.
    type PendingIssuance;
    /// What the issuer returns.
    type IssuedCredential;
    type Credential;
    type Presentation;
    type Error: std::error::Error;

    fn request_issuance(
        holder: &Self::HolderSecret,
    ) -> Result<(Self::IssuanceRequest, Self::PendingIssuance), Self::Error>;

    /// Issuer signs `attributes` bound to the holder's committed secret.
    fn issue(
        sk: &Self::IssuerSecretKey,
        request: &Self::IssuanceRequest,
        attributes: &CredentialAttributes,
    ) -> Result<Self::IssuedCredential, Self::Error>;

    /// Holder checks the issuer's signature.
    fn accept(
        pk: &Self::IssuerPublicKey,
        holder: &Self::HolderSecret,
        pending: Self::PendingIssuance,
        issued: &Self::IssuedCredential,
    ) -> Result<Self::Credential, Self::Error>;

    /// Holder derives an unlinkable presentation disclosing `disclose`
    /// (attribute indices), proving `predicates` over the rest, bound to
    /// `scope` (nullifier domain) and `nonce` (verifier challenge, prevents
    /// replay).
    fn present(
        pk: &Self::IssuerPublicKey,
        credential: &Self::Credential,
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

/// BBS (BLS12-381-SHA-256) with blind issuance and pseudonyms, via zkryptium.
pub struct Bbs;

impl CredentialScheme for Bbs {
    type IssuerSecretKey = IssuerSecretKey;
    type IssuerPublicKey = IssuerPublicKey;
    type HolderSecret = HolderSecret;
    type IssuanceRequest = IssuanceRequest;
    type PendingIssuance = PendingIssuance;
    type IssuedCredential = IssuedCredential;
    type Credential = Credential;
    type Presentation = Presentation;
    type Error = CredentialError;

    fn request_issuance(
        holder: &HolderSecret,
    ) -> Result<(IssuanceRequest, PendingIssuance), CredentialError> {
        request_issuance(holder)
    }

    fn issue(
        sk: &IssuerSecretKey,
        request: &IssuanceRequest,
        attributes: &CredentialAttributes,
    ) -> Result<IssuedCredential, CredentialError> {
        issue(sk, request, attributes)
    }

    fn accept(
        pk: &IssuerPublicKey,
        holder: &HolderSecret,
        pending: PendingIssuance,
        issued: &IssuedCredential,
    ) -> Result<Credential, CredentialError> {
        accept(pk, holder, pending, issued)
    }

    fn present(
        pk: &IssuerPublicKey,
        credential: &Credential,
        disclose: &[usize],
        predicates: &[Predicate],
        scope: &[u8],
        nonce: &[u8],
    ) -> Result<Presentation, CredentialError> {
        present(pk, credential, disclose, predicates, scope, nonce)
    }

    fn verify(
        pk: &IssuerPublicKey,
        presentation: &Presentation,
        scope: &[u8],
        nonce: &[u8],
    ) -> Result<VerifiedPresentation, CredentialError> {
        verify(pk, presentation, scope, nonce)
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests;
