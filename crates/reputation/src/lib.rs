//! Reputation (phase 3).
//!
//! Two pieces, deliberately small:
//!
//! * [`TrustGraph`]: who has had which verified PRs merged, keyed by the
//!   digest of the signed receipt that attests the verification. Every edge
//!   points at a receipt anyone can fetch from the transparency log and
//!   re-verify, so reputation is derived from evidence, not from our say-so.
//! * [`credential`]: anonymous credentials (ADR-8). Rebut issues a BBS
//!   credential over attributes derived from the graph, and the contributor
//!   proves "I have ≥ N verified merges, none reverted" to a new project
//!   without revealing who they are, with a per-scope nullifier. The
//!   cryptography is zkryptium's implementation of the IETF CFRG BBS drafts;
//!   see the module docs for what is and isn't covered.

pub mod credential;

use std::collections::{BTreeMap, BTreeSet};

use rebut_core::Digest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReputationError {
    /// A receipt attests one PR by one author; it cannot be claimed twice.
    #[error("receipt {receipt} is already credited to {owner}")]
    ReceiptAlreadyClaimed { receipt: Digest, owner: String },
    #[error("author must not be empty")]
    EmptyAuthor,
    #[error("receipt {0} is not a recorded merge")]
    UnknownReceipt(Digest),
}

/// Bipartite graph author → receipt digests of their verified merges.
///
/// Callers must only record a merge after verifying the receipt (signature
/// and transparency-log inclusion) and that its verdict was not `fail`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGraph {
    by_author: BTreeMap<String, BTreeSet<Digest>>,
    owner_of: BTreeMap<Digest, String>,
    /// Unix time (seconds) each merge happened, when known.
    #[serde(default)]
    merged_at: BTreeMap<Digest, u64>,
    /// Merges later reverted for a verified defect.
    #[serde(default)]
    reverted: BTreeSet<Digest>,
}

impl TrustGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Credit `receipt_digest` to `author`. Returns `Ok(true)` if the edge is
    /// new, `Ok(false)` if it was already recorded for the same author
    /// (idempotent), and an error if another author already holds it.
    pub fn record_merge(
        &mut self,
        author: &str,
        receipt_digest: Digest,
    ) -> Result<bool, ReputationError> {
        if author.trim().is_empty() {
            return Err(ReputationError::EmptyAuthor);
        }
        if let Some(owner) = self.owner_of.get(&receipt_digest) {
            return if owner == author {
                Ok(false)
            } else {
                Err(ReputationError::ReceiptAlreadyClaimed {
                    receipt: receipt_digest,
                    owner: owner.clone(),
                })
            };
        }
        self.owner_of.insert(receipt_digest, author.to_string());
        self.by_author
            .entry(author.to_string())
            .or_default()
            .insert(receipt_digest);
        Ok(true)
    }

    /// Like [`Self::record_merge`], also recording when the merge happened
    /// (Unix seconds). The first recorded time for a receipt is kept.
    pub fn record_merge_at(
        &mut self,
        author: &str,
        receipt_digest: Digest,
        merged_at: u64,
    ) -> Result<bool, ReputationError> {
        let new = self.record_merge(author, receipt_digest)?;
        self.merged_at.entry(receipt_digest).or_insert(merged_at);
        Ok(new)
    }

    /// Mark a recorded merge as reverted for a verified defect. Returns
    /// `Ok(false)` if it was already marked.
    pub fn record_revert(&mut self, receipt_digest: Digest) -> Result<bool, ReputationError> {
        if !self.owner_of.contains_key(&receipt_digest) {
            return Err(ReputationError::UnknownReceipt(receipt_digest));
        }
        Ok(self.reverted.insert(receipt_digest))
    }

    /// How many of `author`'s merges were reverted.
    pub fn reverted_count(&self, author: &str) -> usize {
        self.by_author.get(author).map_or(0, |s| {
            s.iter().filter(|d| self.reverted.contains(d)).count()
        })
    }

    /// Earliest recorded merge time of `author`, if any merge has one.
    pub fn first_merge_time(&self, author: &str) -> Option<u64> {
        self.by_author
            .get(author)?
            .iter()
            .filter_map(|d| self.merged_at.get(d).copied())
            .min()
    }

    /// Receipt digests of `author`'s verified merges, in digest order.
    pub fn verified_merges(&self, author: &str) -> Vec<Digest> {
        self.by_author
            .get(author)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn merge_count(&self, author: &str) -> usize {
        self.by_author.get(author).map_or(0, BTreeSet::len)
    }

    /// Who a receipt is credited to.
    pub fn author_of(&self, receipt_digest: &Digest) -> Option<&str> {
        self.owner_of.get(receipt_digest).map(String::as_str)
    }

    /// All authors with at least one verified merge.
    pub fn authors(&self) -> impl Iterator<Item = &str> {
        self.by_author.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_counts() {
        let mut g = TrustGraph::new();
        let (r1, r2) = (Digest::of(b"receipt-1"), Digest::of(b"receipt-2"));
        assert_eq!(g.record_merge("alice", r1), Ok(true));
        assert_eq!(g.record_merge("alice", r2), Ok(true));
        assert_eq!(g.record_merge("alice", r1), Ok(false), "idempotent");
        assert_eq!(g.merge_count("alice"), 2);
        let mut expected = vec![r1, r2];
        expected.sort();
        assert_eq!(g.verified_merges("alice"), expected);
        assert!(g.verified_merges("bob").is_empty());
        assert_eq!(g.author_of(&r1), Some("alice"));
        assert_eq!(g.authors().collect::<Vec<_>>(), vec!["alice"]);
    }

    #[test]
    fn receipt_cannot_be_claimed_by_two_authors() {
        let mut g = TrustGraph::new();
        let r = Digest::of(b"receipt");
        g.record_merge("alice", r).unwrap();
        assert_eq!(
            g.record_merge("mallory", r),
            Err(ReputationError::ReceiptAlreadyClaimed {
                receipt: r,
                owner: "alice".into()
            })
        );
        assert_eq!(g.merge_count("mallory"), 0);
        assert_eq!(g.record_merge(" ", r), Err(ReputationError::EmptyAuthor));
    }

    #[test]
    fn reverts_and_times() {
        let mut g = TrustGraph::new();
        let (r1, r2) = (Digest::of(b"receipt-1"), Digest::of(b"receipt-2"));
        g.record_merge_at("alice", r1, 2_000).unwrap();
        g.record_merge_at("alice", r2, 1_000).unwrap();
        assert_eq!(g.first_merge_time("alice"), Some(1_000));
        assert_eq!(g.first_merge_time("bob"), None);
        assert_eq!(g.reverted_count("alice"), 0);
        assert_eq!(g.record_revert(r1), Ok(true));
        assert_eq!(g.record_revert(r1), Ok(false));
        assert_eq!(g.reverted_count("alice"), 1);
        let unknown = Digest::of(b"nope");
        assert_eq!(
            g.record_revert(unknown),
            Err(ReputationError::UnknownReceipt(unknown))
        );
    }

    #[test]
    fn deserializes_graph_without_new_fields() {
        let mut g = TrustGraph::new();
        g.record_merge("alice", Digest::of(b"r")).unwrap();
        let mut v = serde_json::to_value(&g).unwrap();
        v.as_object_mut().unwrap().remove("merged_at");
        v.as_object_mut().unwrap().remove("reverted");
        let back: TrustGraph = serde_json::from_value(v).unwrap();
        assert_eq!(back, g);
    }

    #[test]
    fn serde_roundtrip() {
        let mut g = TrustGraph::new();
        g.record_merge("alice", Digest::of(b"r")).unwrap();
        let json = serde_json::to_string(&g).unwrap();
        let back: TrustGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(back, g);
    }
}
