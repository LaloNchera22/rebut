//! ADR-7: challenge seeds are `H(commit_sha ‖ drand_round ‖ randomness ‖ generator_version)`,
//! using the first drand round published after the push. Anyone can recompute
//! the seed and regenerate the public challenges.

use serde::{Deserialize, Serialize};

use crate::{CommitSha, Digest};

/// Bumped whenever challenge generation changes, so old receipts stay
/// reproducible with the old generator.
pub const GENERATOR_VERSION: &str = "challenges/v1";

/// A drand round from the League of Entropy (quicknet chain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrandBeacon {
    pub chain_hash: String,
    pub round: u64,
    /// Hex-encoded randomness (sha256 of the round signature).
    pub randomness: String,
    /// Hex-encoded BLS signature, kept so auditors can verify the round.
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Seed(pub Digest);

impl Seed {
    pub fn derive(commit: &CommitSha, beacon: &DrandBeacon, generator_version: &str) -> Self {
        Seed(Digest::of_parts(&[
            commit.as_str().as_bytes(),
            &beacon.round.to_be_bytes(),
            beacon.randomness.as_bytes(),
            generator_version.as_bytes(),
        ]))
    }

    /// Sub-seed for an independent stream (e.g. one challenge family), so
    /// adding a family never shifts the inputs of another.
    pub fn fork(&self, label: &str) -> Seed {
        Seed(Digest::of_parts(&[&self.0 .0, label.as_bytes()]))
    }

    pub fn bytes(&self) -> [u8; 32] {
        self.0 .0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beacon(round: u64) -> DrandBeacon {
        DrandBeacon {
            chain_hash: "c".into(),
            round,
            randomness: "ab".into(),
            signature: "s".into(),
        }
    }

    #[test]
    fn deterministic_and_sensitive() {
        let c = CommitSha::new("a".repeat(40)).unwrap();
        let s1 = Seed::derive(&c, &beacon(1), GENERATOR_VERSION);
        assert_eq!(s1, Seed::derive(&c, &beacon(1), GENERATOR_VERSION));
        assert_ne!(s1, Seed::derive(&c, &beacon(2), GENERATOR_VERSION));
        assert_ne!(s1, Seed::derive(&c, &beacon(1), "challenges/v2"));
        assert_ne!(s1.fork("a"), s1.fork("b"));
    }
}
