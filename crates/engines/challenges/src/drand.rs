//! drand beacons (ADR-7): the public randomness challenge seeds are made of.
//!
//! The seed of a PR uses the first quicknet round published strictly after
//! the push, so neither the contributor nor the maintainer can know it in
//! advance, and anyone can fetch the same round later to recompute it.
//!
//! Verification here is the cheap consistency check `randomness ==
//! sha256(signature)`. Full BLS verification of the signature against the
//! quicknet group public key is not done yet; until it is, a malicious relay
//! could serve a self-consistent fake round, so auditors should verify the
//! recorded `signature` independently (e.g. with the drand CLI).

use std::time::Duration;

use anyhow::{bail, Context};
use rebut_core::{CommitSha, DrandBeacon, Seed, GENERATOR_VERSION};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

pub const QUICKNET_CHAIN_HASH: &str =
    "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
/// Unix time of quicknet round 1.
pub const QUICKNET_GENESIS: u64 = 1_692_803_367;
/// Seconds between quicknet rounds.
pub const QUICKNET_PERIOD: u64 = 3;
pub const DEFAULT_ENDPOINT: &str = "https://api.drand.sh";

/// The first quicknet round published strictly after `unix_time`.
pub fn round_after(unix_time: u64) -> u64 {
    if unix_time < QUICKNET_GENESIS {
        return 1;
    }
    (unix_time - QUICKNET_GENESIS) / QUICKNET_PERIOD + 2
}

/// Unix time at which `round` (>= 1) is published.
pub fn round_time(round: u64) -> u64 {
    QUICKNET_GENESIS + round.saturating_sub(1) * QUICKNET_PERIOD
}

/// Checks `randomness == sha256(signature)` (both hex).
pub fn verify_randomness(b: &DrandBeacon) -> anyhow::Result<()> {
    let sig = hex::decode(&b.signature).context("signature is not hex")?;
    let expected = hex::encode(Sha256::digest(&sig));
    if !expected.eq_ignore_ascii_case(&b.randomness) {
        bail!("round {}: randomness is not sha256(signature)", b.round);
    }
    Ok(())
}

#[derive(Deserialize)]
struct Wire {
    round: u64,
    randomness: String,
    signature: String,
}

/// Parses a `/public/...` response body and verifies it (round number when
/// `expected_round` is given, and randomness consistency).
pub fn parse_beacon(
    chain_hash: &str,
    body: &[u8],
    expected_round: Option<u64>,
) -> anyhow::Result<DrandBeacon> {
    let w: Wire = serde_json::from_slice(body).context("malformed drand response")?;
    if let Some(r) = expected_round {
        if w.round != r {
            bail!("asked for round {r}, got {}", w.round);
        }
    }
    let beacon = DrandBeacon {
        chain_hash: chain_hash.to_string(),
        round: w.round,
        randomness: w.randomness.to_ascii_lowercase(),
        signature: w.signature.to_ascii_lowercase(),
    };
    verify_randomness(&beacon)?;
    Ok(beacon)
}

/// Where beacons come from; tests use [`FixedBeacon`].
#[async_trait::async_trait]
pub trait BeaconSource: Send + Sync {
    async fn round(&self, round: u64) -> anyhow::Result<DrandBeacon>;
    async fn latest(&self) -> anyhow::Result<DrandBeacon>;
}

/// HTTP client for a drand relay.
#[derive(Debug, Clone)]
pub struct DrandClient {
    http: reqwest::Client,
    base_url: String,
    chain_hash: String,
}

impl DrandClient {
    /// quicknet via `https://api.drand.sh`.
    pub fn quicknet() -> anyhow::Result<Self> {
        Self::new(DEFAULT_ENDPOINT, QUICKNET_CHAIN_HASH)
    }

    pub fn new(base_url: &str, chain_hash: &str) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(DrandClient {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            chain_hash: chain_hash.to_string(),
        })
    }

    pub fn round_url(&self, round: u64) -> String {
        format!("{}/{}/public/{round}", self.base_url, self.chain_hash)
    }

    pub fn latest_url(&self) -> String {
        format!("{}/{}/public/latest", self.base_url, self.chain_hash)
    }

    async fn fetch(&self, url: &str, expected_round: Option<u64>) -> anyhow::Result<DrandBeacon> {
        let resp = self.http.get(url).send().await?.error_for_status()?;
        let body = resp.bytes().await?;
        parse_beacon(&self.chain_hash, &body, expected_round)
    }
}

#[async_trait::async_trait]
impl BeaconSource for DrandClient {
    async fn round(&self, round: u64) -> anyhow::Result<DrandBeacon> {
        self.fetch(&self.round_url(round), Some(round)).await
    }
    async fn latest(&self) -> anyhow::Result<DrandBeacon> {
        self.fetch(&self.latest_url(), None).await
    }
}

/// A single known beacon (tests, offline replays of a recorded round).
#[derive(Debug, Clone)]
pub struct FixedBeacon(pub DrandBeacon);

#[async_trait::async_trait]
impl BeaconSource for FixedBeacon {
    async fn round(&self, round: u64) -> anyhow::Result<DrandBeacon> {
        if round != self.0.round {
            bail!("fixed beacon has round {}, not {round}", self.0.round);
        }
        Ok(self.0.clone())
    }
    async fn latest(&self) -> anyhow::Result<DrandBeacon> {
        Ok(self.0.clone())
    }
}

/// Fetches the first round after `push_unix_time` and derives the PR seed
/// for `head`. The round must already be published: callers wait until
/// [`round_time`]`(`[`round_after`]`(push))` has passed.
pub async fn seed_for_push(
    source: &dyn BeaconSource,
    head: &CommitSha,
    push_unix_time: u64,
) -> anyhow::Result<(DrandBeacon, Seed)> {
    let round = round_after(push_unix_time);
    let beacon = source.round(round).await?;
    if beacon.round != round {
        bail!("beacon source returned round {} for {round}", beacon.round);
    }
    verify_randomness(&beacon)?;
    let seed = Seed::derive(head, &beacon, GENERATOR_VERSION);
    Ok((beacon, seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn beacon(round: u64) -> DrandBeacon {
        let signature = format!("{:096x}", round);
        let randomness = hex::encode(Sha256::digest(hex::decode(&signature).unwrap()));
        DrandBeacon {
            chain_hash: QUICKNET_CHAIN_HASH.into(),
            round,
            randomness,
            signature,
        }
    }

    #[test]
    fn round_math() {
        assert_eq!(round_after(0), 1);
        assert_eq!(round_after(QUICKNET_GENESIS - 1), 1);
        // Round 1 is published *at* genesis, so it is not strictly after.
        assert_eq!(round_after(QUICKNET_GENESIS), 2);
        assert_eq!(round_after(QUICKNET_GENESIS + 2), 2);
        assert_eq!(round_after(QUICKNET_GENESIS + 3), 3);
        for t in QUICKNET_GENESIS..QUICKNET_GENESIS + 20 {
            let r = round_after(t);
            assert!(round_time(r) > t && round_time(r - 1) <= t, "t={t}");
        }
    }

    #[test]
    fn randomness_must_match_signature() {
        let b = beacon(42);
        verify_randomness(&b).unwrap();
        let mut bad = b.clone();
        bad.randomness = hex::encode([0u8; 32]);
        assert!(verify_randomness(&bad).is_err());
        let mut bad = b;
        bad.signature = "zz".into();
        assert!(verify_randomness(&bad).is_err());
    }

    #[test]
    fn parses_relay_json() {
        let b = beacon(1000);
        let body = format!(
            r#"{{"round":1000,"randomness":"{}","signature":"{}"}}"#,
            b.randomness.to_uppercase(),
            b.signature
        );
        assert_eq!(
            parse_beacon(QUICKNET_CHAIN_HASH, body.as_bytes(), Some(1000)).unwrap(),
            b
        );
        assert!(parse_beacon(QUICKNET_CHAIN_HASH, body.as_bytes(), Some(999)).is_err());
        assert!(parse_beacon(QUICKNET_CHAIN_HASH, b"{}", None).is_err());
    }

    #[test]
    fn urls() {
        let c = DrandClient::new("https://relay.example/", QUICKNET_CHAIN_HASH).unwrap();
        assert_eq!(
            c.round_url(7),
            format!("https://relay.example/{QUICKNET_CHAIN_HASH}/public/7")
        );
        assert!(c.latest_url().ends_with("/public/latest"));
    }

    #[tokio::test]
    async fn seed_from_fixed_beacon() {
        let head = CommitSha::new("c".repeat(40)).unwrap();
        let push = QUICKNET_GENESIS + 3 * 100 + 1; // -> round 102
        let src = FixedBeacon(beacon(102));
        let (b, seed) = seed_for_push(&src, &head, push).await.unwrap();
        assert_eq!(b.round, 102);
        assert_eq!(seed, Seed::derive(&head, &b, GENERATOR_VERSION));
        // A beacon for a different round is refused.
        assert!(seed_for_push(&src, &head, push + 3).await.is_err());
    }
}
