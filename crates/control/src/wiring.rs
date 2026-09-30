//! Production adapters that plug the planner, drand, the execution fabric and
//! the engines into the orchestrator's seams.
//!
//! Checkouts happen on the host, but only to *read* source (planner, challenge
//! specs, tarballs for the VM). Nothing from a checkout is built or executed
//! here: git runs with hooks disabled and only `https` allowed, and every
//! build happens inside the fabric.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use time::OffsetDateTime;
use tokio::process::Command;
use verifier_challenges::drand;
use verifier_challenges::ChallengesEngine;
use verifier_core::{
    CommitSha, DrandBeacon, Engine, EngineContext, EngineKind, EngineReport, ExecutionRequest,
    ImpactPlan, PullRequest, RepoId,
};
use verifier_fabric::SourceProvider;

use crate::orchestrator::{BeaconSource, Planner, SealedSpecSource};

/// Content-addressed cache of source checkouts: `<root>/<sha>/`.
#[derive(Debug, Clone)]
pub struct GitCheckouts {
    root: PathBuf,
    allow_file_protocol: bool,
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl GitCheckouts {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        GitCheckouts {
            root: root.into(),
            allow_file_protocol: false,
            lock: Arc::default(),
        }
    }

    /// Also accept `file://` URLs. Tests only.
    pub fn allow_file_protocol(mut self) -> Self {
        self.allow_file_protocol = true;
        self
    }

    /// Path of a checkout of `sha` from `url`, fetching it if not cached.
    /// The checkout is keyed by the commit alone: a sha names the same tree
    /// whichever fork it was fetched from.
    pub async fn checkout(&self, url: &str, sha: &CommitSha) -> anyhow::Result<PathBuf> {
        let dest = self.root.join(sha.as_str());
        if dest.is_dir() {
            return Ok(dest);
        }
        if !(url.starts_with("https://") || self.allow_file_protocol && url.starts_with("file://"))
        {
            bail!("refusing to fetch from non-https url {url:?}");
        }
        // One fetch at a time keeps concurrent jobs for the same commit from
        // racing; checkouts are cached, so contention is short-lived.
        let _guard = self.lock.lock().await;
        if dest.is_dir() {
            return Ok(dest);
        }
        tokio::fs::create_dir_all(&self.root).await?;
        let tmp = self
            .root
            .join(format!(".tmp-{}-{}", sha.as_str(), uuid::Uuid::new_v4()));
        let result = self.fetch_into(&tmp, url, sha).await;
        if let Err(e) = result {
            let _ = tokio::fs::remove_dir_all(&tmp).await;
            return Err(e);
        }
        tokio::fs::rename(&tmp, &dest)
            .await
            .context("publishing checkout")?;
        Ok(dest)
    }

    async fn fetch_into(&self, dir: &Path, url: &str, sha: &CommitSha) -> anyhow::Result<()> {
        tokio::fs::create_dir_all(dir).await?;
        let protocols = if self.allow_file_protocol {
            "file"
        } else {
            "https"
        };
        git(dir, &["init", "-q"], protocols).await?;
        git(
            dir,
            &["fetch", "-q", "--depth=1", "--no-tags", url, sha.as_str()],
            protocols,
        )
        .await?;
        git(dir, &["checkout", "-q", "--force", "FETCH_HEAD"], protocols).await?;
        let head = git(dir, &["rev-parse", "HEAD"], protocols).await?;
        if head.trim() != sha.as_str() {
            bail!("fetched {} but expected {sha}", head.trim());
        }
        tokio::fs::remove_dir_all(dir.join(".git")).await?;
        Ok(())
    }
}

async fn git(dir: &Path, args: &[&str], allowed_protocol: &str) -> anyhow::Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(["-c", "protocol.allow=never"])
        .args(["-c", &format!("protocol.{allowed_protocol}.allow=always")])
        .args(["-c", "advice.detachedHead=false"])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::null())
        .output()
        .await
        .context("running git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Ships a checkout of `req.commit` into the VM.
pub struct GitSource(pub GitCheckouts);

#[async_trait::async_trait]
impl SourceProvider for GitSource {
    async fn fetch(&self, req: &ExecutionRequest) -> anyhow::Result<Vec<u8>> {
        let dir = self.0.checkout(&req.repo_url, &req.commit).await?;
        let tgz =
            tokio::task::spawn_blocking(move || verifier_guest::archive::pack_directory(&dir))
                .await??;
        Ok(tgz)
    }
}

/// The real planner over base and head checkouts.
pub struct CheckoutPlanner(pub GitCheckouts);

#[async_trait::async_trait]
impl Planner for CheckoutPlanner {
    async fn plan(&self, pr: &PullRequest) -> anyhow::Result<ImpactPlan> {
        let base = self.0.checkout(&pr.base_clone_url, &pr.base_sha).await?;
        let head = self.0.checkout(&pr.head_clone_url, &pr.head_sha).await?;
        tokio::task::spawn_blocking(move || verifier_planner::plan(&base, &head)).await?
    }
}

/// drand quicknet (ADR-7): waits for the first round after the push, then
/// fetches it and checks `randomness == sha256(signature)`.
pub struct DrandBeaconSource<S> {
    pub source: S,
    /// Upper bound on waiting for the round to be published.
    pub max_wait: Duration,
}

#[async_trait::async_trait]
impl<S: drand::BeaconSource> BeaconSource for DrandBeaconSource<S> {
    async fn round_after(&self, after: OffsetDateTime) -> anyhow::Result<DrandBeacon> {
        let round = drand::round_after(after.unix_timestamp().max(0) as u64);
        let due = drand::round_time(round) as i64;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if due >= now {
            let wait = Duration::from_secs((due - now + 1) as u64);
            if wait > self.max_wait {
                bail!("drand round {round} is {wait:?} away");
            }
            tokio::time::sleep(wait).await;
        }
        let beacon = self.source.round(round).await?;
        if beacon.round != round {
            bail!("beacon source returned round {} for {round}", beacon.round);
        }
        drand::verify_randomness(&beacon)?;
        Ok(beacon)
    }
}

/// Challenges engine whose public specs come from the **base** checkout, so a
/// PR can never choose its own challenges.
pub struct BaseChallenges(pub GitCheckouts);

#[async_trait::async_trait]
impl Engine for BaseChallenges {
    fn kind(&self) -> EngineKind {
        EngineKind::Challenges
    }

    async fn run(&self, ctx: &EngineContext) -> anyhow::Result<EngineReport> {
        let base = self
            .0
            .checkout(&ctx.pr.base_clone_url, &ctx.pr.base_sha)
            .await?;
        ChallengesEngine::from_base_checkout(&base)?.run(ctx).await
    }
}

/// Sealed specs stored on the operator's disk: `<root>/<owner>/<repo>/*.toml`.
/// Only their hashes are public (in the base policy's `sealed_commitments`).
pub struct DirSealedSpecs(pub PathBuf);

#[async_trait::async_trait]
impl SealedSpecSource for DirSealedSpecs {
    async fn specs(&self, repo: &RepoId) -> anyhow::Result<Vec<String>> {
        for part in [&repo.owner, &repo.name] {
            if part.is_empty() || part.starts_with('.') || part.contains(['/', '\\']) {
                bail!("invalid repository name component {part:?}");
            }
        }
        let dir = self.0.join(&repo.owner).join(&repo.name);
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut paths = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "toml") && entry.file_type().await?.is_file() {
                paths.push(path);
            }
        }
        paths.sort();
        let mut specs = Vec::with_capacity(paths.len());
        for p in paths {
            specs.push(tokio::fs::read_to_string(&p).await?);
        }
        Ok(specs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{:?}", out);
        String::from_utf8(out.stdout).unwrap()
    }

    fn repo_with_commit(dir: &Path) -> CommitSha {
        run_git(dir, &["init", "-q"]);
        std::fs::write(dir.join("a.txt"), "hello").unwrap();
        run_git(dir, &["add", "."]);
        run_git(dir, &["commit", "-q", "-m", "init"]);
        CommitSha::new(run_git(dir, &["rev-parse", "HEAD"]).trim()).unwrap()
    }

    #[tokio::test]
    async fn checkout_fetches_exact_commit_and_caches() {
        let src = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let sha = repo_with_commit(src.path());
        // Allow fetching an unadvertised sha from a local repo.
        run_git(
            src.path(),
            &["config", "uploadpack.allowAnySHA1InWant", "true"],
        );
        let url = format!("file://{}", src.path().display());
        let co = GitCheckouts::new(cache.path()).allow_file_protocol();
        let dir = co.checkout(&url, &sha).await.unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("a.txt")).unwrap(), "hello");
        assert!(!dir.join(".git").exists());
        // Cached: works even once the source is gone.
        drop(src);
        assert_eq!(co.checkout(&url, &sha).await.unwrap(), dir);
    }

    #[tokio::test]
    async fn checkout_refuses_non_https() {
        let cache = tempfile::tempdir().unwrap();
        let co = GitCheckouts::new(cache.path());
        let sha = CommitSha::new("a".repeat(40)).unwrap();
        for url in [
            "file:///etc",
            "ssh://host/x",
            "http://host/x",
            "ext::sh -c x",
        ] {
            assert!(co.checkout(url, &sha).await.is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn sealed_specs_are_read_sorted_and_names_validated() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("o").join("r");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.toml"), "B").unwrap();
        std::fs::write(dir.join("a.toml"), "A").unwrap();
        std::fs::write(dir.join("notes.md"), "ignored").unwrap();
        let src = DirSealedSpecs(root.path().into());
        let repo = |o: &str, n: &str| RepoId {
            owner: o.into(),
            name: n.into(),
        };
        assert_eq!(src.specs(&repo("o", "r")).await.unwrap(), vec!["A", "B"]);
        assert!(src.specs(&repo("o", "missing")).await.unwrap().is_empty());
        assert!(src.specs(&repo("..", "r")).await.is_err());
        assert!(src.specs(&repo("o", "a/b")).await.is_err());
    }

    #[tokio::test]
    async fn drand_adapter_checks_round_and_randomness() {
        use sha2::{Digest as _, Sha256};
        struct Fake(bool);
        #[async_trait::async_trait]
        impl drand::BeaconSource for Fake {
            async fn round(&self, round: u64) -> anyhow::Result<DrandBeacon> {
                let signature = format!("{round:096x}");
                let mut randomness = hex::encode(Sha256::digest(hex::decode(&signature).unwrap()));
                if self.0 {
                    randomness.replace_range(0..1, "z");
                }
                Ok(DrandBeacon {
                    chain_hash: "c".into(),
                    round,
                    randomness,
                    signature,
                })
            }
            async fn latest(&self) -> anyhow::Result<DrandBeacon> {
                unreachable!()
            }
        }
        let past = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let ok = DrandBeaconSource {
            source: Fake(false),
            max_wait: Duration::ZERO,
        };
        let b = ok.round_after(past).await.unwrap();
        assert_eq!(b.round, drand::round_after(1_700_000_000));
        let bad = DrandBeaconSource {
            source: Fake(true),
            max_wait: Duration::ZERO,
        };
        assert!(bad.round_after(past).await.is_err());
        let future = OffsetDateTime::now_utc() + time::Duration::hours(1);
        assert!(ok.round_after(future).await.is_err());
    }
}
