//! `rebut verify`: the public checks, run locally on your own branch.
//!
//! This uses [`LocalProcessExecutor`], which builds and runs code directly on
//! this machine without a sandbox. That is the same trust you already give
//! `cargo test` in your own checkout; never point it at code you would not
//! run yourself. The hosted service runs the same engines in Firecracker.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{bail, Context};
use rebut_challenges::drand::{self, BeaconSource};
use rebut_challenges::ChallengesEngine;
use rebut_core::{
    CommitSha, Digest, DrandBeacon, Engine, EngineContext, EngineKind, ExecutionRequest, Finding,
    ImpactPlan, IntentManifest, Policy, PullRequest, RepoId, Seed, Verdict, GENERATOR_VERSION,
};
use rebut_differential::DifferentialEngine;
use rebut_fabric::{LocalProcessExecutor, SourceProvider};
use serde::Serialize;

pub struct LocalOptions {
    /// Branch or commit to compare against; the merge base with `HEAD` is used.
    pub base: String,
    /// Where to get the drand beacon. `None` = offline: a local, clearly
    /// labelled pseudo-beacon derived from the head commit.
    pub beacon: Option<Arc<dyn BeaconSource>>,
    /// Restrict to these engines (default: the base policy's list).
    pub engines: Option<Vec<EngineKind>>,
}

#[derive(Debug, Serialize)]
pub struct LocalRun {
    pub base_sha: CommitSha,
    pub head_sha: CommitSha,
    /// The working tree has uncommitted changes; `head_sha` is a digest of
    /// the tree, not a real commit.
    pub synthetic_head: bool,
    pub beacon: DrandBeacon,
    pub offline_seed: bool,
    pub plan: ImpactPlan,
    pub verdict: Verdict,
    /// Hypotheses that could not be reproduced (never findings, ADR-6).
    pub unreproduced: usize,
    pub vm_seconds: u64,
}

/// Maps each commit to the directory holding its tree.
struct MapSource(BTreeMap<CommitSha, PathBuf>);

#[async_trait::async_trait]
impl SourceProvider for MapSource {
    async fn fetch(&self, req: &ExecutionRequest) -> anyhow::Result<Vec<u8>> {
        let dir = self
            .0
            .get(&req.commit)
            .with_context(|| format!("no local tree for commit {}", req.commit))?
            .clone();
        Ok(
            tokio::task::spawn_blocking(move || rebut_guest::archive::pack_directory(&dir))
                .await??,
        )
    }
}

fn git(repo: &Path, args: &[&str]) -> anyhow::Result<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .context("running git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

fn git_str(repo: &Path, args: &[&str]) -> anyhow::Result<String> {
    Ok(String::from_utf8(git(repo, args)?)?.trim().to_string())
}

fn read_opt(path: &Path) -> anyhow::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

pub async fn verify_local(repo: &Path, opts: LocalOptions) -> anyhow::Result<LocalRun> {
    let root = PathBuf::from(git_str(repo, &["rev-parse", "--show-toplevel"])?);
    let base_sha = CommitSha::new(git_str(&root, &["merge-base", &opts.base, "HEAD"])?)
        .map_err(anyhow::Error::msg)?;
    let dirty = !git(&root, &["status", "--porcelain"])?.is_empty();
    let head_sha = if dirty {
        let dir = root.clone();
        let tgz = tokio::task::spawn_blocking(move || rebut_guest::archive::pack_directory(&dir))
            .await??;
        CommitSha::new(&Digest::of(&tgz).to_hex()[..40]).map_err(anyhow::Error::msg)?
    } else {
        CommitSha::new(git_str(&root, &["rev-parse", "HEAD"])?).map_err(anyhow::Error::msg)?
    };

    // The base tree, from git history (never from the working tree).
    let base_dir = tempfile::tempdir()?;
    let tar = git(&root, &["archive", "--format=tar", base_sha.as_str()])?;
    tar::Archive::new(&tar[..]).unpack(base_dir.path())?;

    // Policy from the base, intent from the head: same rule as the service.
    let policy = match read_opt(&base_dir.path().join(".rebut/policy.toml"))? {
        Some(s) => Policy::from_toml(&s).context("parsing base .rebut/policy.toml")?,
        None => Policy::default(),
    };
    let intent = match read_opt(&root.join(".rebut/intent.toml"))? {
        Some(s) => IntentManifest::from_toml(&s).context("parsing .rebut/intent.toml")?,
        None => IntentManifest::default(),
    };

    let (beacon, offline_seed) = match &opts.beacon {
        Some(src) => {
            let b = src.latest().await.context("fetching drand beacon")?;
            drand::verify_randomness(&b)?;
            (b, false)
        }
        None => (
            DrandBeacon {
                chain_hash: "offline".into(),
                round: 0,
                randomness: Digest::of(head_sha.as_str().as_bytes()).to_hex(),
                signature: String::new(),
            },
            true,
        ),
    };
    let seed = Seed::derive(&head_sha, &beacon, GENERATOR_VERSION);

    let plan = {
        let (b, h) = (base_dir.path().to_path_buf(), root.clone());
        tokio::task::spawn_blocking(move || rebut_planner::plan(&b, &h)).await??
    };

    let url = format!("file://{}", root.display());
    let pr = PullRequest {
        repo: RepoId {
            owner: "local".into(),
            name: root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        },
        number: 0,
        base_sha: base_sha.clone(),
        head_sha: head_sha.clone(),
        head_clone_url: url.clone(),
        base_clone_url: url,
        author: "local".into(),
        body: String::new(),
    };
    let executor = LocalProcessExecutor::insecure_for_development(MapSource(BTreeMap::from([
        (base_sha.clone(), base_dir.path().to_path_buf()),
        (head_sha.clone(), root.clone()),
    ])));
    let ctx = EngineContext {
        pr: pr.clone(),
        intent,
        policy: policy.clone(),
        plan: plan.clone(),
        seed: Some(seed),
        sealed_specs: vec![],
        executor: Arc::new(executor),
    };

    let wanted = opts.engines.unwrap_or_else(|| policy.engines.clone());
    let mut engines: Vec<Arc<dyn Engine>> = Vec::new();
    for kind in &wanted {
        match kind {
            EngineKind::Differential => engines.push(Arc::new(DifferentialEngine::new())),
            // Challenges come from the base tree, never from the branch.
            EngineKind::Challenges => engines.push(Arc::new(ChallengesEngine::from_base_checkout(
                base_dir.path(),
            )?)),
            other => tracing::info!(engine = %other, "not available locally in phase 1; skipped"),
        }
    }

    let mut findings = Vec::new();
    let mut inconclusive = Vec::new();
    let mut engines_run = Vec::new();
    let (mut unreproduced, mut vm_seconds) = (0, 0);
    for engine in engines {
        engines_run.push(engine.kind());
        match engine.run(&ctx).await {
            Ok(report) => {
                findings.extend(report.findings);
                unreproduced += report.unreproduced.len();
                vm_seconds += report.vm_seconds;
                if let Some(r) = report.inconclusive {
                    inconclusive.push(format!("{}: {r}", engine.kind()));
                }
            }
            Err(e) => inconclusive.push(format!("{}: {e:#}", engine.kind())),
        }
    }
    let actionable = findings.iter().any(Finding::is_actionable);
    let verdict = Verdict {
        pr,
        seed: Some(seed),
        engines_run,
        findings,
        inconclusive_reason: (!inconclusive.is_empty() && !actionable)
            .then(|| inconclusive.join("; ")),
        mode: policy.mode,
    };
    Ok(LocalRun {
        base_sha,
        head_sha,
        synthetic_head: dirty,
        beacon,
        offline_seed,
        plan,
        verdict,
        unreproduced,
        vm_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rebut_core::VerdictStatus;

    fn run_git(dir: &Path, args: &[&str]) {
        let out = Command::new("git")
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
        assert!(out.status.success(), "{out:?}");
    }

    fn write(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    /// End to end on a real zero-dependency crate: a "refactor" that changes
    /// behavior is caught by the differential engine, with a reproduction.
    #[tokio::test]
    async fn catches_a_green_refactor_that_changes_behavior() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write(
            d,
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
        );
        write(
            d,
            "src/lib.rs",
            "pub fn clamp_add(a: u8, b: u8) -> u8 { a.saturating_add(b) }\n\n\
             #[cfg(test)]\nmod tests {\n    #[test]\n    fn small() { assert_eq!(super::clamp_add(1, 2), 3); }\n}\n",
        );
        // Commit the lockfile so `--locked` works in both trees.
        let st = Command::new("cargo")
            .args(["generate-lockfile", "--offline", "--manifest-path"])
            .arg(d.join("Cargo.toml"))
            .status()
            .unwrap();
        assert!(st.success());
        write(d, ".gitignore", "/target\n");
        run_git(d, &["init", "-q", "-b", "main"]);
        run_git(d, &["add", "."]);
        run_git(d, &["commit", "-q", "-m", "base"]);
        run_git(d, &["checkout", "-q", "-b", "pr"]);
        // Tests still pass (1 + 2 == 3), but 200 + 100 now wraps.
        write(
            d,
            "src/lib.rs",
            "pub fn clamp_add(a: u8, b: u8) -> u8 { a.wrapping_add(b) }\n\n\
             #[cfg(test)]\nmod tests {\n    #[test]\n    fn small() { assert_eq!(super::clamp_add(1, 2), 3); }\n}\n",
        );
        write(d, ".rebut/intent.toml", "kind = \"refactor\"\n");
        run_git(d, &["add", "."]);
        run_git(d, &["commit", "-q", "-m", "refactor"]);

        let run = verify_local(
            d,
            LocalOptions {
                base: "main".into(),
                beacon: None,
                engines: Some(vec![EngineKind::Differential]),
            },
        )
        .await
        .unwrap();

        assert!(!run.synthetic_head);
        assert!(run.offline_seed);
        assert_eq!(run.plan.changed_functions[0].path, "demo::clamp_add");
        assert_eq!(
            run.verdict.status(),
            VerdictStatus::Flagged,
            "{:#?}",
            run.verdict
        );
        let f = &run.verdict.findings[0];
        assert_eq!(f.category, "behavior-divergence");
        assert!(f.is_actionable());
        assert_ne!(f.reproduction().expected(), f.reproduction().observed());
    }
}
