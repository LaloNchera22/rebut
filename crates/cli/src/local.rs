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
use rebut_adversary::{AdversaryConfig, AdversaryEngine, HypothesisGenerator, Oracle};
use rebut_challenges::drand::{self, BeaconSource};
use rebut_challenges::ChallengesEngine;
use rebut_core::{
    ChangeKind, CommitSha, DiffScope, Digest, DrandBeacon, Engine, EngineContext, EngineKind,
    ExecutionRequest, Finding, ImpactPlan, IntentManifest, Policy, PullRequest, RepoId, Seed,
    Verdict, GENERATOR_VERSION,
};
use rebut_differential::{DifferentialConfig, DifferentialEngine};
use rebut_fabric::{LocalProcessExecutor, SourceProvider};
use serde::Serialize;

#[derive(Default)]
pub struct LocalOptions {
    /// Branch or commit to compare against; the merge base with `HEAD` is used.
    pub base: String,
    /// Where to get the drand beacon. `None` = offline: a local, clearly
    /// labelled pseudo-beacon derived from the head commit.
    pub beacon: Option<Arc<dyn BeaconSource>>,
    /// Restrict to these engines (default: the base policy's list).
    pub engines: Option<Vec<EngineKind>>,
    /// Compare every public function, not only the changed ones (automatic
    /// when the diff only touches dependencies).
    pub all_public: bool,
    /// Cap on the functions the differential engine compares (default: 32
    /// changed, or 200 public).
    pub max_functions: Option<usize>,
    /// Rival agent, off unless set. Its hypotheses are replayed like any
    /// other input; only reproductions become findings (ADR-6).
    pub adversary: Option<Arc<dyn HypothesisGenerator>>,
}

/// `rebut verify` flags for the rival agent. Off unless one is given.
#[derive(Debug, Default, clap::Args)]
pub struct AdversaryArgs {
    /// Rival agent proposing inputs that might break the change (off by
    /// default): `ollama[:model]`, `openai-compat` or `anthropic`
    /// [env: REBUT_ADVERSARY].
    #[arg(long, value_name = "PROVIDER")]
    pub adversary: Option<String>,
    /// Endpoint of an OpenAI-compatible server, e.g. http://localhost:8080/v1.
    #[arg(long, env = "REBUT_ADVERSARY_URL", value_name = "URL")]
    pub adversary_url: Option<String>,
    /// Model for the rival agent (ollama default: qwen2.5-coder:7b).
    #[arg(long, env = "REBUT_ADVERSARY_MODEL", value_name = "MODEL")]
    pub adversary_model: Option<String>,
}

impl AdversaryArgs {
    /// The configured generator and a one-line description, or `None` when
    /// the rival agent is off. A misconfiguration given by flag is an error;
    /// one that only comes from `REBUT_ADVERSARY` is pushed to `warnings`
    /// and the rival agent stays off, so a stray environment variable can't
    /// break `verify`.
    pub fn generator(
        &self,
        warnings: &mut Vec<String>,
    ) -> anyhow::Result<Option<(Arc<dyn HypothesisGenerator>, String)>> {
        let (spec, from_flag) = match &self.adversary {
            Some(s) => (s.clone(), true),
            None => match std::env::var("REBUT_ADVERSARY") {
                Ok(s) => (s, false),
                Err(_) => return Ok(None),
            },
        };
        let built = AdversaryConfig::parse(
            &spec,
            self.adversary_url.clone(),
            self.adversary_model.clone(),
        )
        .and_then(|c| c.map(|c| Ok((c.build()?, c.describe()))).transpose());
        match built {
            Err(e) if !from_flag => {
                warnings.push(format!(
                    "REBUT_ADVERSARY={spec}: {e:#}; continuing without the rival agent"
                ));
                Ok(None)
            }
            other => other,
        }
    }
}

/// What the differential engine compares with [`DiffScope::AllPublic`].
#[derive(Debug, Serialize)]
pub struct PublicScope {
    /// Why every public function is compared.
    pub reason: String,
    /// Functions compared.
    pub compared: usize,
    /// Public functions no harness can call (unsupported signatures).
    pub skipped: usize,
    /// Harnessable functions over the cap, not compared.
    pub truncated: usize,
    pub max_functions: usize,
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
    /// Set when the plan compares every public function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_scope: Option<PublicScope>,
    pub verdict: Verdict,
    /// Hypotheses that could not be reproduced (never findings, ADR-6).
    pub unreproduced: usize,
    pub vm_seconds: u64,
    /// Non-fatal problems, e.g. the rival agent's model server is down.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl LocalRun {
    /// One-line summary of the plan, e.g. `plan: 2 changed fn(s), 3 test(s)`
    /// or `plan: dependency change, comparing 37 public fn(s) (5 skipped:
    /// unsupported signatures), 12 test(s), full suite`.
    pub fn plan_line(&self) -> String {
        let p = &self.plan;
        let head = match &self.public_scope {
            None => format!("{} changed fn(s)", p.changed_functions.len()),
            Some(s) => {
                let mut notes = Vec::new();
                if s.skipped > 0 {
                    notes.push(format!("{} skipped: unsupported signatures", s.skipped));
                }
                if s.truncated > 0 {
                    notes.push(format!(
                        "truncated: {} more over the cap of {} (--max-functions)",
                        s.truncated, s.max_functions
                    ));
                }
                let notes = if notes.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", notes.join("; "))
                };
                format!("{}, comparing {} public fn(s){notes}", s.reason, s.compared)
            }
        };
        format!(
            "plan: {head}, {} test(s){}",
            p.tests.len(),
            if p.widen_to_full_suite {
                ", full suite"
            } else {
                ""
            }
        )
    }
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
        let popts = rebut_planner::PlanOptions {
            all_public: opts.all_public,
        };
        tokio::task::spawn_blocking(move || rebut_planner::plan_with(&b, &h, &popts)).await??
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

    let mut config = DifferentialConfig::default();
    if let Some(n) = opts.max_functions {
        config.max_functions = n;
        config.max_public_functions = n;
    }
    let differential = DifferentialEngine::with_config(config.clone());
    let public_scope = (plan.scope == DiffScope::AllPublic).then(|| {
        let sel = differential.select(&ctx);
        PublicScope {
            reason: if opts.all_public {
                "all public fns (--all-public)".into()
            } else {
                "dependency change".into()
            },
            compared: sel.targets.len(),
            skipped: sel.skipped,
            truncated: sel.truncated,
            max_functions: config.max_public_functions,
        }
    });

    let wanted = opts.engines.unwrap_or_else(|| policy.engines.clone());
    let mut engines: Vec<Arc<dyn Engine>> = Vec::new();
    for kind in &wanted {
        match kind {
            EngineKind::Differential => engines.push(Arc::new(differential.clone())),
            // Challenges come from the base tree, never from the branch.
            EngineKind::Challenges => engines.push(Arc::new(ChallengesEngine::from_base_checkout(
                base_dir.path(),
            )?)),
            // Opt-in below, never from the policy alone.
            EngineKind::Adversary => {}
            other => tracing::info!(engine = %other, "not available locally in phase 1; skipped"),
        }
    }
    let mut warnings = Vec::new();
    if let Some(generator) = opts.adversary {
        // An extra: an unreachable model server never fails the run.
        match generator.ready().await {
            Err(e) => warnings.push(format!(
                "rival agent unavailable, continuing without it: {e:#}"
            )),
            Ok(()) => {
                let mut engine = AdversaryEngine::new(generator);
                if ctx.intent.kind == ChangeKind::Refactor {
                    engine.adversary.oracle = Oracle::Differential;
                }
                engines.push(Arc::new(engine));
            }
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
        public_scope,
        verdict,
        unreproduced,
        vm_seconds,
        warnings,
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
                ..Default::default()
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

    /// A dependency update (simulated offline by repointing a path
    /// dependency to a newer copy) touches only Cargo.toml and Cargo.lock.
    /// No function of the crate changed, yet one now behaves differently:
    /// the plan switches to all public functions and the divergence is
    /// reported.
    #[tokio::test]
    async fn dependency_update_that_changes_behavior_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let manifest = |helper: &str| {
            format!(
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
                 [dependencies]\nhelper = {{ path = \"vendor/{helper}\" }}\n\n[workspace]\n"
            )
        };
        let helper = |version: &str, body: &str| {
            (
                format!(
                    "[package]\nname = \"helper\"\nversion = \"{version}\"\nedition = \"2021\"\n"
                ),
                format!("pub fn scale(x: u32) -> u32 {{ {body} }}\n"),
            )
        };
        let lock = |d: &Path| {
            let st = Command::new("cargo")
                .args(["generate-lockfile", "--offline", "--manifest-path"])
                .arg(d.join("Cargo.toml"))
                .status()
                .unwrap();
            assert!(st.success());
        };
        for (name, version, body) in [
            ("helper-1.0.0", "1.0.0", "x.saturating_mul(3)"),
            ("helper-1.0.1", "1.0.1", "x.wrapping_mul(3)"),
        ] {
            let (m, src) = helper(version, body);
            write(d, &format!("vendor/{name}/Cargo.toml"), &m);
            write(d, &format!("vendor/{name}/src/lib.rs"), &src);
        }
        write(d, "Cargo.toml", &manifest("helper-1.0.0"));
        write(
            d,
            "src/lib.rs",
            "pub fn triple(x: u32) -> u32 { helper::scale(x) }\n\
             pub fn label(s: &str) -> usize { s.len() }\n\
             pub fn same<T>(x: T) -> T { x }\n",
        );
        lock(d);
        write(d, ".gitignore", "/target\n");
        run_git(d, &["init", "-q", "-b", "main"]);
        run_git(d, &["add", "."]);
        run_git(d, &["commit", "-q", "-m", "base"]);
        run_git(d, &["checkout", "-q", "-b", "deps"]);
        write(d, "Cargo.toml", &manifest("helper-1.0.1"));
        lock(d);
        run_git(d, &["add", "."]);
        run_git(d, &["commit", "-q", "-m", "cargo update"]);

        let run = verify_local(
            d,
            LocalOptions {
                base: "main".into(),
                engines: Some(vec![EngineKind::Differential]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(run.plan.changed_files, vec!["Cargo.lock", "Cargo.toml"]);
        assert!(run.plan.changed_functions.is_empty());
        assert_eq!(run.plan.scope, DiffScope::AllPublic);
        assert_eq!(
            run.plan_line(),
            "plan: dependency change, comparing 2 public fn(s) \
             (1 skipped: unsupported signatures), 0 test(s), full suite"
        );
        assert_eq!(
            run.verdict.status(),
            VerdictStatus::Flagged,
            "{:#?}",
            run.verdict
        );
        assert!(!run.verdict.findings.is_empty());
        for f in &run.verdict.findings {
            assert_eq!(f.category, "behavior-divergence");
            assert_eq!(f.target.as_deref(), Some("demo::triple"));
            assert!(f.is_actionable());
            assert_ne!(f.reproduction().expected(), f.reproduction().observed());
        }
    }
}

#[cfg(test)]
mod adversary_tests {
    use super::*;
    use rebut_core::{Hypothesis, HypothesisSource, VerdictStatus};

    fn git_in(dir: &Path, args: &[&str]) {
        let st = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@t"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .status()
            .unwrap();
        assert!(st.success());
    }

    /// Insists a changed function is broken, with no input that shows it.
    struct Insistent;

    #[async_trait::async_trait]
    impl HypothesisGenerator for Insistent {
        async fn propose(&self, _: &EngineContext) -> anyhow::Result<Vec<Hypothesis>> {
            Ok(vec![Hypothesis {
                source: HypothesisSource::Llm,
                target: "demo::f".into(),
                claim: "definitely overflows".into(),
                candidate_input: Some(b"\xFF".to_vec()),
            }])
        }
    }

    /// An unreachable model server only warns, and a hypothesis that is
    /// never reproduced is not a finding (no other engine runs here, and
    /// `f(u8, u8)` has no harness, so nothing is built).
    #[tokio::test]
    async fn rival_agent_is_an_extra_never_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(
            d.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(
            d.join("src/lib.rs"),
            "pub fn f(a: u8, b: u8) -> u8 { a + b }\n",
        )
        .unwrap();
        git_in(d, &["init", "-q", "-b", "main"]);
        git_in(d, &["add", "."]);
        git_in(d, &["commit", "-q", "-m", "base"]);
        git_in(d, &["checkout", "-q", "-b", "pr"]);
        std::fs::write(
            d.join("src/lib.rs"),
            "pub fn f(a: u8, b: u8) -> u8 { b + a }\n",
        )
        .unwrap();
        git_in(d, &["commit", "-q", "-am", "head"]);

        let opts = |adversary| LocalOptions {
            base: "main".into(),
            engines: Some(vec![]),
            adversary,
            ..Default::default()
        };
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let down =
            rebut_adversary::OpenAiCompatGenerator::new(format!("http://127.0.0.1:{port}/v1"), "m");
        let run = verify_local(d, opts(Some(Arc::new(down)))).await.unwrap();
        assert!(
            run.warnings[0].contains("rival agent unavailable"),
            "{:?}",
            run.warnings
        );
        assert!(run.verdict.engines_run.is_empty());

        let run = verify_local(d, opts(Some(Arc::new(Insistent))))
            .await
            .unwrap();
        assert!(run.warnings.is_empty());
        assert_eq!(run.verdict.engines_run, vec![EngineKind::Adversary]);
        assert_eq!(run.plan.changed_functions[0].path, "demo::f");
        assert_eq!(run.unreproduced, 1);
        assert!(run.verdict.findings.is_empty());
        assert_ne!(run.verdict.status(), VerdictStatus::Flagged);
    }

    #[test]
    fn misconfiguration_fails_by_flag_but_only_warns_from_env() {
        let mut warnings = vec![];
        assert!(AdversaryArgs::default()
            .generator(&mut warnings)
            .unwrap()
            .is_none());
        let flag = AdversaryArgs {
            adversary: Some("openai-compat".into()),
            ..Default::default()
        };
        assert!(flag.generator(&mut warnings).is_err());
        let ok = AdversaryArgs {
            adversary: Some("ollama:llama3.1:8b".into()),
            ..Default::default()
        };
        let (_, what) = ok.generator(&mut warnings).unwrap().unwrap();
        assert_eq!(what, "ollama llama3.1:8b at http://localhost:11434/v1");
        assert!(warnings.is_empty());

        // The only test touching this variable.
        std::env::set_var("REBUT_ADVERSARY", "openai-compat");
        let from_env = AdversaryArgs::default().generator(&mut warnings);
        std::env::remove_var("REBUT_ADVERSARY");
        assert!(from_env.unwrap().is_none());
        assert!(warnings[0].starts_with("REBUT_ADVERSARY=openai-compat"));
    }
}
