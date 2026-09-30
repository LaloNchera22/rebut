//! Turns a queued job into a signed, logged, published verdict.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use time::OffsetDateTime;
use tracing::Instrument;
use uuid::Uuid;
use verifier_core::{
    Budget, Digest, DrandBeacon, Engine, EngineContext, EngineKind, ExecutionRequest,
    ExecutionResult, Executor, Finding, ImpactPlan, IntentManifest, Policy, PullRequest, RepoId,
    Seed, Verdict, VerdictStatus, GENERATOR_VERSION,
};
use verifier_receipts::{ReceiptContext, Signer, TransparencyLog};

use crate::forge::{check_run, Forge, ReceiptRef};
use crate::queue::Job;
use crate::store::{RunRecord, Store};

pub const POLICY_PATH: &str = ".verifier/policy.toml";
pub const INTENT_PATH: &str = ".verifier/intent.toml";
pub const VERIFIER_VERSION: &str = concat!("verifier-control/", env!("CARGO_PKG_VERSION"));

/// Produces the impact plan for a PR. The real implementation is the planner
/// crate; the control plane only depends on this seam.
#[async_trait::async_trait]
pub trait Planner: Send + Sync {
    async fn plan(&self, pr: &PullRequest) -> anyhow::Result<ImpactPlan>;
}

/// Public randomness for seeds (ADR-7): the first drand round published after
/// `after`.
#[async_trait::async_trait]
pub trait BeaconSource: Send + Sync {
    async fn round_after(&self, after: OffsetDateTime) -> anyhow::Result<DrandBeacon>;
}

/// The maintainer's sealed challenge specs, stored outside the repository.
#[async_trait::async_trait]
pub trait SealedSpecSource: Send + Sync {
    async fn specs(&self, repo: &RepoId) -> anyhow::Result<Vec<String>>;
}

pub struct NoSealedSpecs;

#[async_trait::async_trait]
impl SealedSpecSource for NoSealedSpecs {
    async fn specs(&self, _: &RepoId) -> anyhow::Result<Vec<String>> {
        Ok(vec![])
    }
}

pub struct Orchestrator {
    pub engines: Vec<Arc<dyn Engine>>,
    pub executor: Arc<dyn Executor>,
    pub store: Arc<dyn Store>,
    pub signer: Arc<dyn Signer>,
    pub log: Arc<dyn TransparencyLog>,
    pub forge: Arc<dyn Forge>,
    pub planner: Arc<dyn Planner>,
    pub beacon: Arc<dyn BeaconSource>,
    pub sealed: Arc<dyn SealedSpecSource>,
    /// Base URL of the public API, used to link receipts from check runs.
    pub public_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Processed {
    pub run_id: Uuid,
    pub status: VerdictStatus,
    pub log_index: u64,
}

impl Orchestrator {
    pub async fn process(&self, job: &Job) -> anyhow::Result<Processed> {
        let span =
            tracing::info_span!("job", id = %job.id, repo = %job.pr.repo, pr = job.pr.number);
        self.process_inner(job).instrument(span).await
    }

    async fn process_inner(&self, job: &Job) -> anyhow::Result<Processed> {
        let pr = &job.pr;

        // Policy comes from the BASE commit: a PR must not relax its own checks.
        let (policy, policy_error) = match self
            .forge
            .file_at(&pr.repo, &pr.base_sha, POLICY_PATH)
            .await?
        {
            None => (Policy::default(), None),
            Some(text) => match Policy::from_toml(&text) {
                Ok(p) => (p, None),
                Err(e) => (
                    Policy::default(),
                    Some(format!("invalid {POLICY_PATH} on base: {e}")),
                ),
            },
        };
        let policy_digest = Digest::of_parts(&[
            b"verifier/policy/v1",
            &serde_json::to_vec(&policy).expect("policy serializes"),
        ]);

        let intent = self.intent(pr).await?;
        let beacon = match self.beacon.round_after(job.enqueued_at).await {
            Ok(b) => Some(b),
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "no beacon; running without a seed");
                None
            }
        };
        let seed = beacon
            .as_ref()
            .map(|b| Seed::derive(&pr.head_sha, b, GENERATOR_VERSION));

        let metered = Arc::new(MeteredExecutor::new(
            self.executor.clone(),
            policy.budget.clone(),
        ));
        let mut run = EngineRun::default();
        match policy_error {
            Some(reason) => run.inconclusive.push(reason),
            None => {
                self.run_engines(pr, intent, &policy, seed, metered.clone(), &mut run)
                    .await
            }
        }

        let actionable = run.findings.iter().any(Finding::is_actionable);
        let verdict = Verdict {
            pr: pr.clone(),
            seed,
            engines_run: run.engines_run,
            findings: run.findings,
            inconclusive_reason: (!run.inconclusive.is_empty() && !actionable)
                .then(|| run.inconclusive.join("; ")),
            mode: policy.mode,
        };
        let status = verdict.status();

        let ctx = ReceiptContext {
            policy_digest,
            environment_digests: metered.environments(),
            beacon,
            generator_version: GENERATOR_VERSION.to_string(),
            verifier_version: VERIFIER_VERSION.to_string(),
        };
        let envelope = verifier_receipts::sign_verdict(&verdict, &ctx, self.signer.as_ref())
            .await
            .context("signing receipt")?;
        let entry = self
            .log
            .append(&envelope)
            .await
            .context("appending to log")?;

        let run_id = Uuid::new_v4();
        let report = verdict.for_contributor();
        let mode = verdict.mode;
        self.store
            .save_run(&RunRecord {
                id: run_id,
                job_id: job.id,
                verdict,
                envelope,
                log_index: entry.index,
                created_at: OffsetDateTime::now_utc(),
            })
            .await
            .context("storing run")?;

        let receipt = ReceiptRef {
            id: run_id,
            log_index: entry.index,
            url: self
                .public_url
                .as_ref()
                .map(|u| format!("{}/v1/receipts/{run_id}", u.trim_end_matches('/'))),
        };
        self.forge
            .publish_check_run(
                &pr.repo,
                &check_run(&report, mode, pr.head_sha.clone(), Some(&receipt)),
            )
            .await
            .context("publishing check run")?;

        tracing::info!(?status, log_index = entry.index, "verdict published");
        Ok(Processed {
            run_id,
            status,
            log_index: entry.index,
        })
    }

    /// Head `.verifier/intent.toml` wins over a block in the PR body. An
    /// unparsable manifest falls back to `Unspecified`, which claims nothing.
    async fn intent(&self, pr: &PullRequest) -> anyhow::Result<IntentManifest> {
        let parsed = match self
            .forge
            .file_at(&pr.repo, &pr.head_sha, INTENT_PATH)
            .await?
        {
            Some(text) => Some(IntentManifest::from_toml(&text)),
            None => IntentManifest::from_pr_body(&pr.body),
        };
        Ok(match parsed {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                tracing::warn!(error = %e, "invalid intent manifest; treating as unspecified");
                IntentManifest::default()
            }
            None => IntentManifest::default(),
        })
    }

    async fn run_engines(
        &self,
        pr: &PullRequest,
        intent: IntentManifest,
        policy: &Policy,
        seed: Option<Seed>,
        executor: Arc<MeteredExecutor>,
        run: &mut EngineRun,
    ) {
        let plan = match self.planner.plan(pr).await {
            Ok(p) => p,
            Err(e) => {
                run.inconclusive.push(format!("planning failed: {e:#}"));
                return;
            }
        };
        let sealed_specs = match self.sealed.specs(&pr.repo).await {
            Ok(specs) => committed_specs(specs, policy),
            Err(e) => {
                run.inconclusive
                    .push(format!("sealed specs unavailable: {e:#}"));
                return;
            }
        };
        let ctx = EngineContext {
            pr: pr.clone(),
            intent,
            policy: policy.clone(),
            plan,
            seed,
            sealed_specs,
            executor: executor.clone(),
        };

        for kind in &policy.engines {
            let remaining = executor.remaining_secs();
            if remaining == 0 {
                run.inconclusive
                    .push(format!("VM budget exhausted before the {kind} engine"));
                break;
            }
            let Some(engine) = self.engines.iter().find(|e| e.kind() == *kind) else {
                run.inconclusive
                    .push(format!("{kind} engine is not available"));
                continue;
            };
            // Wall-clock bound; VM-seconds are enforced by the metered executor.
            let outcome =
                tokio::time::timeout(Duration::from_secs(remaining), engine.run(&ctx)).await;
            match outcome {
                Ok(Ok(report)) => {
                    executor.charge_reported(report.vm_seconds);
                    if !report.unreproduced.is_empty() {
                        tracing::info!(engine = %kind, n = report.unreproduced.len(),
                            "unreproduced hypotheses discarded");
                    }
                    if let Some(reason) = report.inconclusive {
                        run.inconclusive.push(format!("{kind}: {reason}"));
                    }
                    run.findings.extend(report.findings);
                    run.engines_run.push(*kind);
                }
                // The mutation engine only yields hypotheses (ADR-6); its
                // failing can't hide a finding, so it never costs the
                // contributor an inconclusive verdict.
                Ok(Err(e)) if *kind == EngineKind::Mutation => {
                    tracing::warn!(error = %format!("{e:#}"), "mutation engine failed");
                }
                Err(_) if *kind == EngineKind::Mutation => {
                    tracing::warn!("mutation engine ran out of VM budget");
                }
                Ok(Err(e)) => run
                    .inconclusive
                    .push(format!("{kind} engine failed: {e:#}")),
                Err(_) => run
                    .inconclusive
                    .push(format!("VM budget exhausted during the {kind} engine")),
            }
        }
    }
}

#[derive(Default)]
struct EngineRun {
    engines_run: Vec<EngineKind>,
    findings: Vec<Finding>,
    inconclusive: Vec<String>,
}

/// Keep only specs whose hash is committed in the base policy.
fn committed_specs(specs: Vec<String>, policy: &Policy) -> Vec<String> {
    specs
        .into_iter()
        .filter(|s| {
            let ok = policy
                .sealed_commitments
                .contains(&Digest::of(s.as_bytes()));
            if !ok {
                tracing::warn!("dropping sealed spec without a commitment in the base policy");
            }
            ok
        })
        .collect()
}

/// Wraps the fabric: clamps every request to the policy budget, refuses new
/// runs once the PR's VM-seconds are spent, and records environment digests
/// for the receipt.
pub struct MeteredExecutor {
    inner: Arc<dyn Executor>,
    budget: Budget,
    measured_ms: AtomicU64,
    reported_secs: AtomicU64,
    environments: Mutex<BTreeSet<Digest>>,
}

impl MeteredExecutor {
    pub fn new(inner: Arc<dyn Executor>, budget: Budget) -> Self {
        MeteredExecutor {
            inner,
            budget,
            measured_ms: AtomicU64::new(0),
            reported_secs: AtomicU64::new(0),
            environments: Mutex::new(BTreeSet::new()),
        }
    }

    /// VM-seconds spent: the larger of what we measured and what engines reported.
    pub fn used_secs(&self) -> u64 {
        let measured = self.measured_ms.load(Ordering::Relaxed).div_ceil(1000);
        measured.max(self.reported_secs.load(Ordering::Relaxed))
    }

    pub fn remaining_secs(&self) -> u64 {
        self.budget.pr_vm_seconds.saturating_sub(self.used_secs())
    }

    fn charge_reported(&self, secs: u64) {
        self.reported_secs.fetch_add(secs, Ordering::Relaxed);
    }

    pub fn environments(&self) -> Vec<Digest> {
        self.environments
            .lock()
            .expect("env lock")
            .iter()
            .copied()
            .collect()
    }
}

#[async_trait::async_trait]
impl Executor for MeteredExecutor {
    async fn execute(&self, mut req: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
        let remaining = self.remaining_secs();
        if remaining == 0 {
            anyhow::bail!("PR VM budget exhausted");
        }
        req.timeout_secs = req
            .timeout_secs
            .min(self.budget.vm_timeout_secs)
            .min(remaining);
        req.vcpus = req.vcpus.min(self.budget.vcpus);
        req.memory_mib = req.memory_mib.min(self.budget.memory_mib);
        let started = Instant::now();
        let result = self.inner.execute(req).await;
        self.measured_ms
            .fetch_add(started.elapsed().as_millis() as u64, Ordering::Relaxed);
        if let Ok(r) = &result {
            self.environments
                .lock()
                .expect("env lock")
                .insert(r.environment);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forge::{CheckRun, Conclusion};
    use crate::queue::{InMemoryQueue, JobQueue};
    use crate::store::InMemoryStore;
    use std::collections::HashMap;
    use verifier_core::*;
    use verifier_receipts::{verify_envelope, Ed25519Signer, InMemoryLog};

    #[derive(Default)]
    pub struct FakeForge {
        pub files: HashMap<(String, String), String>,
        pub checks: Mutex<Vec<CheckRun>>,
    }

    #[async_trait::async_trait]
    impl Forge for FakeForge {
        async fn file_at(
            &self,
            _: &RepoId,
            commit: &CommitSha,
            path: &str,
        ) -> anyhow::Result<Option<String>> {
            Ok(self
                .files
                .get(&(commit.to_string(), path.to_string()))
                .cloned())
        }
        async fn publish_check_run(&self, _: &RepoId, run: &CheckRun) -> anyhow::Result<()> {
            self.checks.lock().unwrap().push(run.clone());
            Ok(())
        }
    }

    struct FakeExecutor;

    #[async_trait::async_trait]
    impl Executor for FakeExecutor {
        async fn execute(&self, req: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
            let outcomes = vec![StepOutcome {
                step_index: 0,
                exit_code: Some(101),
                timed_out: false,
                stdout: b"SEALED-OUTPUT".to_vec(),
                stderr: vec![],
                duration_ms: 5,
            }];
            Ok(ExecutionResult {
                request_id: req.id,
                transcript: ExecutionResult::compute_transcript(&req, &outcomes),
                outcomes,
                environment: Digest::of(b"rootfs-v1"),
            })
        }
    }

    /// Runs one harness through the executor and reports a sealed finding.
    struct SealedChallengeEngine;

    #[async_trait::async_trait]
    impl Engine for SealedChallengeEngine {
        fn kind(&self) -> EngineKind {
            EngineKind::Challenges
        }
        async fn run(&self, ctx: &EngineContext) -> anyhow::Result<EngineReport> {
            assert!(ctx.seed.is_some());
            let req = ExecutionRequest {
                id: Uuid::new_v4(),
                repo_url: ctx.pr.head_clone_url.clone(),
                commit: ctx.pr.head_sha.clone(),
                steps: vec![Step::Harness {
                    name: "h".into(),
                    source: String::new(),
                    input: b"SEALED-INPUT".to_vec(),
                }],
                timeout_secs: 10_000,
                vcpus: 64,
                memory_mib: 1 << 20,
                sealed: true,
                env: Default::default(),
            };
            let result = ctx.executor.execute(req).await?;
            let repro = Reproduction::confirm(
                &result,
                0,
                b"SEALED-INPUT".to_vec(),
                b"exit:Some(0)\n".to_vec(),
            )
            .unwrap();
            Ok(EngineReport {
                findings: vec![Finding::new(
                    EngineKind::Challenges,
                    "integer-overflow",
                    "overflow on SEALED-INPUT",
                    Visibility::Sealed,
                    Some("lib::parse".into()),
                    false,
                    repro,
                )],
                vm_seconds: 10,
                ..Default::default()
            })
        }
    }

    /// Reports nothing but burns `vm_seconds`.
    struct BurnEngine(EngineKind, u64);

    #[async_trait::async_trait]
    impl Engine for BurnEngine {
        fn kind(&self) -> EngineKind {
            self.0
        }
        async fn run(&self, _: &EngineContext) -> anyhow::Result<EngineReport> {
            Ok(EngineReport {
                vm_seconds: self.1,
                ..Default::default()
            })
        }
    }

    struct FakePlanner;

    #[async_trait::async_trait]
    impl Planner for FakePlanner {
        async fn plan(&self, _: &PullRequest) -> anyhow::Result<ImpactPlan> {
            Ok(ImpactPlan {
                widen_to_full_suite: true,
                ..Default::default()
            })
        }
    }

    struct FakeBeacon;

    #[async_trait::async_trait]
    impl BeaconSource for FakeBeacon {
        async fn round_after(&self, _: OffsetDateTime) -> anyhow::Result<DrandBeacon> {
            Ok(DrandBeacon {
                chain_hash: "52db9ba7".into(),
                round: 1234,
                randomness: "ab".repeat(32),
                signature: "cd".into(),
            })
        }
    }

    struct Fixture {
        orch: Orchestrator,
        forge: Arc<FakeForge>,
        store: Arc<InMemoryStore>,
        log: Arc<InMemoryLog>,
        signer: Arc<Ed25519Signer>,
    }

    fn fixture(engines: Vec<Arc<dyn Engine>>, files: &[(char, &str, &str)]) -> Fixture {
        let mut forge = FakeForge::default();
        for (commit, path, text) in files {
            forge.files.insert(
                (commit.to_string().repeat(40), path.to_string()),
                text.to_string(),
            );
        }
        let forge = Arc::new(forge);
        let store = Arc::new(InMemoryStore::default());
        let signer = Arc::new(Ed25519Signer::generate());
        let log = Arc::new(InMemoryLog::new(signer.clone()));
        let orch = Orchestrator {
            engines,
            executor: Arc::new(FakeExecutor),
            store: store.clone(),
            signer: signer.clone(),
            log: log.clone(),
            forge: forge.clone(),
            planner: Arc::new(FakePlanner),
            beacon: Arc::new(FakeBeacon),
            sealed: Arc::new(NoSealedSpecs),
            public_url: Some("https://verifier.example".into()),
        };
        Fixture {
            orch,
            forge,
            store,
            log,
            signer,
        }
    }

    async fn job() -> Job {
        let q = InMemoryQueue::default();
        q.enqueue(crate::queue::tests::pr(4, 'b')).await.unwrap();
        q.claim("w").await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn flagged_mark_mode_end_to_end() {
        let fx = fixture(
            vec![
                Arc::new(SealedChallengeEngine),
                Arc::new(BurnEngine(EngineKind::Differential, 1)),
            ],
            &[],
        );
        let out = fx.orch.process(&job().await).await.unwrap();
        assert_eq!(out.status, VerdictStatus::Flagged);

        // Receipt: signed, logged, provable, sealed bytes absent.
        let runs = fx.store.runs();
        assert_eq!(runs.len(), 1);
        let st = verify_envelope(&runs[0].envelope, &fx.signer.public_key()).unwrap();
        assert_eq!(st.predicate.status, VerdictStatus::Flagged);
        assert_eq!(
            st.predicate
                .seed
                .as_ref()
                .unwrap()
                .drand
                .as_ref()
                .unwrap()
                .round,
            1234
        );
        assert_eq!(
            st.predicate.environment_digests,
            vec![Digest::of(b"rootfs-v1")]
        );
        assert_eq!(
            st.predicate.engines_run,
            vec![EngineKind::Differential, EngineKind::Challenges]
        );
        let payload = String::from_utf8(runs[0].envelope.payload_bytes().unwrap()).unwrap();
        assert!(!payload.contains("SEALED"));
        let entry = fx.log.get(out.log_index).await.unwrap().unwrap();
        entry.verify_inclusion().unwrap();
        entry
            .signed_tree_head
            .verify(&fx.signer.public_key())
            .unwrap();

        // Check run: neutral in mark mode, category only.
        let checks = fx.forge.checks.lock().unwrap();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].conclusion, Conclusion::Neutral);
        assert!(!checks[0].summary.contains("SEALED"));
        assert!(checks[0].summary.contains("category `integer-overflow`"));
        assert!(checks[0]
            .summary
            .contains(&format!("verifier.example/v1/receipts/{}", out.run_id)));
    }

    #[tokio::test]
    async fn policy_comes_from_base_not_head() {
        let block = "mode = \"block\"\nengines = [\"challenges\"]\n";
        let mark = "mode = \"mark\"\nengines = [\"challenges\"]\n";
        // Base says block; the PR head tries to downgrade to mark.
        let fx = fixture(
            vec![Arc::new(SealedChallengeEngine)],
            &[('a', POLICY_PATH, block), ('b', POLICY_PATH, mark)],
        );
        let out = fx.orch.process(&job().await).await.unwrap();
        assert_eq!(out.status, VerdictStatus::Fail);
        assert_eq!(
            fx.forge.checks.lock().unwrap()[0].conclusion,
            Conclusion::Failure
        );
    }

    #[tokio::test]
    async fn budget_exhaustion_is_inconclusive() {
        let policy = "engines = [\"mutation\", \"differential\"]\n[budget]\nvm_timeout_secs = 60\nvcpus = 1\nmemory_mib = 512\npr_vm_seconds = 100\npublic_challenges = 1\n";
        let fx = fixture(
            vec![
                Arc::new(BurnEngine(EngineKind::Mutation, 100)),
                Arc::new(BurnEngine(EngineKind::Differential, 1)),
            ],
            &[('a', POLICY_PATH, policy)],
        );
        let out = fx.orch.process(&job().await).await.unwrap();
        assert_eq!(out.status, VerdictStatus::Inconclusive);
        let v = &fx.store.runs()[0].verdict;
        assert_eq!(v.engines_run, vec![EngineKind::Mutation]);
        assert!(v
            .inconclusive_reason
            .as_deref()
            .unwrap()
            .contains("budget exhausted before the differential"));
        assert_eq!(
            fx.forge.checks.lock().unwrap()[0].conclusion,
            Conclusion::Neutral
        );
    }

    struct FailingEngine(EngineKind);

    #[async_trait::async_trait]
    impl Engine for FailingEngine {
        fn kind(&self) -> EngineKind {
            self.0
        }
        async fn run(&self, _: &EngineContext) -> anyhow::Result<EngineReport> {
            anyhow::bail!("tool missing in the VM")
        }
    }

    #[tokio::test]
    async fn failing_mutation_engine_is_verdict_neutral() {
        let policy = "engines = [\"mutation\", \"differential\"]\n";
        let fx = fixture(
            vec![
                Arc::new(FailingEngine(EngineKind::Mutation)),
                Arc::new(BurnEngine(EngineKind::Differential, 1)),
            ],
            &[('a', POLICY_PATH, policy)],
        );
        let out = fx.orch.process(&job().await).await.unwrap();
        assert_eq!(out.status, VerdictStatus::Pass);
        let fx = fixture(
            vec![Arc::new(FailingEngine(EngineKind::Formal))],
            &[('a', POLICY_PATH, "engines = [\"formal\"]\n")],
        );
        let out = fx.orch.process(&job().await).await.unwrap();
        assert_eq!(out.status, VerdictStatus::Inconclusive);
    }

    #[tokio::test]
    async fn actionable_findings_dominate_inconclusive_engines() {
        // Differential is requested by default policy but not registered.
        let fx = fixture(vec![Arc::new(SealedChallengeEngine)], &[]);
        let out = fx.orch.process(&job().await).await.unwrap();
        assert_eq!(out.status, VerdictStatus::Flagged);
    }

    #[tokio::test]
    async fn metered_executor_clamps_requests() {
        struct Echo(Mutex<Option<ExecutionRequest>>);
        #[async_trait::async_trait]
        impl Executor for Echo {
            async fn execute(&self, req: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
                *self.0.lock().unwrap() = Some(req.clone());
                FakeExecutor.execute(req).await
            }
        }
        let echo = Arc::new(Echo(Mutex::new(None)));
        let m = MeteredExecutor::new(echo.clone(), Budget::default());
        let req = ExecutionRequest {
            id: Uuid::nil(),
            repo_url: String::new(),
            commit: CommitSha::new("a".repeat(40)).unwrap(),
            steps: vec![],
            timeout_secs: u64::MAX,
            vcpus: u8::MAX,
            memory_mib: u32::MAX,
            sealed: false,
            env: Default::default(),
        };
        m.execute(req.clone()).await.unwrap();
        let seen = echo.0.lock().unwrap().clone().unwrap();
        let b = Budget::default();
        assert_eq!(
            (seen.timeout_secs, seen.vcpus, seen.memory_mib),
            (b.vm_timeout_secs, b.vcpus, b.memory_mib)
        );
        m.charge_reported(b.pr_vm_seconds);
        assert!(m.execute(req).await.is_err());
    }

    #[test]
    fn uncommitted_sealed_specs_are_dropped() {
        let policy = Policy {
            sealed_commitments: vec![Digest::of(b"spec-a")],
            ..Default::default()
        };
        assert_eq!(
            committed_specs(vec!["spec-a".into(), "spec-b".into()], &policy),
            vec!["spec-a".to_string()]
        );
    }

    #[tokio::test]
    async fn workers_drain_queue_and_shut_down() {
        let fx = fixture(vec![Arc::new(SealedChallengeEngine)], &[]);
        let queue = Arc::new(InMemoryQueue::default());
        for n in 1..=3 {
            queue
                .enqueue(crate::queue::tests::pr(n, 'b'))
                .await
                .unwrap();
        }
        let (tx, rx) = tokio::sync::watch::channel(false);
        let workers = tokio::spawn(crate::worker::run_workers(
            queue.clone(),
            Arc::new(fx.orch),
            crate::worker::WorkerConfig {
                workers: 2,
                poll_interval: Duration::from_millis(10),
            },
            rx,
        ));
        tokio::time::timeout(Duration::from_secs(10), async {
            while queue.counts().2 < 3 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("jobs finished");
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), workers)
            .await
            .expect("workers stopped")
            .unwrap();
        assert_eq!(fx.store.runs().len(), 3);
    }
}
