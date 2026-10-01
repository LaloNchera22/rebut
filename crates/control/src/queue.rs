//! The job queue (ADR-3): one row per (repo, PR, head commit).
//!
//! Claiming takes a lease; a worker that dies simply lets the lease expire and
//! another worker picks the job up. Every claim counts as an attempt, so a job
//! that keeps crashing workers ends up `failed` instead of looping forever.

use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Context};
use rebut_core::PullRequest;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub worker: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub id: Uuid,
    pub pr: PullRequest,
    /// When the webhook was first accepted; the drand round is the first one
    /// published after this instant (ADR-7).
    pub enqueued_at: OffsetDateTime,
    /// Claims so far, including the current one.
    pub attempts: u32,
    /// Set on claimed jobs; completion and failure are only accepted from the
    /// lease holder.
    pub lease: Option<Lease>,
}

impl Job {
    fn lease_owner(&self) -> anyhow::Result<&str> {
        match &self.lease {
            Some(l) => Ok(&l.worker),
            None => bail!("job {} was not claimed", self.id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueued {
    Created(Uuid),
    /// A job for the same (repo, PR, head) already exists.
    Duplicate(Uuid),
}

impl Enqueued {
    pub fn id(self) -> Uuid {
        match self {
            Enqueued::Created(id) | Enqueued::Duplicate(id) => id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailOutcome {
    RetryAt(OffsetDateTime),
    /// Attempts exhausted; the job will not run again.
    Dead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
    /// Must exceed the longest expected job (PR budget plus overhead).
    pub lease: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 3,
            base_backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(3600),
            lease: Duration::from_secs(3600),
        }
    }
}

impl RetryPolicy {
    /// Exponential backoff after the `attempts`-th failed attempt.
    pub fn backoff(&self, attempts: u32) -> Duration {
        let factor = 1u32 << attempts.saturating_sub(1).min(16);
        self.base_backoff
            .saturating_mul(factor)
            .min(self.max_backoff)
    }
}

#[async_trait::async_trait]
pub trait JobQueue: Send + Sync {
    async fn enqueue(&self, pr: PullRequest) -> anyhow::Result<Enqueued>;
    async fn claim(&self, worker: &str) -> anyhow::Result<Option<Job>>;
    async fn complete(&self, job: &Job) -> anyhow::Result<()>;
    async fn fail(&self, job: &Job, error: &str) -> anyhow::Result<FailOutcome>;
}

// ---------------------------------------------------------------------------
// In-memory implementation (tests, local runs).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Queued,
    Running,
    Done,
    Failed,
}

struct Entry {
    job: Job,
    state: State,
    run_after: OffsetDateTime,
    last_error: Option<String>,
}

pub struct InMemoryQueue {
    policy: RetryPolicy,
    entries: Mutex<Vec<Entry>>,
    /// Offset added to the wall clock, so tests can expire leases.
    skew: Mutex<time::Duration>,
}

impl InMemoryQueue {
    pub fn new(policy: RetryPolicy) -> Self {
        InMemoryQueue {
            policy,
            entries: Mutex::new(Vec::new()),
            skew: Mutex::new(time::Duration::ZERO),
        }
    }

    /// Move this queue's clock forward.
    pub fn advance(&self, d: Duration) {
        *self.skew.lock().expect("clock lock") += d;
    }

    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc() + *self.skew.lock().expect("clock lock")
    }

    /// Number of jobs in each state: (queued, running, done, failed).
    pub fn counts(&self) -> (usize, usize, usize, usize) {
        let entries = self.entries.lock().expect("queue lock");
        let n = |s| entries.iter().filter(|e| e.state == s).count();
        (
            n(State::Queued),
            n(State::Running),
            n(State::Done),
            n(State::Failed),
        )
    }

    pub fn last_error(&self, id: Uuid) -> Option<String> {
        let entries = self.entries.lock().expect("queue lock");
        entries
            .iter()
            .find(|e| e.job.id == id)
            .and_then(|e| e.last_error.clone())
    }

    fn held<'a>(entries: &'a mut [Entry], job: &Job) -> anyhow::Result<&'a mut Entry> {
        let owner = job.lease_owner()?;
        entries
            .iter_mut()
            .find(|e| {
                e.job.id == job.id
                    && e.state == State::Running
                    && e.job.lease.as_ref().is_some_and(|l| l.worker == owner)
            })
            .with_context(|| format!("lease on job {} lost", job.id))
    }
}

impl Default for InMemoryQueue {
    fn default() -> Self {
        Self::new(RetryPolicy::default())
    }
}

#[async_trait::async_trait]
impl JobQueue for InMemoryQueue {
    async fn enqueue(&self, pr: PullRequest) -> anyhow::Result<Enqueued> {
        let mut entries = self.entries.lock().expect("queue lock");
        if let Some(e) = entries.iter().find(|e| {
            e.job.pr.repo == pr.repo
                && e.job.pr.number == pr.number
                && e.job.pr.head_sha == pr.head_sha
        }) {
            return Ok(Enqueued::Duplicate(e.job.id));
        }
        let now = self.now();
        let id = Uuid::new_v4();
        entries.push(Entry {
            job: Job {
                id,
                pr,
                enqueued_at: now,
                attempts: 0,
                lease: None,
            },
            state: State::Queued,
            run_after: now,
            last_error: None,
        });
        Ok(Enqueued::Created(id))
    }

    async fn claim(&self, worker: &str) -> anyhow::Result<Option<Job>> {
        let now = self.now();
        let mut entries = self.entries.lock().expect("queue lock");
        let expired = |e: &Entry| {
            e.state == State::Running && e.job.lease.as_ref().is_some_and(|l| l.expires_at <= now)
        };
        for e in entries.iter_mut() {
            if expired(e) && e.job.attempts >= self.policy.max_attempts {
                e.state = State::Failed;
                e.job.lease = None;
                e.last_error = Some("lease expired after final attempt".into());
            }
        }
        let next = entries
            .iter_mut()
            .filter(|e| (e.state == State::Queued && e.run_after <= now) || expired(e))
            .min_by_key(|e| e.run_after);
        Ok(next.map(|e| {
            e.state = State::Running;
            e.job.attempts += 1;
            e.job.lease = Some(Lease {
                worker: worker.to_string(),
                expires_at: now + self.policy.lease,
            });
            e.job.clone()
        }))
    }

    async fn complete(&self, job: &Job) -> anyhow::Result<()> {
        let mut entries = self.entries.lock().expect("queue lock");
        let e = Self::held(&mut entries, job)?;
        e.state = State::Done;
        e.job.lease = None;
        Ok(())
    }

    async fn fail(&self, job: &Job, error: &str) -> anyhow::Result<FailOutcome> {
        let now = self.now();
        let mut entries = self.entries.lock().expect("queue lock");
        let e = Self::held(&mut entries, job)?;
        e.job.lease = None;
        e.last_error = Some(error.to_string());
        if e.job.attempts >= self.policy.max_attempts {
            e.state = State::Failed;
            Ok(FailOutcome::Dead)
        } else {
            e.state = State::Queued;
            e.run_after = now + self.policy.backoff(e.job.attempts);
            Ok(FailOutcome::RetryAt(e.run_after))
        }
    }
}

// ---------------------------------------------------------------------------
// Postgres implementation.

pub struct PgQueue {
    pool: PgPool,
    policy: RetryPolicy,
}

impl PgQueue {
    pub fn new(pool: PgPool, policy: RetryPolicy) -> Self {
        PgQueue { pool, policy }
    }
}

#[async_trait::async_trait]
impl JobQueue for PgQueue {
    async fn enqueue(&self, pr: PullRequest) -> anyhow::Result<Enqueued> {
        let repo = pr.repo.to_string();
        let inserted = sqlx::query(
            "INSERT INTO jobs (id, repo, pr_number, head_sha, pr, max_attempts)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (repo, pr_number, head_sha) DO NOTHING
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&repo)
        .bind(pr.number as i64)
        .bind(pr.head_sha.as_str())
        .bind(sqlx::types::Json(&pr))
        .bind(self.policy.max_attempts as i32)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = inserted {
            return Ok(Enqueued::Created(row.try_get("id")?));
        }
        let row =
            sqlx::query("SELECT id FROM jobs WHERE repo = $1 AND pr_number = $2 AND head_sha = $3")
                .bind(&repo)
                .bind(pr.number as i64)
                .bind(pr.head_sha.as_str())
                .fetch_one(&self.pool)
                .await?;
        Ok(Enqueued::Duplicate(row.try_get("id")?))
    }

    async fn claim(&self, worker: &str) -> anyhow::Result<Option<Job>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE jobs SET state = 'failed', lease_owner = NULL, updated_at = now(),
                    last_error = 'lease expired after final attempt'
             WHERE state = 'running' AND lease_expires_at <= now()
               AND attempts >= max_attempts",
        )
        .execute(&mut *tx)
        .await?;
        let candidate = sqlx::query(
            "SELECT id FROM jobs
             WHERE (state = 'queued' AND run_after <= now())
                OR (state = 'running' AND lease_expires_at <= now())
             ORDER BY run_after, created_at
             LIMIT 1
             FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(candidate) = candidate else {
            tx.commit().await?;
            return Ok(None);
        };
        let id: Uuid = candidate.try_get("id")?;
        let row = sqlx::query(
            "UPDATE jobs SET state = 'running', attempts = attempts + 1, lease_owner = $2,
                    lease_expires_at = now() + make_interval(secs => $3), updated_at = now()
             WHERE id = $1
             RETURNING pr, created_at, attempts, lease_expires_at",
        )
        .bind(id)
        .bind(worker)
        .bind(self.policy.lease.as_secs_f64())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        let sqlx::types::Json(pr) = row.try_get::<sqlx::types::Json<PullRequest>, _>("pr")?;
        Ok(Some(Job {
            id,
            pr,
            enqueued_at: row.try_get("created_at")?,
            attempts: row.try_get::<i32, _>("attempts")? as u32,
            lease: Some(Lease {
                worker: worker.to_string(),
                expires_at: row.try_get("lease_expires_at")?,
            }),
        }))
    }

    async fn complete(&self, job: &Job) -> anyhow::Result<()> {
        let done = sqlx::query(
            "UPDATE jobs SET state = 'done', lease_owner = NULL, lease_expires_at = NULL,
                    updated_at = now()
             WHERE id = $1 AND state = 'running' AND lease_owner = $2",
        )
        .bind(job.id)
        .bind(job.lease_owner()?)
        .execute(&self.pool)
        .await?;
        if done.rows_affected() == 0 {
            bail!("lease on job {} lost", job.id);
        }
        Ok(())
    }

    async fn fail(&self, job: &Job, error: &str) -> anyhow::Result<FailOutcome> {
        let backoff = self.policy.backoff(job.attempts).as_secs_f64();
        let row = sqlx::query(
            "UPDATE jobs SET
                    state = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
                    run_after = now() + make_interval(secs => $3),
                    last_error = $4, lease_owner = NULL, lease_expires_at = NULL,
                    updated_at = now()
             WHERE id = $1 AND state = 'running' AND lease_owner = $2
             RETURNING state, run_after",
        )
        .bind(job.id)
        .bind(job.lease_owner()?)
        .bind(backoff)
        .bind(error)
        .fetch_optional(&self.pool)
        .await?
        .with_context(|| format!("lease on job {} lost", job.id))?;
        match row.try_get::<String, _>("state")?.as_str() {
            "failed" => Ok(FailOutcome::Dead),
            _ => Ok(FailOutcome::RetryAt(row.try_get("run_after")?)),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rebut_core::{CommitSha, RepoId};

    pub fn pr(number: u64, head: char) -> PullRequest {
        PullRequest {
            repo: RepoId {
                owner: "acme".into(),
                name: "lib".into(),
            },
            number,
            base_sha: CommitSha::new("a".repeat(40)).unwrap(),
            head_sha: CommitSha::new(head.to_string().repeat(40)).unwrap(),
            head_clone_url: "https://github.com/fork/lib.git".into(),
            base_clone_url: "https://github.com/acme/lib.git".into(),
            author: "contributor".into(),
            body: String::new(),
        }
    }

    #[tokio::test]
    async fn enqueue_is_idempotent_per_head() {
        let q = InMemoryQueue::default();
        let a = q.enqueue(pr(1, 'b')).await.unwrap();
        let again = q.enqueue(pr(1, 'b')).await.unwrap();
        assert!(matches!(a, Enqueued::Created(_)));
        assert_eq!(again, Enqueued::Duplicate(a.id()));
        // A new push (different head) is a new job.
        assert!(matches!(
            q.enqueue(pr(1, 'c')).await.unwrap(),
            Enqueued::Created(_)
        ));
        assert_eq!(q.counts().0, 2);
    }

    #[tokio::test]
    async fn claim_is_exclusive_and_lease_expiry_reclaims() {
        let q = InMemoryQueue::default();
        q.enqueue(pr(1, 'b')).await.unwrap();
        let first = q.claim("w1").await.unwrap().unwrap();
        assert!(q.claim("w2").await.unwrap().is_none());

        q.advance(RetryPolicy::default().lease + Duration::from_secs(1));
        let second = q.claim("w2").await.unwrap().unwrap();
        assert_eq!(second.id, first.id);
        assert_eq!(second.attempts, 2);

        // The stale worker can no longer complete it; the new holder can.
        assert!(q.complete(&first).await.is_err());
        q.complete(&second).await.unwrap();
        assert_eq!(q.counts(), (0, 0, 1, 0));
    }

    #[tokio::test]
    async fn fail_backs_off_then_dies() {
        let policy = RetryPolicy::default();
        let q = InMemoryQueue::new(policy);
        let id = q.enqueue(pr(1, 'b')).await.unwrap().id();
        for attempt in 1..=policy.max_attempts {
            let job = q.claim("w").await.unwrap().unwrap();
            assert_eq!(job.attempts, attempt);
            let outcome = q.fail(&job, "boom").await.unwrap();
            if attempt < policy.max_attempts {
                assert!(matches!(outcome, FailOutcome::RetryAt(_)));
                // Not claimable until the backoff elapses.
                assert!(q.claim("w").await.unwrap().is_none());
                q.advance(policy.backoff(attempt));
            } else {
                assert_eq!(outcome, FailOutcome::Dead);
            }
        }
        assert_eq!(q.counts(), (0, 0, 0, 1));
        assert_eq!(q.last_error(id).as_deref(), Some("boom"));
    }

    #[tokio::test]
    async fn crashing_worker_exhausts_attempts() {
        let policy = RetryPolicy::default();
        let q = InMemoryQueue::new(policy);
        q.enqueue(pr(1, 'b')).await.unwrap();
        for _ in 0..policy.max_attempts {
            assert!(q.claim("w").await.unwrap().is_some());
            q.advance(policy.lease + Duration::from_secs(1));
        }
        assert!(q.claim("w").await.unwrap().is_none());
        assert_eq!(q.counts(), (0, 0, 0, 1));
    }

    #[test]
    fn backoff_grows_and_caps() {
        let p = RetryPolicy::default();
        assert_eq!(p.backoff(1), Duration::from_secs(30));
        assert_eq!(p.backoff(2), Duration::from_secs(60));
        assert_eq!(p.backoff(3), Duration::from_secs(120));
        assert_eq!(p.backoff(40), p.max_backoff);
    }

    /// Requires a Postgres database: `DATABASE_URL=postgres://... cargo test
    /// -p rebut-control -- --ignored`.
    #[tokio::test]
    #[ignore = "needs DATABASE_URL pointing at a disposable Postgres"]
    async fn pg_queue_roundtrip() {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let pool = PgPool::connect(&url).await.unwrap();
        crate::MIGRATOR.run(&pool).await.unwrap();
        sqlx::query("TRUNCATE jobs CASCADE")
            .execute(&pool)
            .await
            .unwrap();
        let q = PgQueue::new(pool, RetryPolicy::default());
        let a = q.enqueue(pr(1, 'b')).await.unwrap();
        assert_eq!(
            q.enqueue(pr(1, 'b')).await.unwrap(),
            Enqueued::Duplicate(a.id())
        );
        let job = q.claim("w1").await.unwrap().unwrap();
        assert!(q.claim("w2").await.unwrap().is_none());
        assert!(matches!(
            q.fail(&job, "x").await.unwrap(),
            FailOutcome::RetryAt(_)
        ));
        sqlx::query("UPDATE jobs SET run_after = now()")
            .execute(&q.pool)
            .await
            .unwrap();
        let job = q.claim("w2").await.unwrap().unwrap();
        assert_eq!(job.attempts, 2);
        q.complete(&job).await.unwrap();
    }
}
