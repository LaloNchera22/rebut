//! Persistence of verdicts and receipts.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sqlx::{types::Json, PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;
use verifier_core::{RepoId, Verdict};
use verifier_receipts::Envelope;

/// One finished run. `id` names both the verdict and its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    pub id: Uuid,
    pub job_id: Uuid,
    /// Full verdict: maintainer-only, may contain sealed reproductions.
    pub verdict: Verdict,
    pub envelope: Envelope,
    pub log_index: u64,
    pub created_at: OffsetDateTime,
}

#[async_trait::async_trait]
pub trait Store: Send + Sync {
    async fn save_run(&self, run: &RunRecord) -> anyhow::Result<()>;
    async fn receipt(&self, id: Uuid) -> anyhow::Result<Option<Envelope>>;
    /// Most recent run for a PR (any head).
    async fn latest_run(&self, repo: &RepoId, number: u64) -> anyhow::Result<Option<RunRecord>>;
}

#[derive(Default)]
pub struct InMemoryStore {
    runs: Mutex<Vec<RunRecord>>,
}

impl InMemoryStore {
    pub fn runs(&self) -> Vec<RunRecord> {
        self.runs.lock().expect("store lock").clone()
    }
}

#[async_trait::async_trait]
impl Store for InMemoryStore {
    async fn save_run(&self, run: &RunRecord) -> anyhow::Result<()> {
        self.runs.lock().expect("store lock").push(run.clone());
        Ok(())
    }

    async fn receipt(&self, id: Uuid) -> anyhow::Result<Option<Envelope>> {
        let runs = self.runs.lock().expect("store lock");
        Ok(runs.iter().find(|r| r.id == id).map(|r| r.envelope.clone()))
    }

    async fn latest_run(&self, repo: &RepoId, number: u64) -> anyhow::Result<Option<RunRecord>> {
        let runs = self.runs.lock().expect("store lock");
        Ok(runs
            .iter()
            .rev()
            .find(|r| &r.verdict.pr.repo == repo && r.verdict.pr.number == number)
            .cloned())
    }
}

pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    pub fn new(pool: PgPool) -> Self {
        PgStore { pool }
    }
}

#[async_trait::async_trait]
impl Store for PgStore {
    async fn save_run(&self, run: &RunRecord) -> anyhow::Result<()> {
        let pr = &run.verdict.pr;
        let status = serde_json::to_value(run.verdict.status())?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO verdicts (id, job_id, repo, pr_number, head_sha, status, verdict, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(run.id)
        .bind(run.job_id)
        .bind(pr.repo.to_string())
        .bind(pr.number as i64)
        .bind(pr.head_sha.as_str())
        .bind(status.as_str().unwrap_or_default())
        .bind(Json(&run.verdict))
        .bind(run.created_at)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO receipts (id, verdict_id, envelope, log_index, created_at)
             VALUES ($1, $1, $2, $3, $4)",
        )
        .bind(run.id)
        .bind(Json(&run.envelope))
        .bind(run.log_index as i64)
        .bind(run.created_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn receipt(&self, id: Uuid) -> anyhow::Result<Option<Envelope>> {
        let row = sqlx::query("SELECT envelope FROM receipts WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| Ok(r.try_get::<Json<Envelope>, _>("envelope")?.0))
            .transpose()
    }

    async fn latest_run(&self, repo: &RepoId, number: u64) -> anyhow::Result<Option<RunRecord>> {
        let row = sqlx::query(
            "SELECT v.id, v.job_id, v.verdict, r.envelope, r.log_index, v.created_at
             FROM verdicts v JOIN receipts r ON r.verdict_id = v.id
             WHERE v.repo = $1 AND v.pr_number = $2
             ORDER BY v.created_at DESC
             LIMIT 1",
        )
        .bind(repo.to_string())
        .bind(number as i64)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| {
            Ok(RunRecord {
                id: r.try_get("id")?,
                job_id: r.try_get("job_id")?,
                verdict: r.try_get::<Json<Verdict>, _>("verdict")?.0,
                envelope: r.try_get::<Json<Envelope>, _>("envelope")?.0,
                log_index: r.try_get::<i64, _>("log_index")? as u64,
                created_at: r.try_get("created_at")?,
            })
        })
        .transpose()
    }
}
