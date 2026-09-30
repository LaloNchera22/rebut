-- Job queue (ADR-3): Postgres is the queue. Workers claim with
-- SELECT ... FOR UPDATE SKIP LOCKED and hold a lease; a job whose lease
-- expired is claimable again.
CREATE TABLE jobs (
    id               UUID PRIMARY KEY,
    repo             TEXT        NOT NULL,
    pr_number        BIGINT      NOT NULL,
    head_sha         TEXT        NOT NULL,
    pr               JSONB       NOT NULL,
    state            TEXT        NOT NULL DEFAULT 'queued'
                     CHECK (state IN ('queued', 'running', 'done', 'failed')),
    attempts         INTEGER     NOT NULL DEFAULT 0,
    max_attempts     INTEGER     NOT NULL,
    run_after        TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner      TEXT,
    lease_expires_at TIMESTAMPTZ,
    last_error       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Idempotency: a re-delivered webhook for the same head is a no-op.
    UNIQUE (repo, pr_number, head_sha)
);

CREATE INDEX jobs_claimable ON jobs (run_after) WHERE state IN ('queued', 'running');

-- Full verdicts: maintainer-visible, may contain sealed reproductions.
CREATE TABLE verdicts (
    id         UUID PRIMARY KEY,
    job_id     UUID        NOT NULL REFERENCES jobs (id),
    repo       TEXT        NOT NULL,
    pr_number  BIGINT      NOT NULL,
    head_sha   TEXT        NOT NULL,
    status     TEXT        NOT NULL,
    verdict    JSONB       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX verdicts_by_pr ON verdicts (repo, pr_number, created_at DESC);

-- Signed receipts (DSSE envelopes) and their transparency-log position.
CREATE TABLE receipts (
    id         UUID PRIMARY KEY,
    verdict_id UUID        NOT NULL UNIQUE REFERENCES verdicts (id),
    envelope   JSONB       NOT NULL,
    log_index  BIGINT      NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
