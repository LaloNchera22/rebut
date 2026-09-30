# ADR-0003: Postgres as the queue, content-addressed object store for artifacts

## Status

Accepted.

## Context

We need a durable job queue (PR events → verification jobs → engine runs), a place
for relational state (installations, policies seen, verdicts, receipts), and storage
for large immutable artifacts (execution transcripts, recordings, build logs,
snapshots). A dedicated broker (Kafka, RabbitMQ, SQS) would be one more stateful
system to run, back up and reason about.

## Decision

- **Queue:** Postgres. Workers claim jobs with
  `SELECT … FOR UPDATE SKIP LOCKED LIMIT n` inside a transaction. A job and its state
  transition commit atomically with the rest of the relational state. Leases expire
  so crashed workers' jobs are retried.
- **Artifacts:** an S3-compatible object store (S3, R2, MinIO), **content-addressed**:
  every object is stored under its SHA-256 (`sha256/ab/cdef…`, see `core::Digest`).
  Findings and receipts point at transcripts by digest.

## Consequences

- One stateful system to operate for everything except blobs.
- Content addressing gives integrity for free: a receipt that names a transcript
  digest can be checked by anyone who fetches the object. Identical artifacts are
  deduplicated, and objects are immutable, so caching is trivial.
- Postgres as a queue is good to thousands of jobs per second, far above our load. If
  that ever changes, the queue sits behind one module in `control`.

## Vote

Unanimous.
