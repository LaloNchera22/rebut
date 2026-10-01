# ADR-0008: Anonymous credentials before zkVMs

## Status

Accepted. Phase 3. Issuance, presentation, verification and nullifiers are
implemented in `rebut-reputation` (`credential` module) on
[zkryptium](https://github.com/Cybersecurity-LINKS/zkryptium) 0.7.1. Not yet
wired into the control plane.

## Context

Receipts accumulate into a record: this person had N verified PRs merged. That record
is valuable to a project deciding how much to scrutinize a newcomer. Using it
naively deanonymizes contributors and links their activity across projects.
We want "prove you have ≥ N verified merges, none reverted" without "prove you are
@alice".

Options considered: zkVM proofs (SP1, RISC Zero) over the receipts, and anonymous
credentials (BBS signatures).

## Decision

- Use **BBS signatures** (IETF CFRG draft `draft-irtf-cfrg-bbs-signatures`). The
  Rebut issues a credential over attributes derived from the trust graph. The
  holder presents zero-knowledge proofs that disclose chosen attributes and prove
  predicates (e.g. `merges ≥ 20`) over the rest. Presentations are unlinkable.
- Presentations carry a **nullifier** derived from the holder's secret and a
  rebut-chosen scope. The same person can't claim a scoped benefit twice, and
  presentations in different scopes can't be linked.
- **zkVMs later**, only for aggregation BBS predicates can't express (e.g. weighted
  sums across organizations). They are heavier to prove and verify.
- Phase 1–2 builds only the substrate: `rebut-reputation`'s `TrustGraph`, keyed by
  receipt digests, and the `CredentialScheme` trait. No cryptography is implemented
  until a reviewed BBS library is integrated.
- **Library: zkryptium, pinned to `=0.7.1`.** It implements the BBS signatures,
  blind signatures and per-rebut-linkability (pseudonym) drafts on
  BLS12-381-SHA-256, and is on crates.io. The alternative, MATTR's `pairing_crypto`,
  is not published on crates.io and has no pseudonym support in a release. We write
  no pairing code ourselves.
- **Predicates are threshold buckets.** BBS has no range proofs. The issuer also
  signs booleans `verified_merges ≥ t` for t in 1, 5, 10, 20, 50, 100, 200, 500,
  1000 and `reverted_merges ≤ t` for t in 0, 1, 2, 5. Proving a predicate means
  disclosing the matching boolean; the verifier rebuilds it as "true", so a bucket
  signed as false never verifies. Only those predicates can be proven; anything else
  is an error, never a rounded or assumed answer.

## Consequences

What is implemented:

- Blind issuance. The holder sends a commitment to its secret with a proof of
  knowledge; the issuer signs the four attributes (`VerifiedMerges`,
  `RevertedMerges`, `FirstMergeDay`, `ReceiptsCommitment`), derived from the
  `TrustGraph`, plus the buckets, without seeing the secret.
- Presentations with selective disclosure and bucket predicates, bound to a
  verifier nonce. Each presentation is re-randomized.
- Nullifiers: SHA-256 of the draft's pseudonym for the verifier's scope. Same
  credential and scope give the same nullifier; different scopes are unlinkable.
- `rebut credential verify` in the CLI.

Costs and limits:

- A verifier learns exactly which bucket was proven (`≥ 20`), not the count. The
  buckets are coarse, and asking for two buckets narrows the count to an interval.
  Changing the buckets is a new schema version.
- The nullifier is per *credential*. Blind issuance means the issuer can't check that
  a holder reused their secret, so a second credential brings a second nullifier.
  "One claim per person per scope" also needs the issuer to issue at most one
  credential per author for the lifetime of a scope. That policy is not written yet.
- zkryptium calls itself experimental and has no public audit. It also panics on
  short inputs and does not reject identity points in proofs, which the drafts
  require; our wrapper checks lengths and rejects identity points before calling it.
  An audit of zkryptium, or a move to an audited implementation, comes before these
  credentials protect anything of value.
- `ReceiptsCommitment` is a plain hash of public receipts, so disclosing it identifies
  the holder. It is for auditors only.
- `FirstMergeDay` needs merge times in the `TrustGraph` (`record_merge_at`).

- Standards-track, fast primitives (proofs in milliseconds) with small presentations.
- Issuance trusts the issuer's view of the graph. `ReceiptsCommitment` binds a
  credential to the receipts behind it, so the issuer can be audited.
- Sybil resistance comes from receipts being expensive to earn (verified, merged
  PRs), not from the credential scheme.

## Vote

Unanimous.
