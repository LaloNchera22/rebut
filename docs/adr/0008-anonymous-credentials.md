# ADR-0008: Anonymous credentials before zkVMs

## Status

Accepted. Phase 3.

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
  verifier issues a credential over attributes derived from the trust graph. The
  holder presents zero-knowledge proofs that disclose chosen attributes and prove
  predicates (e.g. `merges ≥ 20`) over the rest. Presentations are unlinkable.
- Presentations carry a **nullifier** derived from the holder's secret and a
  verifier-chosen scope. The same person can't claim a scoped benefit twice, and
  presentations in different scopes can't be linked.
- **zkVMs later**, only for aggregation BBS predicates can't express (e.g. weighted
  sums across organizations). They are heavier to prove and verify.
- Phase 1–2 builds only the substrate: `verifier-reputation`'s `TrustGraph`, keyed by
  receipt digests, and the `CredentialScheme` trait. No cryptography is implemented
  until a reviewed BBS library is integrated.

## Consequences

- Standards-track, fast primitives (proofs in milliseconds) with small presentations.
- Issuance trusts the issuer's view of the graph. `ReceiptsCommitment` binds a
  credential to the receipts behind it, so the issuer can be audited.
- Sybil resistance comes from receipts being expensive to earn (verified, merged
  PRs), not from the credential scheme.

## Vote

Unanimous.
