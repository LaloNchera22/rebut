# ADR-0007: Challenges seeded by the drand beacon

## Status

Accepted.

## Context

Challenge engines generate inputs the PR must handle correctly. If the inputs are
fixed or predictable, a contributor (or an LLM writing code for them) can special-case
them, i.e. overfit to the test. If they come from our own RNG, nobody can check we
didn't pick inputs to fail (or pass) a particular PR.

## Decision

- Seed every challenge run with
  `seed = H(commit_sha ‖ drand_round ‖ drand_randomness ‖ generator_version)`
  (length-framed SHA-256, see `core::Seed::derive`). `drand_round` is the **first
  [drand](https://drand.love) round published after the push**. The randomness was
  unknown when the commit was made, so the commit can't depend on it. And it is
  public and verifiable (BLS signature from the League of Entropy), so anyone can
  recompute the seed and regenerate the exact public challenges
  (`rebut challenges regenerate`).
- `generator_version` is bumped whenever generation changes, so old receipts stay
  reproducible with the old generator. Sub-streams use `Seed::fork(label)`, so adding a
  challenge family never shifts another family's inputs.
- **Sealed challenges** use the same seed, but with maintainer-private specs. The repo
  commits only the spec's SHA-256 (`sealed_commitments` in the policy, read from the
  base branch). The maintainer can later prove which spec was used, and can't
  swap it after seeing a PR.

## Consequences

- Contributors can't precompute answers, and maintainers and operators can't
  cherry-pick inputs. Both are checkable after the fact.
- Verification waits for the next drand round (3 s on quicknet). That's negligible.
- If drand is unavailable, the challenge engine reports `inconclusive`. It never
  falls back to a private RNG.
- Sealed challenges bring their own exfiltration threat. See the threat model.

## Vote

Unanimous.
