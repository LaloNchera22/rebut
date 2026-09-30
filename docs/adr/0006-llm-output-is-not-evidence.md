# ADR-0006: LLM output is never evidence

## Status

Accepted.

## Context

Several components use LLMs: the rival agent proposes where a PR might break, the
formal engine asks an LLM for invariants to prove, and future engines may summarize.
LLMs hallucinate confidently. They can also be prompt-injected by the very PR they
are reviewing: the PR body, comments and code are attacker-controlled. If a
verdict can rest on an LLM's say-so, then a hallucination can falsely accuse a
contributor, and an injection can do so on purpose.

The ML Engineer, who owns the rival agent, proposed this rule himself. It caps how
much his component can claim.

## Decision

- Anything a generator produces (LLM, heuristic, mutation tool) is a
  **`Hypothesis`**. A hypothesis has no weight in a verdict.
- A **`Finding`** can only be constructed from a **`Reproduction`**, and a
  `Reproduction` can only be constructed by `Reproduction::confirm` or
  `confirm_divergence` from an **`ExecutionResult`** that actually shows the
  disagreement. This is enforced by the type system in `verifier-core` (private
  fields, no other constructors), not by convention.
- Hypotheses that don't reproduce are kept in `EngineReport::unreproduced` for tuning.
  They are never shown to the contributor as findings.
- Surviving mutants (mutation engine) and Kani `FAILED` results (formal engine) are
  hypotheses too. The Kani counterexample must be replayed as a normal harness in
  the fabric before it counts.

## Consequences

- A hallucinating or prompt-injected LLM can waste VM-seconds and can cause us to
  *miss* a bug. It can't manufacture one.
- Every finding carries a concrete input, the expected and observed behavior, and the
  digest of the recorded transcript, so the contributor can reproduce it.
- Some true problems that the model "sees" but can't turn into a reproducing input
  go unreported. We accept this: false negatives are cheaper than false accusations.

## Vote

Unanimous. Proposed by the ML Engineer, against his own interest.
