# The council

The design was argued out by a council of five roles. Each owns a failure mode, and
each had a veto on decisions in their area. Votes are recorded in the
[ADRs](adr/).

| Role | Owns | Bias |
|---|---|---|
| **Systems Architect** | Overall structure, module boundaries | Obsessed with simplicity: one binary, one database, one trait per boundary ([ADR-2](adr/0002-modular-monolith.md), [ADR-3](adr/0003-postgres-queue-object-store.md)). |
| **Security & Crypto Engineer** | Isolation, sealed challenges, receipts, credentials | Assumes every contributor is an attacker ([threat model](threat-model.md)). Dissented on shipping without a TEE ([ADR-5](adr/0005-tee-later.md)). |
| **SRE** | Cost, operations, determinism | Won the Rust-first argument on hermetic builds ([ADR-1](adr/0001-rust-first.md)). Runs the bare-metal fleet ([ADR-4](adr/0004-firecracker-bare-metal.md)). |
| **ML Engineer** | The rival agent, LLM-proposed invariants | Proposed, against his own interest, that LLM output is never evidence ([ADR-6](adr/0006-llm-output-is-not-evidence.md)). |
| **Skeptical Staff Engineer** | Developer experience, false positives | Hates false positives. Dissented on Rust-only (Python has the volume) and on the TEE timing. |

## The Skeptic's closing warning

> Phase 1 marks, it doesn't block. Maintainers adopt a tool like this on probation, and
> the probation has no second chances. One unfair rejection on a well-known project,
> one contributor told their correct PR "failed verification", and the maintainer
> uninstalls, publicly, with a screenshot. Every default must be chosen so that the
> worst case is a missed bug, never a false accusation.

This is why `EnforcementMode::Mark` is the default in `rebut-core`, why
`Inconclusive` never counts against a contributor, why stderr and timings are excluded
from observations, and why a finding can't exist without a reproduction.
