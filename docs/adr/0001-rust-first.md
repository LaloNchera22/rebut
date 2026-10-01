# ADR-0001: Rust first

## Status

Accepted.

## Context

We verify PRs by building and running them, so the first ecosystem we support sets
the ceiling on how deterministic and how deep verification can be. We considered
Rust, Python and TypeScript.

The SRE's argument decided it:

- **Hermetic execution.** `Cargo.lock` pins the full dependency graph by checksum.
  `cargo build --locked --offline` against a vendored or cached registry runs in a VM
  with no network, which ADR-4 requires. Python's resolution (`pip`, extras, sdists
  that run arbitrary `setup.py`, platform wheels) makes "same inputs, same build"
  much harder to guarantee.
- **Tooling for depth.** Rust already has the engines we plan to run:
  [Kani](https://github.com/model-checking/kani) and
  [Verus](https://github.com/verus-lang/verus) for formal checks,
  [cargo-mutants](https://mutants.rs) for mutation testing,
  [proptest](https://github.com/proptest-rs/proptest) for property tests and
  [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) for fuzzing.
- **Build-time code execution is explicit.** `build.rs` and proc-macros are the known
  places where a build runs code. We run all of it in the VM anyway (see the threat
  model), but the attack surface is well understood.
- The verifier itself is written in Rust, so we are our own first user.

## Decision

Support Rust repositories first. The whole pipeline (planner, differential,
challenges, receipts) is designed and tested against Cargo workspaces.

Python is the second ecosystem, no earlier than phase 2. The roadmap currently puts
it with phase 3, after the engines have proven themselves on Rust.

## Consequences

- We can promise reproducibility ("anyone can re-run this receipt") with a straight
  face for Rust.
- The `Step` contract in `verifier-core` is Cargo-shaped (`Build { profile }`,
  `Test { filters }`). Adding Python will mean generalizing it.
- We give up most of the open-source PR volume at launch.

## Vote

4–1 (Skeptic dissenting).

Dissent (Skeptic): Most open-source PR volume, and most of the maintainers drowning in low-quality
contributions, is in Python and JavaScript. Launching Rust-only means optimizing
for the ecosystem that needs us least and has the least traffic to prove the product
on. The Skeptic asked that Python be committed for phase 2. The majority kept Rust
first and recorded the dissent.
