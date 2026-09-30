# ADR-0002: Modular monolith

## Status

Accepted.

## Context

The system has clear parts: control plane, planner, engines, execution fabric,
receipts. Deploying them as microservices would add network hops, serialization
boundaries, distributed failure modes and an operations burden for a small team.
It would buy nothing until the parts have to scale separately. The one part that
does scale separately, the VM fleet, sits behind the `Executor` trait anyway.

## Decision

Build one Cargo workspace that deploys as one control-plane binary. Module boundaries
are enforced as crate boundaries:

- every crate depends on `verifier-core`, which holds the shared vocabulary and the
  two invariants that must not drift (ADR-6 and sealed-output asymmetry);
- engines implement `core::Engine` and are orchestrated only through it;
- hostile code runs only through `core::Executor`. The fabric is the one component
  expected to run on other machines (bare-metal VM hosts), and it talks to the
  control plane through that one interface.

## Consequences

- One deploy, one log stream, one set of migrations. You can test the whole system
  with `cargo test --workspace`.
- A crate can be split into a service later without changing its callers, because
  callers already go through a trait.
- Crate-level discipline is needed: no reaching into another crate's internals.
  Visibility and the dependency graph enforce this better than convention does.

## Vote

Unanimous.
