# ADR-0004: Firecracker microVMs on bare metal

## Status

Accepted.

## Context

We execute code written by people we must assume are hostile: tests, harnesses, and
also `build.rs` scripts and proc-macros that run during compilation. Containers
share the host kernel. One kernel exploit and a PR owns the machine that holds
sealed challenges and signing keys. Full VMs (QEMU) isolate well but boot slowly and
cost memory.

We also want deterministic replay for flaky or suspicious runs. Record-and-replay
(`rr`) needs hardware performance counters, which cloud VMs usually don't expose.
Firecracker needs `/dev/kvm`. Nested virtualization is slow or unavailable.

## Decision

- Run every build and execution in a **Firecracker microVM**, one per request,
  **ephemeral** (destroyed after the run, never reused across PRs).
- Launch through the Firecracker **jailer** (chroot, cgroups, unprivileged uid,
  namespaces), with Firecracker's **seccomp** filters enabled.
- **No network** inside the guest. Dependencies come from a read-only, pre-populated
  Cargo cache (`--offline`). Results go back over vsock.
- Start from **snapshots** of a booted guest with a **warm cache** (toolchain,
  registry, common crates compiled), so a VM is ready in well under a second and a
  build doesn't start cold.
- Host on **bare metal**: KVM without nesting, and access to the performance counters
  that `rr` needs.

## Consequences

- Strong isolation boundary (a minimal VMM in Rust, small device model) at
  container-like startup cost.
- We operate our own bare-metal fleet. That costs more than serverless and is the
  SRE's responsibility. Budgets (`[budget]` in the policy) cap VM-seconds per PR.
- Snapshot restore creates identical guests. Randomness and clocks must be reseeded
  after restore, or VMs share entropy. The guest agent does this.
- Differences between the verification environment and a developer machine become an
  attack surface (see "environment detection" in the threat model).

## Vote

Unanimous.
