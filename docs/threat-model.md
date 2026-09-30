# Threat model

## The attacker is every contributor

We assume anyone who opens a pull request may be hostile, and that they know how the
verifier works (this document included). They control the PR's code, its tests,
`build.rs`, proc-macros, `Cargo.toml`, the PR title and body, the intent manifest in
the head commit, and the timing of their pushes. Their goals, from most to least
damaging:

1. Run code on our infrastructure outside the sandbox (steal signing keys, sealed
   challenge specs, other PRs' data).
2. Get a malicious or broken change marked as verified.
3. Learn sealed challenges, so future PRs can pass them without being correct.
4. Get *someone else's* PR flagged, or wear down the maintainer's trust in the tool.

Maintainers are trusted for their own repository. Their policy is authoritative. The
operator (us) is trusted in phase 1. See [below](#phase-1-you-trust-the-operator).

## Build-time code execution

**Threat.** `cargo build` runs arbitrary code before any test does: `build.rs` scripts,
proc-macros, and the build scripts of dependencies the PR adds. "We only run the
tests in a sandbox" is not enough.

**Defense.** *Everything* that touches PR content runs in the microVM, including
`cargo metadata`, the build, test compilation and harness compilation
([ADR-4](adr/0004-firecracker-bare-metal.md)). The VM is ephemeral, has no network,
and runs under the jailer with seccomp. The control plane never checks out the head
commit on the host for anything but reading text (diff, manifest). The planner parses
source with `syn` and never compiles or expands it on the host.

## Policy is read from the base branch

**Threat.** A PR edits `.verifier/policy.toml` to switch to mark mode, disable
engines, shrink budgets, or replace `sealed_commitments`.

**Defense.** The policy is read from the **base** commit only. A policy change takes
effect only once it has been reviewed and merged like any other change. The intent
manifest *is* read from head, because it is the contributor's claim. But it can only
narrow what counts as unexpected (a `refactor` promises *no* behavior change). It
can't disable checks, and findings it explains are still recorded as informational.

## Sealed-challenge exfiltration

**Threat.** Sealed challenges run the PR's code on inputs the contributor must not
see. But the PR code and the challenge inputs are in the same VM, and the PR code is
the attacker. It can:

- print the inputs to stdout or stderr;
- encode them in panic or error messages, or in exit codes;
- leak them through timing (sleep for `input[0]` milliseconds) or through the
  pass/fail pattern across many challenges;
- spread them over many PRs, learning a little each time.

We can't stop hostile code from *reading* its own inputs. We can control what gets
*out*. Three defenses:

1. **Asymmetric outputs.** For a sealed finding, the contributor learns only "failed a
   challenge of category X". `Verdict::for_contributor` in `verifier-core` is the
   only projection shown to contributors, and it strips everything else (a unit test
   checks that the serialized report contains no byte of the sealed input).
2. **Sealed runs return nothing to the contributor.** Requests marked
   `sealed: true` have stdout, stderr and timings routed only to maintainer-visible
   storage. They never appear in check-run output, logs, or the public receipt,
   which references them by digest only.
3. **Regenerated per PR.** Sealed challenges are generated from the maintainer's spec
   *and* the per-PR drand seed ([ADR-7](adr/0007-drand-seeded-challenges.md)). A leaked
   instance shows one sample, not the generator. The category-level signal
   ("failed: overflow") leaks at most a few bits per PR.

**Residual.** A patient attacker can learn about a sealed spec's *shape* across many
PRs from category-level pass/fail. Maintainers should treat sealed specs as
rotatable, and bump them when a category flips suspiciously often.

## OPEN: environment detection (the "Volkswagen" attack)

**Threat.** The PR detects that it is running under verification and behaves
correctly only there, like the emissions software that recognized the test cycle.
Signals include: no network, a Firecracker device model, CPU flags, a clean `$HOME`,
specific env vars, the snapshot's boot time, the hostname, the presence of the
harness binary, test-only inputs, or simply `cfg(test)`.

**Mitigations.** Make the environment as indistinguishable from a normal build as we
can. Use standard toolchain paths, no verifier-specific env vars, realistic hostnames
and clocks, and randomness reseeded after snapshot restore. Run the *same* binary that
would ship (release profile where possible), not a test-only variant. Differential
testing helps, because base and head run in identical environments, so
environment-conditional behavior in head that base doesn't have can show up as a
divergence.

**This is not solved.** Code that is determined to tell "am I being verified?" apart
can find a signal we didn't erase, and it can behave perfectly in the VM. Verification
shows how the code behaves *in our environment*. It doesn't prove how it behaves in
production. We say so in every report. It is the main reason the verifier supplements
code review and does not replace it.

## Phase 1: you trust the operator

In phase 1 the orchestrator holds the key that signs receipts
([ADR-5](adr/0005-tee-later.md)). A malicious or compromised operator could sign a
false receipt. What limits the damage:

- every receipt goes into an append-only transparency log, so forgeries are
  permanent and attributable;
- every receipt names its seed, commits, environment digest and transcripts by
  content digest, so a third party can re-run the verification and compare.

Phase 2 moves the signer into a TEE. Until then: **trust us, and check us.**

## False positives and flaky tests: a threat to adoption

A wrong accusation costs more than a missed bug. One unfair rejection on a
well-known project, and the maintainer uninstalls the app, publicly. Sources and
defenses:

- **Flaky tests** (time, randomness, ordering, network). The differential engine runs
  base and head at least twice each; any output that varies between identical runs is
  discarded as flaky and never becomes a finding. A test that fails on base is not
  counted as a regression. The guest pins the environment (`SOURCE_DATE_EPOCH`, `TZ`,
  `LANG`, single test thread, no network). Recording with `rr` on bare metal, so a
  divergence can be replayed exactly, is planned but not implemented yet.
- **Noise in observations.** Findings compare exit status and stdout only. Stderr and
  timings are excluded on purpose (`core::finding::observation`).
- **Unfounded claims.** LLM and tool output is never evidence
  ([ADR-6](adr/0006-llm-output-is-not-evidence.md)). Every finding carries a
  reproduction.
- **Infrastructure failures** (build fails, budget exhausted, drand down) produce
  `Inconclusive`, which is never counted against the contributor.
- **Mark, don't block.** Phase 1 defaults to `mode = "mark"`. Blocking is opt-in per
  repository.

## Out of scope (for now)

- Vulnerabilities in dependencies the PR doesn't change. That's supply-chain
  scanning, a different tool.
- Hardware side channels between co-tenant VMs on the same host. We rely on
  Firecracker's mitigations and do not co-schedule sealed runs with unrelated tenants.
- Maintainers attacking their own contributors through the policy. The policy is
  public in the repository and its hash is in every receipt.
