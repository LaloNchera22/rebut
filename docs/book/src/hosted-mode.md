# Hosted mode (experimental)

> Nothing in the rest of this book needs hosted mode. It is experimental, it is
> not part of the free command-line tool, and its control-plane crate (`rebut-control`) is
> not published to crates.io.

Hosted mode is a service design for checking pull requests from contributors
nobody trusts, at scale, with evidence a third party can audit. It assumes
**every contributor is an attacker**: pull request code, including `build.rs`
and proc-macros, never runs outside a microVM. It adds what a local tool can't:

- a **GitHub App** with a Postgres job queue and check runs;
- an **execution fabric** of Firecracker microVMs on bare metal (jailer,
  seccomp, no network, ephemeral, snapshot + warm cargo cache);
- **sealed challenges**: maintainer-private specs whose SHA-256 is committed
  in the policy; a contributor who fails one learns only its category;
- **signed receipts**: an [in-toto](https://in-toto.io) statement over the
  verdict, transcripts, environment digest and seed, signed and appended to a
  transparency log, verifiable with `rebut receipt verify`;
- **reputation** (phase 3): verified merges keyed by receipt digest, with
  anonymous credentials (BBS signatures and scoped pseudonyms).

## The four planes

```text
             +--------------------------- integration ---------------------------+
  GitHub --->| GitHub App webhooks . check runs . CLI (rebut) . MCP server       |
             +--------------------------------+----------------------------------+
                                              | PR event (base sha, head sha, body)
             +--------------------------------v---------------- control ---------+
             | control: Postgres job queue (FOR UPDATE SKIP LOCKED), policy from |
             | base branch, intent manifest, drand seed, budgets                 |
             | planner: diff -> impacted functions & tests                       |
             | engines: differential . challenges . mutation . formal . adversary|
             +-------------+-------------------------------------^---------------+
               ExecutionRequest (Steps)            ExecutionResult (+ transcript digest)
             +-------------v------------------- execution fabric -+--------------+
             | fabric: Firecracker microVMs on bare metal, jailer + seccomp,     |
             | no network, ephemeral, snapshot + warm cargo cache                |
             | guest: in-VM agent: cargo build/test, harnesses, recording        |
             +--------------------------------+----------------------------------+
                                              | verdict + transcripts (content-addressed)
             +--------------------------------v----------------- trust ----------+
             | receipts: in-toto statement, signed (orchestrator key, later TEE),|
             | appended to a transparency log (Rekor / Trillian)                 |
             | reputation: verified merges keyed by receipt digest (phase 3)     |
             +-------------------------------------------------------------------+
```

## How a pull request flows

1. **Event.** The GitHub App receives `pull_request` and enqueues a job.
2. **Policy and intent.** `.rebut/policy.toml` from the base commit, the intent
   from `.rebut/intent.toml` in head or a `rebut-intent` block in the PR body.
3. **Seed.** It waits for the first [drand](https://drand.love) round after the
   push and derives `seed = H(commit_sha ‖ drand_round ‖ randomness ‖ generator_version)`.
   Anyone can recompute it with `rebut seed`.
4. **Plan.** Changed functions and the tests that reach them; the full suite
   when it can't reason about the change (`build.rs`, `Cargo.toml`, macros).
5. **Engines** emit steps (`Build`, `Test`, `Harness`) that run in fresh
   microVMs: differential, public and sealed challenges, and in phase 2
   mutation (cargo-mutants), formal (Kani) and the rival agent.
6. **Verdict.** Findings only from recorded executions. Sealed findings show
   only their category to the contributor.
7. **Receipt.** Signed, appended to the transparency log, linked from the
   check run. Check one with `rebut receipt verify`.

## Running the control plane

```sh
DATABASE_URL=postgres://... \
GITHUB_WEBHOOK_SECRET=... GITHUB_APP_ID=... GITHUB_PRIVATE_KEY_PATH=app.pem \
SIGNING_KEY_PATH=receipts.key \
EXECUTOR=firecracker FC_KERNEL=/var/lib/rebut/vmlinux FC_ROOTFS=/var/lib/rebut/rootfs.ext4 \
cargo run -p rebut-control
```

`EXECUTOR` is `none` by default: nothing runs and every verdict is
inconclusive, never a pass. `firecracker` needs bare metal with KVM.
`insecure-local` runs pull request code unsandboxed and is for development
only. `cargo run -p rebut-control -- --help` lists the other settings.

## Design documents

- [Threat model](https://github.com/LaloNchera22/rebut/blob/main/docs/threat-model.md):
  who the attacker is, what is defended, and what is still open.
- [Council notes](https://github.com/LaloNchera22/rebut/blob/main/docs/council.md).
- Architecture decision records:
  - [0001 Rust first](https://github.com/LaloNchera22/rebut/blob/main/docs/adr/0001-rust-first.md)
  - [0002 Modular monolith](https://github.com/LaloNchera22/rebut/blob/main/docs/adr/0002-modular-monolith.md)
  - [0003 Postgres queue + object store](https://github.com/LaloNchera22/rebut/blob/main/docs/adr/0003-postgres-queue-object-store.md)
  - [0004 Firecracker on bare metal](https://github.com/LaloNchera22/rebut/blob/main/docs/adr/0004-firecracker-bare-metal.md)
  - [0005 TEE later, transparency log now](https://github.com/LaloNchera22/rebut/blob/main/docs/adr/0005-tee-later.md)
  - [0006 LLM output is never evidence](https://github.com/LaloNchera22/rebut/blob/main/docs/adr/0006-llm-output-is-not-evidence.md)
  - [0007 drand-seeded challenges](https://github.com/LaloNchera22/rebut/blob/main/docs/adr/0007-drand-seeded-challenges.md)
  - [0008 Anonymous credentials before zkVM](https://github.com/LaloNchera22/rebut/blob/main/docs/adr/0008-anonymous-credentials.md)
