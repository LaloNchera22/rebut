# rebut

**Rebut** checks pull requests by running them. It builds and executes the PR
(head) and its merge base (base) in throwaway Firecracker microVMs, compares their
behavior on the same inputs, runs challenge inputs seeded from public randomness,
and publishes a signed [in-toto](https://in-toto.io) receipt of what it did in an
append-only transparency log. It supports Rust repositories first.

It assumes **every contributor is an attacker**. PR code, including `build.rs` and
proc-macros, never runs outside a VM. The maintainer's policy is read from the base
branch, so a PR can't relax its own checks. Nothing an LLM says counts as evidence:
a finding exists only if a concrete, recorded execution reproduces it.

> Phase 1 **marks, it doesn't block.** The check run concludes `neutral` and
> annotates the PR. Blocking is opt-in per repository (`mode = "block"`), after a
> maintainer has watched it run for weeks without false positives. One unfair
> rejection on a well-known project and the maintainer uninstalls, publicly.

## The four planes

```
                 ┌──────────────────────────── integration ────────────────────────────┐
  GitHub  ──────▶│  GitHub App webhooks · check runs · CLI (rebut) · MCP server │
                 └──────────────────────────────┬──────────────────────────────────────┘
                                                │ PR event (base sha, head sha, body)
                 ┌──────────────────────────────▼──────────── control ──────────────────┐
                 │  control: Postgres job queue (FOR UPDATE SKIP LOCKED), policy from   │
                 │  base branch, intent manifest, drand seed, budgets                   │
                 │  planner: diff → impacted functions & tests                          │
                 │  engines: differential · challenges · mutation · formal · adversary  │
                 └───────────────┬──────────────────────────────────────▲───────────────┘
                   ExecutionRequest (Steps)                    ExecutionResult (+ transcript digest)
                 ┌───────────────▼────────────────── execution fabric ─┴───────────────┐
                 │  fabric: Firecracker microVMs on bare metal, jailer + seccomp,       │
                 │  no network, ephemeral, snapshot + warm cargo cache                  │
                 │  guest: in-VM agent: cargo build/test, harnesses, recording          │
                 └───────────────────────────────┬─────────────────────────────────────┘
                                                 │ verdict + transcripts (content-addressed, S3)
                 ┌───────────────────────────────▼──────────────── trust ──────────────┐
                 │  receipts: in-toto statement, signed (orchestrator key, later TEE),  │
                 │  appended to a transparency log (Rekor / Trillian)                   │
                 │  reputation: verified merges keyed by receipt digest (phase 3)       │
                 └─────────────────────────────────────────────────────────────────────┘
```

## How a PR flows

1. **Event.** The GitHub App receives `pull_request` and enqueues a job in Postgres.
2. **Policy and intent.** The control plane reads `.rebut/policy.toml` from the
   **base** commit and the intent manifest (`.rebut/intent.toml` in head, or a
   `rebut-intent` fenced block in the PR body). The intent is what the contributor
   *claims* the PR does, e.g. `refactor` means "no observable behavior changes".
3. **Seed.** It waits for the first [drand](https://drand.love) round published after
   the push and derives `seed = H(commit_sha ‖ drand_round ‖ randomness ‖ generator_version)`.
   Anyone can recompute it.
4. **Plan.** The planner diffs base and head and finds the changed functions and the
   tests that reach them. It widens to the full suite when it can't reason about the
   change (`build.rs`, `Cargo.toml`, macros).
5. **Engines.** Each enabled engine emits `Step`s (`Build`, `Test`, `Harness`) that the
   fabric runs in fresh microVMs:
   - **differential** runs base and head on the same inputs. A divergence that the
     declared intent doesn't explain is a finding.
   - **challenges** runs public challenge inputs generated from the seed, plus
     **sealed** challenges from maintainer-private specs whose hashes are committed in
     the policy.
   - phase 2: **mutation** (cargo-mutants scoped to the diff), **formal** (Kani
     proofs of proposed invariants, with counterexamples replayed), and the
     **adversary** (rival agent).
6. **Verdict.** Findings come only from recorded executions. The contributor sees
   public findings in full. For sealed ones they see only "failed a challenge of
   category X".
7. **Receipt.** An in-toto statement over the verdict, transcripts, environment
   digest and seed is signed and appended to the transparency log. The check run
   links to it.

## Crate map

```
crates/
├── core                 shared types: Engine, Executor, Step, Hypothesis/Finding/Reproduction, Policy, Seed, Verdict
├── control              job queue (Postgres), orchestration, GitHub App
├── planner              diff → ImpactPlan (changed functions, tests)
├── fabric               Executor over Firecracker microVMs (jailer, snapshots)
├── guest                agent inside the VM: build, test, harness, record
├── engines/
│   ├── differential     base vs head on the same inputs
│   ├── challenges       drand-seeded public challenges + sealed challenges
│   ├── mutation         cargo-mutants in the diff → hypotheses          (phase 2)
│   └── formal           Kani harnesses; counterexamples replayed         (phase 2)
├── adversary            rival agent: untrusted hypotheses → replay → findings (phase 2)
├── receipts             in-toto receipts, signing, transparency log
├── reputation           trust graph of verified merges; credential interface (phase 3)
├── cli                  `rebut` command line
└── mcp                  MCP server for agents
policies/                example policy.toml and intent manifests
docs/                    ADRs, threat model, council notes
```

## Phases

| Phase | Scope |
|---|---|
| **1** | Control plane, execution fabric, differential and challenges engines, GitHub App, CLI. Mark mode by default. Receipts signed by the orchestrator. |
| **2** | Mutation engine, formal engine (Kani), rival agent, transparency-log receipts, TEE signer. |
| **3** | Reputation with anonymous credentials (BBS + nullifiers). Python repositories. |

The phase-2 and phase-3 crates already exist and are tested. They are kept small and
honest about what they can't do yet. For example, the mutation and formal engines
wait for dedicated executor steps and never report an unverified claim as a finding.

## Quickstart

```sh
# Run the public checks on your branch against main. This builds and runs YOUR
# code locally without a sandbox, like `cargo test`; the hosted service runs the
# same engines in Firecracker. Mark mode: exits 0 unless --fail-on-findings.
cargo run -p rebut -- verify --base main
cargo run -p rebut -- verify --base main --offline --json

# Recompute the challenge seed for a commit and drand round.
cargo run -p rebut -- seed --help

# Regenerate the public challenges a receipt claims were run.
cargo run -p rebut -- challenges regenerate --help

# Verify a receipt's signature and transparency-log inclusion.
cargo run -p rebut -- receipt verify --help
```

Example output for a PR that declares `kind = "refactor"`, keeps its tests green,
and swaps `saturating_add` for `wrapping_add`:

```text
plan: 1 changed fn(s), 1 test(s)

[FINDING] differential / behavior-divergence: `demo::clamp_add` behaves differently on head than on base for a generated input
  input:    255 255
  expected: exit:Some(0) | #harness-start | case 0 ok "255"
  observed: exit:Some(0) | #harness-start | case 0 ok "254"

FLAGGED (mark mode: not blocking)
```

### Control plane (GitHub App)

```sh
DATABASE_URL=postgres://... \
GITHUB_WEBHOOK_SECRET=... GITHUB_APP_ID=... GITHUB_PRIVATE_KEY_PATH=app.pem \
SIGNING_KEY_PATH=receipts.key \
EXECUTOR=firecracker FC_KERNEL=/var/lib/rebut/vmlinux FC_ROOTFS=/var/lib/rebut/rootfs.ext4 \
cargo run -p rebut-control
```

`EXECUTOR` is `none` by default: nothing runs and every verdict is inconclusive,
never a pass. `firecracker` needs bare metal with KVM (ADR-4). `insecure-local`
runs PR code unsandboxed and is for development only. Other settings
(`SEALED_SPECS_DIR`, `REKOR_URL`, `MAINTAINER_TOKEN`, `FC_*`) are listed by
`cargo run -p rebut-control -- --help`.

### MCP server for agents

```sh
cargo build -p rebut-mcp --release
claude mcp add rebut -- ./target/release/rebut-mcp
```

Tools: `verify_local`, `derive_seed`, `regenerate_challenges`, `verify_receipt`,
`get_report`.

Configure a repository by committing `.rebut/policy.toml` on its default branch.
See [`policies/`](policies/README.md).

Development:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Documentation

- [Threat model](docs/threat-model.md): who the attacker is, what we defend against, and what is still open.
- [Council](docs/council.md): the five roles that designed this, and the Skeptic's warning.
- Architecture decision records:
  [0001 Rust first](docs/adr/0001-rust-first.md) ·
  [0002 Modular monolith](docs/adr/0002-modular-monolith.md) ·
  [0003 Postgres queue + object store](docs/adr/0003-postgres-queue-object-store.md) ·
  [0004 Firecracker on bare metal](docs/adr/0004-firecracker-bare-metal.md) ·
  [0005 TEE later, transparency log now](docs/adr/0005-tee-later.md) ·
  [0006 LLM output is never evidence](docs/adr/0006-llm-output-is-not-evidence.md) ·
  [0007 drand-seeded challenges](docs/adr/0007-drand-seeded-challenges.md) ·
  [0008 Anonymous credentials before zkVM](docs/adr/0008-anonymous-credentials.md)

License: Apache-2.0.
