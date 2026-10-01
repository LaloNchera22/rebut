# rebut

**Rebut** checks that a Rust change does what it claims, by running it. It
builds your branch (head) and the commit it started from (base), runs both on
the same generated inputs, plus challenge inputs seeded from public
randomness, and reports every function whose behavior changed when the change
said it wouldn't. Each finding is a concrete input with the base's output and
the head's output, never an opinion: a language model may *propose* inputs, but
only a recorded execution that reproduces counts. It is a free, open-source
tool that runs on your machine or your CI runner, with no server, no database
and no account.

**Documentation: [the rebut book](https://lalonchera22.github.io/rebut/).**

## Install

```sh
cargo install rebut --locked              # CLI
cargo install rebut-mcp --locked          # MCP server for coding agents (optional)
brew install LaloNchera22/tap/rebut       # both, on macOS or Linux
```

Prebuilt static binaries for Linux (x86_64, arm64) and macOS are on the
[releases page](https://github.com/LaloNchera22/rebut/releases). rebut needs
`git` and a Rust toolchain, because it builds your code with your toolchain.

## 30-second quickstart

A branch replaces `a.saturating_add(b)` with `a.wrapping_add(b)` and calls it a
refactor. The tests (`clamp_add(1, 2) == 3`) still pass.

```sh
mkdir -p .rebut && echo 'kind = "refactor"' > .rebut/intent.toml   # what it claims
rebut verify --base main
```

```text
plan: 1 changed fn(s), 1 test(s)

[FINDING] differential / behavior-divergence: `demo::clamp_add` behaves differently on head than on base for a generated input
  input:    255 255
  expected: exit:Some(0) | #harness-start | case 0 ok "255"
  observed: exit:Some(0) | #harness-start | case 0 ok "254"

FLAGGED (mark mode: not blocking)
```

By default rebut marks and exits 0; `--fail-on-findings` exits 1 on findings.

> `rebut verify` builds and runs code on your machine **without a sandbox**,
> exactly like `cargo test`. Use it on code you would run anyway. For code you
> don't trust, use the GitHub Action, where the disposable runner is the
> sandbox.

## Five ways to use it

1. **Check your own change before you push.** `rebut hook install` adds a
   pre-push hook running `rebut verify --fail-on-findings`.
   ([book](https://lalonchera22.github.io/rebut/scenarios/pre-push.html))
2. **Guard your own AI agent.** `claude mcp add rebut -- rebut-mcp` gives the
   agent a check it can't satisfy by editing its own tests: policy and
   challenges come from the base branch, and findings are executions.
   ([book](https://lalonchera22.github.io/rebut/scenarios/agent.html))
3. **Amplify your tests with challenges.** A few lines in
   `.rebut/challenges.toml` (no-panic, properties, round-trips, reference
   implementations) become fresh inputs on every run.
   ([book](https://lalonchera22.github.io/rebut/scenarios/challenges.html))
4. **Review dependency updates.** `rebut verify --all-public` compares every
   public function under the old and the new `Cargo.lock`.
   ([book](https://lalonchera22.github.io/rebut/scenarios/dependencies.html))
5. **Review someone else's pull request**, only in a sandbox: the GitHub Action
   below, or a throwaway VM.
   ([book](https://lalonchera22.github.io/rebut/scenarios/review-prs.html))

### GitHub Action

```yaml
on: pull_request
permissions:
  contents: read
jobs:
  rebut:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: LaloNchera22/rebut@v0   # mark mode; fail-on-findings: "true" to block
```

Two caveats, explained in the
[book](https://lalonchera22.github.io/rebut/github-action.html): pull requests
from forks get no secrets, so only public checks run there; and with
`pull_request` a PR can edit the workflow to skip rebut, so review changes to
`.github/workflows/` by hand (CODEOWNERS plus branch protection requiring the
check). Never use `pull_request_target` with a checkout of the PR's code. Full
example: [`examples/github-workflow.yml`](examples/github-workflow.yml).

## Crate map

```
crates/
├── cli                  `rebut` command line (published as `rebut`)
├── mcp                  `rebut-mcp`, MCP server for agents
├── core                 shared types: Engine, Executor, Step, Hypothesis/Finding/Reproduction, Policy, Seed, Verdict
├── planner              diff → ImpactPlan (changed functions, tests)
├── engines/
│   ├── differential     base vs head on the same inputs
│   ├── challenges       drand-seeded public challenges + sealed challenges
│   ├── mutation         cargo-mutants in the diff → hypotheses          (phase 2)
│   └── formal           Kani harnesses; counterexamples replayed         (phase 2)
├── adversary            rival agent: untrusted hypotheses → replay → findings (phase 2)
├── fabric               executors: local process; Firecracker microVMs (hosted mode)
├── guest                agent inside the VM: build, test, harness, record
├── receipts             in-toto receipts, signing, transparency log (hosted mode)
├── control              hosted mode: job queue (Postgres), orchestration, GitHub App (not published)
└── reputation           hosted mode: trust graph, anonymous credentials, phase 3 (not published)
policies/                example policy.toml and intent manifests
docs/book/               the user guide (mdBook)
docs/                    ADRs, threat model, council notes
```

Development:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
mdbook build docs/book
```

## Hosted mode (experimental)

None of the above needs it. Hosted mode is a service design for checking pull
requests from contributors nobody trusts, at scale, with evidence a third party
can audit. It assumes **every contributor is an attacker**: PR code, including
`build.rs` and proc-macros, never runs outside a Firecracker microVM; the
maintainer's policy is read from the base branch; and every verdict gets a
signed [in-toto](https://in-toto.io) receipt in an append-only transparency
log. The `rebut-control` and `rebut-reputation` crates are not published.

> Hosted mode **marks, it doesn't block** by default. The check run concludes
> `neutral` and annotates the PR. Blocking is opt-in per repository
> (`mode = "block"`), after a maintainer has watched it run for weeks without
> false positives.

### The four planes

```
                 ┌──────────────────────────── integration ────────────────────────────┐
  GitHub  ──────▶│  GitHub App webhooks · check runs · CLI (rebut) · MCP server        │
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

### How a PR flows

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

### Phases

| Phase | Scope |
|---|---|
| **1** | Control plane, execution fabric, differential and challenges engines, GitHub App, CLI. Mark mode by default. Receipts signed by the orchestrator. |
| **2** | Mutation engine, formal engine (Kani), rival agent, transparency-log receipts, TEE signer. |
| **3** | Reputation with anonymous credentials (BBS + nullifiers). Python repositories. |

The phase-2 and phase-3 crates already exist and are tested. They are kept small and
honest about what they can't do yet. For example, the mutation and formal engines
wait for dedicated executor steps and never report an unverified claim as a finding.

### Running the control plane

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

Auditing a hosted verdict needs only the CLI:

```sh
rebut seed --help                    # recompute the challenge seed from drand
rebut challenges regenerate --help   # regenerate the public challenges a receipt claims
rebut receipt verify --help          # check a receipt's signature and log inclusion
```

Configure a repository by committing `.rebut/policy.toml` on its default branch.
See [`policies/`](policies/README.md).

## Documentation

- [The rebut book](https://lalonchera22.github.io/rebut/) (source in [`docs/book`](docs/book/src/SUMMARY.md)).
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
