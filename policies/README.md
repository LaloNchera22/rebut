# Policies

A repository opts in by committing **`.verifier/policy.toml`** on its default branch.

The verifier always reads the policy from the PR's **base** commit, never from the
head. A pull request can't relax its own checks: a change to the policy applies
only to PRs opened after it has been merged.

| File | Use |
|---|---|
| [`default.toml`](default.toml) | Phase-1 default: `mode = "mark"`, differential + challenges. Annotates, never fails a PR. |
| [`strict.toml`](strict.toml) | `mode = "block"`, all engines, sealed challenge commitments, larger budget. |
| [`intent.example.toml`](intent.example.toml) | Example **intent manifest** (`.verifier/intent.toml` in the PR, or a `verifier-intent` block in the PR body). |

An empty or missing policy file means the defaults: mark mode, `differential` +
`challenges`, and the budget shown in `default.toml`.

## Fields

These match `verifier_core::Policy` exactly. Unknown keys are ignored. Missing keys
take their defaults, except inside `[budget]`: if you write a `[budget]` table, give
all five keys.

| Key | Type | Default |
|---|---|---|
| `mode` | `"mark"` \| `"block"` | `"mark"` |
| `engines` | array of `"differential"`, `"challenges"`, `"mutation"`, `"formal"` | `["differential", "challenges"]` |
| `sealed_commitments` | array of 64-hex SHA-256 strings (optional `sha256:` prefix) | `[]` |
| `budget.vm_timeout_secs` | integer, seconds per microVM run | `600` |
| `budget.vcpus` | integer (≤ 255) | `2` |
| `budget.memory_mib` | integer | `4096` |
| `budget.pr_vm_seconds` | integer, VM-seconds per PR across engines | `1800` |
| `budget.public_challenges` | integer, public challenge cases per PR | `64` |

## Sealed challenges

Sealed challenge specs stay private to the maintainer and are supplied to the
verifier out of band. Only their SHA-256 goes in `sealed_commitments`. That way the
spec can't be swapped after a PR is seen, and the maintainer can later prove which
spec was used. Contributors who fail a sealed challenge learn only its category. See
the [threat model](../docs/threat-model.md#sealed-challenge-exfiltration).
