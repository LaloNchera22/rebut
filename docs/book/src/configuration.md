# Configuration

rebut needs no configuration: without any files it runs the differential and
challenge engines in mark mode. Three optional files live in `.rebut/`.

| File | Read from | Written by | Purpose |
|---|---|---|---|
| `.rebut/policy.toml` | base | maintainer | Which engines run, mark or block, budgets. |
| `.rebut/challenges.toml` | base | maintainer | [Challenges](scenarios/challenges.md). |
| `.rebut/intent.toml` | head | author of the change | What the change claims to do. |

The policy and challenges come from the **base** commit so a branch can't relax
its own checks. The intent comes from the **head** because it is the author's
claim; it can only decide which divergences are expected, never disable a
check.

## Intent

```toml
# .rebut/intent.toml
kind = "bugfix"
changes_behavior_of = ["mylib::parse::header"]
summary = "Reject headers whose length field exceeds the buffer instead of panicking."
```

| `kind` | Meaning |
|---|---|
| `refactor` | No observable behavior change anywhere. |
| `performance` | Same as refactor: faster, same behavior. |
| `bugfix` | Behavior changes only in `changes_behavior_of` (a path also covers everything nested under it). |
| `feature` | Behavior may change; divergences are informational. |
| `unspecified` | No claim (the default); divergences are informational. |

## Policy

```toml
# .rebut/policy.toml
mode = "mark"                               # or "block"
engines = ["differential", "challenges"]

[budget]                                    # if present, give all five keys
vm_timeout_secs = 600
vcpus = 2
memory_mib = 4096
pr_vm_seconds = 1800
public_challenges = 64
```

Locally, `mode` affects the verdict label; whether the command fails is up to
`--fail-on-findings`. The `vcpus`/`memory_mib` limits and `sealed_commitments`
only apply in [hosted mode](hosted-mode.md). The full field reference is in
[`policies/README.md`](https://github.com/LaloNchera22/rebut/blob/main/policies/README.md).

## Command line

```text
rebut verify [--base <branch>] [--repo <path>] [--offline]
             [--engines differential,challenges] [--json] [--fail-on-findings]
rebut hook install [--base <branch>] [--force]
rebut hook uninstall
rebut seed --commit <sha> --round <n>
rebut challenges regenerate --commit <sha> --round <n> --spec <file>
```

`rebut <command> --help` has the details. Logging goes to stderr and follows
`RUST_LOG`.
