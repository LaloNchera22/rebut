# Guard your own AI agent

Coding agents are rewarded for "the tests pass". Sometimes they get there the
wrong way: special-casing the inputs the tests use, deleting or loosening an
assertion, catching a panic and returning a default, or changing behavior
nobody asked them to change. This is *reward hacking*, and a green test suite
can't see it, because the tests are part of what the agent edited.

rebut gives the agent (and you) a check that does not depend on the agent's
own tests: the base branch's behavior, on inputs the agent didn't choose.

## Add the MCP server

```sh
cargo install rebut-mcp --locked      # or brew install LaloNchera22/tap/rebut
claude mcp add rebut -- rebut-mcp
```

Any MCP client that speaks stdio works the same way: the command is
`rebut-mcp`, with no arguments.

The server offers these tools:

| Tool | What it does |
|---|---|
| `verify_local` | `rebut verify` on a checkout: `path`, `base` (default `main`), `offline`, `engines`. Returns the verdict with every finding's input, expected and observed output. |
| `derive_seed` | Recompute a challenge seed from a commit and a drand round. |
| `regenerate_challenges` | Regenerate the public challenge inputs for a seed. |
| `verify_receipt`, `get_report` | For [hosted mode](../hosted-mode.md) only. |

Then tell the agent when to use it, for example in `CLAUDE.md` or
`AGENTS.md`:

```markdown
Before you say a change is done, call the `verify_local` tool of the `rebut`
MCP server with `base = "main"`, and write `.rebut/intent.toml` saying what the
change is (`refactor`, `bugfix` with `changes_behavior_of`, `feature`). Fix
every finding, or explain why the behavior change is intended.
```

## Why the agent can't talk its way past it

- **The rules come from the base branch.** `.rebut/policy.toml` and
  `.rebut/challenges.toml` are read from the merge base, not from the agent's
  working tree. Editing them on the branch has no effect on the check.
- **Findings are executions, not opinions.** A finding exists only when a run
  of the base and head on a concrete input disagrees (or a challenge's oracle
  fails). The agent can't argue a finding away; it can only change the code.
- **The harness result channel is authenticated.** The generated harness
  reports its results over a channel the code under test cannot forge, so a
  function that prints a fake "ok" line to stdout is not believed.
- **Inputs are not known in advance.** Challenge inputs are drawn from a seed
  derived from the commit and public drand randomness, so special-casing last
  run's inputs doesn't help.

What it can't stop: the agent can still edit `.rebut/intent.toml` to claim a
`feature` and make divergences informational. Review the intent like you review
the diff, and use `--fail-on-findings` in the [pre-push hook](pre-push.md) or
the [GitHub Action](../github-action.md) so the check runs outside the agent's
loop too.

`verify_local` runs the agent's code unsandboxed on your machine, exactly like
the agent running `cargo test` itself. It adds no new exposure, and no new
protection either: if you don't trust the agent to run code, sandbox the agent.
