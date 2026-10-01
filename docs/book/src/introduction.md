# rebut

**rebut** checks that a Rust change does what it claims by running it. It builds
your branch (head) and the commit it started from (base), runs both on the same
generated inputs, and reports every function whose behavior changed when your
change said it wouldn't. It also runs challenge inputs that you write once and
that are re-drawn from public randomness on every run.

A finding is never an opinion. Each one carries a concrete input, the output
the base produced and the output the head produced, so you can replay it
yourself. Language models can *propose* inputs (see
[Rival agent](rival-agent.md)), but a guess only becomes a finding after a
recorded execution reproduces it.

rebut is a free, open-source command-line tool. It runs on your machine or on
your CI runner. There is no server, no database and no account.

```sh
cargo install rebut --locked
cd your-crate
rebut verify --base main
```

## What it is for

| Scenario | Chapter |
|---|---|
| Catch a behavior change your tests miss, before `git push` | [Check your change before you push](scenarios/pre-push.md) |
| Stop a coding agent from "passing" by weakening the code or the tests | [Guard your own AI agent](scenarios/agent.md) |
| Turn a few lines of TOML into hundreds of fresh test inputs | [Amplify your tests with challenges](scenarios/challenges.md) |
| See what a `cargo update` actually changed | [Review dependency updates](scenarios/dependencies.md) |
| Look at a contributor's pull request | [Review someone else's pull request](scenarios/review-prs.md) |

## What it is not

- **Not a sandbox.** `rebut verify` builds and runs code exactly like
  `cargo test` does: unsandboxed, with your user's permissions. Run it on code
  you would run anyway. For code you don't trust, use the
  [GitHub Action](github-action.md), where a disposable runner plays the role
  of the sandbox.
- **Not a proof.** rebut samples inputs. A pass means "nothing we tried
  behaved differently", not "equivalent".
- **Rust only**, for now.

The [hosted mode](hosted-mode.md) (a control plane with Firecracker microVMs
and signed receipts in a transparency log) is experimental and is not needed
for anything in this book.
