# Usage scenarios

All five scenarios use the same command, `rebut verify`, pointed at different
things:

1. [Check your change before you push](pre-push.md): your own branch, from a
   git hook.
2. [Guard your own AI agent](agent.md): the branch your coding agent is working
   on, through the MCP server.
3. [Amplify your tests with challenges](challenges.md): a few lines of
   `.rebut/challenges.toml` that generate fresh inputs on every run.
4. [Review dependency updates](dependencies.md): a branch that only changes
   `Cargo.lock`.
5. [Review someone else's pull request](review-prs.md): code you did not
   write, which needs a sandbox.

What every run does:

1. Finds the merge base of `HEAD` and `--base` and extracts that tree from git
   history (never from your working tree).
2. Reads `.rebut/policy.toml` and `.rebut/challenges.toml` from the **base**
   tree, and `.rebut/intent.toml` from the **head**. Your branch can say what
   it claims to do, but it cannot change the rules it is checked against.
3. Plans: parses both trees with `syn`, finds the functions that changed and
   the tests that reach them.
4. Runs the engines: **differential** (base and head on the same generated
   inputs) and **challenges** (your challenge specs, seeded from
   [drand](https://drand.love) public randomness, or from a local
   pseudo-beacon with `--offline`).
5. Prints the verdict: `PASS`, `FLAGGED` (findings, mark mode), `FAIL` or
   `INCONCLUSIVE` (it could not check, for example because the build failed).
   `--json` prints everything machine-readable.

By default rebut *marks*: it exits 0 even with findings. `--fail-on-findings`
makes findings exit 1. Errors exit 2.

rebut builds with `cargo build --locked --offline`, so commit `Cargo.lock` and
make sure the dependencies are in your cargo cache (`cargo fetch`).
