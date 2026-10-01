# Review someone else's pull request

This is the one scenario where you must think about where the code runs.

## Local mode is not a sandbox

`rebut verify` builds and runs the head with your user account, your files,
your SSH keys and your network, exactly like `cargo test`. A pull request
controls far more than its tests: `build.rs`, proc-macros and every dependency
it adds all run **at build time**, before any check does. Running
`rebut verify` on a stranger's branch is running a stranger's program.

So, for code you didn't write and haven't read:

- **Don't** check it out and run `rebut verify` on your workstation.
- **Do** run it somewhere disposable:
  - the [GitHub Action](../github-action.md): the runner is a fresh VM that is
    thrown away after the job, with a read-only token and no secrets on pull
    requests from forks. That disposable runner is the sandbox;
  - or a throwaway VM or container you control, with no credentials in it and
    no network access beyond what the build needs.

A container that shares your home directory, your Docker socket or your cloud
credentials is not a sandbox.

## On the runner

With the [example workflow](../github-action.md#set-it-up), every pull request
gets a `rebut` job whose summary shows the verdict and each finding's input,
expected and observed output. In mark mode (the default) the check stays
green and the findings are a review aid; you decide.

Read the intent manifest (`.rebut/intent.toml` in the PR) as part of the
review: it is the contributor's claim, and rebut checks the code against it.
A `refactor` with a divergence is a false claim. A `feature` makes divergences
informational; ask whether that is honest.

## Future work: local sandboxes

Running untrusted pull requests safely on your own machine needs an isolating
backend. Two are planned and neither exists yet:

- a **WebAssembly** backend (build to `wasm32-wasip1`, run harnesses under a
  WASI runtime with no file system or network access), for crates that compile
  to WebAssembly;
- the **Firecracker** microVM backend of [hosted mode](../hosted-mode.md),
  usable locally on Linux hosts with KVM.

Until then, the disposable runner is the supported way.
