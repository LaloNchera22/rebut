# GitHub Action

The action runs `rebut verify` on every pull request, on GitHub's runner. The
runner is a fresh virtual machine that is discarded after the job, so it is
also the safe place to check code you didn't write.

> **Read the two caveats below before you rely on it.**
>
> 1. Pull requests from forks get **no secrets**, so nothing secret (such as
>    sealed challenges) can be checked there. Only the public checks run.
> 2. With `on: pull_request`, the workflow file comes from the pull request.
>    **A pull request can edit the workflow to skip rebut.** Review every change
>    under `.github/workflows/` by hand.

## Set it up

Copy [`examples/github-workflow.yml`](https://github.com/LaloNchera22/rebut/blob/main/examples/github-workflow.yml)
to `.github/workflows/rebut.yml`:

```yaml
name: rebut

on:
  pull_request:

permissions:
  contents: read

jobs:
  rebut:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: LaloNchera22/rebut@v0
```

The verdict and every finding appear in the job summary. In mark mode (the
default) findings also raise a warning annotation, and the job stays green.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `base` | the PR's base branch (`github.base_ref`), else the default branch | Branch to compare against. The action fetches it and runs `rebut verify --base origin/<base>`. |
| `fail-on-findings` | `"false"` | `"true"` fails the job on findings. Start in mark mode and switch once you trust it on your code. |
| `version` | `latest` | Release tag to install, such as `v0.1.0`. `source` builds the action's own checkout with cargo. |
| `args` | empty | Extra `rebut verify` arguments, split on whitespace, e.g. `--engines differential` or `--all-public`. |

Output: `report`, the path of the plain-text report.

What the action does:

1. Installs the prebuilt binary for the runner (Linux x86_64/arm64, macOS)
   from the GitHub Release and checks its sha256. If there is none, it falls
   back to `cargo install rebut --locked`.
2. Fetches the base branch with full history (the merge base needs it), then
   runs `cargo fetch --locked` for both sides, because rebut builds offline.
   Your repository must commit `Cargo.lock`.
3. Runs `rebut verify --base origin/<base>`, prints the report to the log and
   writes it to the job summary (`$GITHUB_STEP_SUMMARY`).

The runner needs a Rust toolchain. GitHub's Ubuntu and macOS images have one;
a `rust-toolchain.toml` in your repository is honoured.

## Caveat 1: no secrets on fork pull requests

GitHub does not pass repository secrets to workflows triggered by pull
requests from forks, and gives them a read-only token. That is what makes the
runner safe for untrusted code, and it also means anything that needs a secret
can't run there. Sealed challenges are private by definition, so on fork pull
requests only the public checks run: the differential engine and the public
challenges in `.rebut/challenges.toml`.

## Caveat 2: a pull request can edit the workflow

With `on: pull_request`, GitHub runs the workflow **as it is in the pull
request**. A contributor can delete the rebut step, set `args` to disable
engines, or replace the action with one that always passes, and the check
will look green.

Protect against it:

- Review every change to `.github/workflows/` (and to `action.yml` files) by
  hand, as carefully as code that handles your secrets.
- Make that review mandatory with a `CODEOWNERS` entry:

  ```text
  /.github/workflows/  @your-org/maintainers
  ```

  and a branch protection rule (or ruleset) on the default branch with
  **Require review from Code Owners** and **Require status checks to pass**
  listing the `rebut` job.
- A pull request that changes the workflow and passes is not evidence of
  anything until you've read the workflow change.

**Never** "fix" this with `pull_request_target` plus a checkout of the pull
request's code. `pull_request_target` runs with your repository's secrets and
a write token; building the pull request's code there hands both to the
contributor (their `build.rs` runs first). The policy and challenges are
already read from the base branch, so `pull_request` loses nothing that
`pull_request_target` would safely give you.

## Pinning

`@v0` follows the latest `0.x` release. To pin exactly, use a release tag
(`@v0.1.0`) or a commit SHA, and set `version` to the same tag so the binary
matches the action.
