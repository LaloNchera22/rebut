# Review dependency updates

A `cargo update` or a Dependabot pull request changes `Cargo.lock` and nothing
else. Your tests pass, but did your crate's behavior change? A new minor
version of a parser, a float formatting crate or a regex engine can change
results without breaking a single test.

The normal plan has nothing to compare here: no function in your crate
changed. `--all-public` makes rebut run the differential engine on **every
public function** of the crate instead of only the changed ones, so base (old
lockfile) and head (new lockfile) are compared on the same generated inputs:

```sh
git switch dependabot/cargo/serde_json-1.0.140
cargo fetch                      # rebut builds with --offline
rebut verify --base main --all-public
```

Any divergence is listed with its input, the output under the old
dependencies and the output under the new ones. Write the intent so the
verdict means something:

```toml
# .rebut/intent.toml
kind = "refactor"   # "this update should not change what my crate does"
```

Notes:

- Only functions whose argument types rebut can generate are exercised
  (integers, `bool`, `char`, strings, byte slices and `Option`s of them). Wider
  coverage comes from [challenges](challenges.md), which also run on every
  update.
- `--all-public` builds and calls a lot of code. As always, this runs
  unsandboxed: the new dependency versions run on your machine, their build
  scripts included, just as they would with `cargo build`. If you haven't
  decided to trust the update yet, run it in the
  [GitHub Action](../github-action.md) instead.
- For a Dependabot pull request, the GitHub Action runs on it automatically;
  add `args: --all-public` to the step.
