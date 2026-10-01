# Review dependency updates

A `cargo update` or a Dependabot pull request changes `Cargo.lock` and nothing
else. Your tests pass, but did your crate's behavior change? A new minor
version of a parser, a float formatting crate or a regex engine can change
results without breaking a single test.

No function in your crate changed, so the normal plan would have nothing to
compare. When the diff touches only `Cargo.toml`/`Cargo.lock` (no `.rs` file,
nothing under `src/`), rebut switches on its own to **every public function**
reachable from the crate root, and compares base (old lockfile) and head (new
lockfile) on the same generated inputs. `--all-public` forces this for any
diff; `--max-functions` caps it (default 200).

```sh
git switch dependabot/cargo/serde_json-1.0.140
cargo fetch                      # rebut builds with --offline
rebut verify --base main
# plan: dependency change, comparing 37 public fn(s) (5 skipped: unsupported signatures), ...
```

Any divergence is listed with its input, the output under the old
dependencies and the output under the new ones. A function whose own code did
not change is never excused by an unspecified intent; to accept a known change,
name the function in `changes_behavior_of` in `.rebut/intent.toml`.

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
- For a Dependabot pull request, the GitHub Action runs on it automatically
  and picks this mode by itself.
