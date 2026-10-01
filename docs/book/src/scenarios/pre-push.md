# Check your change before you push

Tests check the cases someone thought of. rebut checks the cases nobody wrote
down, by comparing your branch with the code it replaces.

## A green refactor that isn't one

Start with a crate whose `main` branch has:

```rust
pub fn clamp_add(a: u8, b: u8) -> u8 {
    a.saturating_add(b)
}

#[cfg(test)]
mod tests {
    #[test]
    fn small() {
        assert_eq!(super::clamp_add(1, 2), 3);
    }
}
```

On a branch, someone "simplifies" it:

```rust
pub fn clamp_add(a: u8, b: u8) -> u8 {
    a.wrapping_add(b)
}
```

`cargo test` still passes: `1 + 2` is `3` either way. Say what the change is
supposed to be by committing `.rebut/intent.toml`:

```toml
kind = "refactor"   # no observable behavior change
```

Then run:

```console
$ rebut verify --base main
note: building and running your code locally, unsandboxed (like `cargo test`)
base 3f1c...  head 9a7e...
seed 5d0b... (drand round 1234567)
plan: 1 changed fn(s), 1 test(s)

[FINDING] differential / behavior-divergence: `demo::clamp_add` behaves differently on head than on base for a generated input
  target:   demo::clamp_add
  input:    255 255
  expected: exit:Some(0) | #harness-start | case 0 ok "255"
  observed: exit:Some(0) | #harness-start | case 0 ok "254"
  transcript: ...

FLAGGED (mark mode: not blocking)
```

rebut lists every diverging input it found (only the first is shown here).
`expected` is what the base returned, `observed` is what the head returned, for
`clamp_add(255, 255)`. The refactor claim is false.

Without an intent file the claim is `unspecified`: divergences are still
listed, as informational, and don't count as findings. Use `kind = "bugfix"`
with `changes_behavior_of = ["demo::clamp_add"]` when a behavior change is the
point. See [Configuration](../configuration.md).

## Run it on every push

```sh
rebut hook install            # compares against main
rebut hook install --base develop
```

This writes the repository's `pre-push` hook (`.git/hooks/pre-push`, or
wherever `core.hooksPath` points) with:

```sh
exec rebut verify --base main --fail-on-findings
```

so a push with findings is stopped. To push anyway, once:
`git push --no-verify`.

- `rebut hook install` refuses to replace a `pre-push` hook it did not write.
  Pass `--force` to replace it, or call `rebut verify` from your existing hook.
- `rebut hook uninstall` removes the hook, and only if rebut wrote it.

The hook runs the full check, which builds both sides. On a large crate,
narrow it with `--engines differential` by editing the hook, or run
`rebut verify` by hand instead.

## Tips

- Uncommitted changes are included: with a dirty tree, the head is your working
  tree (reported as `(uncommitted tree)`).
- `--offline` skips the drand fetch and uses a clearly labelled local
  pseudo-beacon. Inputs are still generated, just from a local seed.
- `--json` for scripts; `--engines differential,challenges` to choose engines.
