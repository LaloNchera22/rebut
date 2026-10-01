# Amplify your tests with challenges

A unit test checks one input. A challenge states a rule once and rebut
generates the inputs: different ones on every run, derived from a seed that
anyone can recompute.

Challenges live in **`.rebut/challenges.toml`**, and rebut reads that file from
the **base** branch. A branch can add challenges for future runs, but it can't
remove or weaken the ones it is checked against.

## Example

```toml
# .rebut/challenges.toml

[[challenge]]
id = "parse-never-panics"
target = "mylib::parse"
cases = 64
args = [{ ty = "&str", alphabet = "0123456789-+e.", len = [0, 12] }]
oracle = { kind = "no_panic" }

[[challenge]]
id = "clamp-in-range"
target = "mylib::clamp"
args = [{ ty = "i32", min = -1000, max = 1000 }, { ty = "i32", min = 0, max = 10 }]
oracle = { kind = "property", expr = "output.abs() <= *input.1" }

[[challenge]]
id = "base64-roundtrip"
target = "mylib::encode"
args = [{ ty = "&[u8]", len = [0, 64] }]
oracle = { kind = "roundtrip", decode = "mylib::decode", decode_returns = "result" }

[[challenge]]
id = "fast-sum-matches-naive"
target = "mylib::fast_sum"
args = [{ ty = "&[u8]", len = [0, 256] }]
oracle = { kind = "equals_reference", source = """
fn reference(xs: &[u8]) -> u64 { xs.iter().map(|&x| x as u64).sum() }
""" }
```

## Fields

| Key | Meaning |
|---|---|
| `id` | Unique name, `[A-Za-z0-9_-]`. |
| `target` | Path of the function under test, `crate::module::function`. |
| `args` | One entry per parameter, in order (see below). |
| `oracle` | What counts as correct (see below). |
| `cases` | Inputs per run, 1 to 4096. Default 32. |
| `category` | Optional label for findings. Defaults per oracle: `panic`, `property-violation`, `roundtrip-failure`, `reference-mismatch`. |
| `title` | Optional finding title. |

Each `args` entry:

| Key | Applies to | Meaning |
|---|---|---|
| `ty` | all | The parameter type as written in the signature: integers (`i8` to `i128`, `u8` to `u128`, `isize`, `usize`), `bool`, `char`, `&str`, `String`, `&[u8]`, `Vec<u8>`, references to these, and `Option<...>` of them. |
| `min`, `max` | integers | Inclusive bounds. Default: the type's whole range. |
| `alphabet` | strings, chars | Characters to draw from. |
| `len` | strings, byte slices | Inclusive length bounds, `[min, max]`. |

Oracles:

- `{ kind = "no_panic" }`: the call returns.
- `{ kind = "property", expr = "..." }`: a Rust boolean expression over `input`
  (a reference to the single argument, or a tuple of references) and `output`
  (the return value).
- `{ kind = "roundtrip", decode = "path" }`: `target` encodes its single
  argument and `decode` must give it back. `decode_returns` is `value`
  (default), `option` or `result`; `decode_by_ref` (default `true`) passes
  `&encoded`.
- `{ kind = "equals_reference", source = "..." }`: `source` defines
  `fn reference(..)` with the same parameters; the `Debug` output of both must
  match. Cases where the reference itself panics are skipped.

## Running them

Challenges run as part of `rebut verify` (the `challenges` engine is on by
default). A failure prints the input, the expected and the observed outcome,
like any other finding.

The total number of challenge cases per run is capped by the policy's
`budget.public_challenges` (default 64; see [Configuration](../configuration.md)).

## Reproducible inputs

The seed is `H(commit ‖ drand round ‖ randomness ‖ generator version)`, printed
on the `seed` line of every run. To see the exact inputs a run used:

```sh
rebut challenges regenerate --commit <head sha> --round <drand round> \
  --spec .rebut/challenges.toml
```

With `--offline`, the seed comes from a local pseudo-beacon instead of drand.

## Sealed challenges

The hosted service also supports **sealed** challenges: specs the maintainer
keeps private, whose SHA-256 is committed in `policy.toml`
(`sealed_commitments`), and whose failures only reveal a category. They only
make sense when the person running the check is not the person being checked,
so they belong to [hosted mode](../hosted-mode.md). In the
[GitHub Action](../github-action.md), anything secret is unavailable to pull
requests from forks.
