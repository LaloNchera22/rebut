//! Deterministic input generation.
//!
//! Everything here is a pure function of a [`Seed`]: ChaCha20 seeded with the
//! seed bytes, and sampling written against the raw `u64` stream only (no
//! `rand` distributions), so the cases for a given seed stay the same across
//! dependency upgrades. That is what lets anyone regenerate public challenge
//! inputs from a published seed (ADR-7).

use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rebut_core::Seed;

use crate::harness::{ArgType, IntTy, Scalar, Value};

/// Deterministic generator.
pub struct Rng(ChaCha20Rng);

impl Rng {
    pub fn new(seed: &Seed) -> Rng {
        Rng(ChaCha20Rng::from_seed(seed.bytes()))
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    pub fn next_u128(&mut self) -> u128 {
        (u128::from(self.next_u64()) << 64) | u128::from(self.next_u64())
    }

    /// Uniform in `0..n` (`n > 0`), by rejection sampling.
    pub fn below(&mut self, n: u128) -> u128 {
        assert!(n > 0, "empty range");
        // Largest multiple of n that fits, minus one.
        let zone = u128::MAX - (u128::MAX - n + 1) % n;
        loop {
            let x = self.next_u128();
            if x <= zone {
                return x % n;
            }
        }
    }

    /// Uniform in `lo..=hi` (`lo <= hi`), for spans that fit in `u128`.
    pub fn range(&mut self, lo: i128, hi: i128) -> i128 {
        let span = (hi as u128).wrapping_sub(lo as u128);
        let off = if span == u128::MAX {
            self.next_u128()
        } else {
            self.below(span + 1)
        };
        (lo as u128).wrapping_add(off) as i128
    }

    /// True with probability `num/den`.
    pub fn chance(&mut self, num: u128, den: u128) -> bool {
        self.below(den) < num
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u128) as usize]
    }
}

/// Optional restrictions on generated values (from challenge specs). They
/// apply to the scalar inside an `Option`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Constraints {
    /// Inclusive integer range; must lie within the integer type.
    pub int_range: Option<(i128, i128)>,
    /// Characters for strings and chars.
    pub alphabet: Option<Vec<char>>,
    /// Inclusive length range for strings and byte vectors.
    pub len: Option<(usize, usize)>,
}

/// Default string alphabet: printable ASCII plus a few characters that
/// commonly break parsers (multi-byte, NUL, control, bidi override).
pub fn default_alphabet() -> Vec<char> {
    let mut v: Vec<char> = (0x20u8..0x7f).map(char::from).collect();
    v.extend([
        'é', 'ß', '日', '本', '🦀', '\0', '\n', '\t', '\u{202e}', '\u{fffd}',
    ]);
    v
}

/// Length range for strings and byte vectors when a spec gives none.
pub const DEFAULT_LEN: (usize, usize) = (0, 24);

fn int_value(ty: IntTy, v: i128) -> Value {
    if ty.signed {
        Value::Int(v)
    } else {
        Value::UInt(v as u128)
    }
}

fn int_max(ty: IntTy) -> Value {
    if ty.signed {
        Value::Int(ty.max_u128() as i128)
    } else {
        Value::UInt(ty.max_u128())
    }
}

/// Boundary values for a scalar.
fn scalar_edges(s: Scalar) -> Vec<Value> {
    match s {
        Scalar::Int(ty) => {
            let mut v = vec![
                int_value(ty, 0),
                int_value(ty, 1),
                int_value(ty, 2),
                int_max(ty),
                if ty.signed {
                    Value::Int(ty.max_u128() as i128 - 1)
                } else {
                    Value::UInt(ty.max_u128() - 1)
                },
            ];
            if ty.signed {
                v.extend([
                    Value::Int(-1),
                    Value::Int(ty.min_i128()),
                    Value::Int(ty.min_i128() + 1),
                ]);
            }
            v
        }
        Scalar::Bool => vec![Value::Bool(false), Value::Bool(true)],
        Scalar::Char => ['a', '\0', ' ', 'é', '🦀', '\u{10ffff}', '9']
            .into_iter()
            .map(Value::Char)
            .collect(),
        Scalar::Str => [
            "",
            "a",
            " ",
            "0",
            "-1",
            "é",
            "日本語",
            "🦀",
            "a\nb",
            "\0",
            &"a".repeat(1024),
        ]
        .into_iter()
        .map(|s| Value::Str(s.to_string()))
        .collect(),
        Scalar::Bytes => vec![
            Value::Bytes(vec![]),
            Value::Bytes(vec![0]),
            Value::Bytes(vec![255]),
            Value::Bytes(vec![1, 2, 3]),
            Value::Bytes(vec![0; 1024]),
        ],
    }
}

/// Boundary values for an argument type (`None` first for options).
pub fn edge_values(ty: &ArgType) -> Vec<Value> {
    let inner = scalar_edges(ty.scalar);
    if ty.optional {
        std::iter::once(Value::None)
            .chain(inner.into_iter().map(|v| Value::Some(Box::new(v))))
            .collect()
    } else {
        inner
    }
}

/// A random value of `ty` under `c`.
pub fn random_value(rng: &mut Rng, ty: &ArgType, c: &Constraints) -> Value {
    if ty.optional {
        if rng.chance(1, 4) {
            return Value::None;
        }
        return Value::Some(Box::new(random_scalar(rng, ty.scalar, c)));
    }
    random_scalar(rng, ty.scalar, c)
}

fn random_len(rng: &mut Rng, c: &Constraints) -> usize {
    let (lo, hi) = c.len.unwrap_or(DEFAULT_LEN);
    rng.range(lo as i128, hi as i128) as usize
}

fn random_scalar(rng: &mut Rng, s: Scalar, c: &Constraints) -> Value {
    match s {
        Scalar::Int(ty) => {
            if let Some((lo, hi)) = c.int_range {
                return int_value(ty, rng.range(lo, hi));
            }
            // Half full-width random bits, half small magnitudes, where most
            // interesting behavior lives.
            if rng.chance(1, 2) {
                let shift = 128 - ty.bits;
                let x = rng.next_u128();
                if ty.signed {
                    Value::Int(((x << shift) as i128) >> shift)
                } else {
                    Value::UInt((x << shift) >> shift)
                }
            } else if ty.signed {
                Value::Int(rng.range(-16, 16).max(ty.min_i128()))
            } else {
                Value::UInt(rng.range(0, 32) as u128)
            }
        }
        Scalar::Bool => Value::Bool(rng.chance(1, 2)),
        Scalar::Char => Value::Char(match &c.alphabet {
            Some(a) => *rng.pick(a),
            None => {
                if rng.chance(1, 2) {
                    char::from(rng.range(0x20, 0x7e) as u8)
                } else {
                    loop {
                        if let Some(ch) = char::from_u32(rng.below(0x11_0000) as u32) {
                            break ch;
                        }
                    }
                }
            }
        }),
        Scalar::Str => {
            let alphabet = c.alphabet.clone().unwrap_or_else(default_alphabet);
            let n = random_len(rng, c);
            Value::Str((0..n).map(|_| *rng.pick(&alphabet)).collect())
        }
        Scalar::Bytes => {
            let n = random_len(rng, c);
            Value::Bytes((0..n).map(|_| rng.below(256) as u8).collect())
        }
    }
}

/// Differential cases: first the boundary values (diagonally across the
/// arguments), then random cases where each argument is a boundary value one
/// time in four. A zero-argument function gets a single case.
pub fn differential_cases(args: &[ArgType], seed: &Seed, n: usize) -> Vec<Vec<Value>> {
    if args.is_empty() {
        return vec![vec![]];
    }
    let mut rng = Rng::new(seed);
    let edges: Vec<Vec<Value>> = args.iter().map(edge_values).collect();
    let diagonal = edges.iter().map(Vec::len).max().unwrap_or(0).min(n);
    let mut cases: Vec<Vec<Value>> = (0..diagonal)
        .map(|i| edges.iter().map(|e| e[i % e.len()].clone()).collect())
        .collect();
    while cases.len() < n {
        let case = args
            .iter()
            .zip(&edges)
            .map(|(ty, e)| {
                if rng.chance(1, 4) {
                    rng.pick(e).clone()
                } else {
                    random_value(&mut rng, ty, &Constraints::default())
                }
            })
            .collect();
        cases.push(case);
    }
    cases
}

#[cfg(test)]
mod tests {
    use super::*;
    use rebut_core::Digest;

    fn seed(s: &str) -> Seed {
        Seed(Digest::of(s.as_bytes()))
    }

    #[test]
    fn deterministic_and_seed_sensitive() {
        let args = [
            ArgType::parse("i16").unwrap(),
            ArgType::parse("Option<&str>").unwrap(),
        ];
        let a = differential_cases(&args, &seed("x"), 40);
        assert_eq!(a, differential_cases(&args, &seed("x"), 40));
        assert_ne!(a, differential_cases(&args, &seed("y"), 40));
        assert_eq!(a.len(), 40);
        // Boundary values come first.
        assert_eq!(a[0], vec![Value::Int(0), Value::None]);
        assert_eq!(a[3][0], Value::Int(i16::MAX as i128));
    }

    #[test]
    fn values_respect_types_and_constraints() {
        let mut rng = Rng::new(&seed("c"));
        let u8t = ArgType::parse("u8").unwrap();
        let i8t = ArgType::parse("i8").unwrap();
        let s = ArgType::parse("String").unwrap();
        let c = Constraints {
            int_range: Some((-3, 3)),
            alphabet: Some(vec!['x', 'y']),
            len: Some((2, 4)),
        };
        for _ in 0..500 {
            match random_value(&mut rng, &u8t, &Constraints::default()) {
                Value::UInt(v) => assert!(v <= 255),
                other => panic!("{other:?}"),
            }
            match random_value(&mut rng, &i8t, &Constraints::default()) {
                Value::Int(v) => assert!((-128..=127).contains(&v)),
                other => panic!("{other:?}"),
            }
            match random_value(&mut rng, &i8t, &c) {
                Value::Int(v) => assert!((-3..=3).contains(&v)),
                other => panic!("{other:?}"),
            }
            match random_value(&mut rng, &s, &c) {
                Value::Str(v) => {
                    assert!((2..=4).contains(&v.chars().count()));
                    assert!(v.chars().all(|ch| ch == 'x' || ch == 'y'));
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn range_handles_extremes() {
        let mut rng = Rng::new(&seed("r"));
        for _ in 0..100 {
            let v = rng.range(i128::MIN, i128::MAX);
            let _ = v;
            assert_eq!(rng.range(7, 7), 7);
            assert!((0..3).contains(&rng.below(3)));
        }
    }

    #[test]
    fn zero_arity_has_one_case() {
        assert_eq!(differential_cases(&[], &seed("z"), 10), vec![vec![]]);
    }
}
