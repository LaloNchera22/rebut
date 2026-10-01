//! Challenge specs, written by maintainers in TOML.
//!
//! ```toml
//! [[challenge]]
//! id = "parse-never-panics"
//! target = "mylib::parse"
//! category = "panic"          # optional; defaults per oracle
//! cases = 64                  # optional
//! args = [{ ty = "&str", alphabet = "0123456789-+e.", len = [0, 12] }]
//! oracle = { kind = "no_panic" }
//!
//! [[challenge]]
//! id = "clamp-in-range"
//! target = "mylib::clamp"
//! args = [{ ty = "i32", min = -1000, max = 1000 }, { ty = "i32", min = 0, max = 10 }]
//! oracle = { kind = "property", expr = "output.abs() <= *input.1" }
//! ```
//!
//! Oracles:
//!
//! * `no_panic` — the call returns.
//! * `equals_reference` — `source` defines `fn reference(..)` with the same
//!   parameters; the `Debug` of both results must match (cases where the
//!   reference itself panics are skipped).
//! * `roundtrip` — `target` encodes its single argument, `decode` must give
//!   it back. `decode_returns` is `value`, `option` or `result`;
//!   `decode_by_ref` (default true) passes `&encoded`.
//! * `property` — `expr` is a Rust boolean expression over `input` (a
//!   reference to the single argument, or a tuple of references) and
//!   `output` (the return value).
//!
//! Public specs live in `.rebut/challenges.toml` on the base branch.
//! Sealed specs are supplied privately and are only accepted when their
//! SHA-256 is one of `policy.sealed_commitments`.

use std::collections::BTreeSet;

use rebut_core::{Digest, Seed, Visibility};
use rebut_differential::gen::{self, Constraints, Rng};
use rebut_differential::harness::{self, ArgType, Scalar, Value};
use serde::Deserialize;

pub const MAX_CASES: u32 = 4096;
const MAX_LEN: usize = 1 << 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpecError {
    #[error("invalid challenge TOML: {0}")]
    Toml(String),
    #[error("sealed spec {0} does not match any commitment in the policy")]
    UncommittedSealedSpec(Digest),
    #[error("challenge `{id}`: {msg}")]
    Invalid { id: String, msg: String },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpecFile {
    #[serde(default, rename = "challenge")]
    pub challenges: Vec<ChallengeSpec>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChallengeSpec {
    pub id: String,
    /// Path of the function under test (`crate::module::function`).
    pub target: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default = "default_cases")]
    pub cases: u32,
    #[serde(default)]
    pub args: Vec<ArgSpec>,
    pub oracle: Oracle,
}

fn default_cases() -> u32 {
    32
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArgSpec {
    /// Rust type as written in the target's signature (`&str`, `u32`,
    /// `Option<&[u8]>`...).
    pub ty: String,
    /// Inclusive integer bounds (default: the type's range).
    pub min: Option<i64>,
    pub max: Option<i64>,
    /// Characters for strings and chars.
    pub alphabet: Option<String>,
    /// Inclusive length bounds for strings and byte vectors.
    pub len: Option<[usize; 2]>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecodeReturns {
    #[default]
    Value,
    Option,
    Result,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Oracle {
    NoPanic,
    EqualsReference {
        source: String,
    },
    Roundtrip {
        decode: String,
        #[serde(default)]
        decode_returns: DecodeReturns,
        #[serde(default = "yes")]
        decode_by_ref: bool,
    },
    Property {
        expr: String,
    },
}

impl Oracle {
    pub fn default_category(&self) -> &'static str {
        match self {
            Oracle::NoPanic => "panic",
            Oracle::EqualsReference { .. } => "reference-mismatch",
            Oracle::Roundtrip { .. } => "roundtrip-failure",
            Oracle::Property { .. } => "property-violation",
        }
    }
}

/// A validated challenge, ready to generate and run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub spec: ChallengeSpec,
    pub args: Vec<ArgType>,
    pub constraints: Vec<Constraints>,
    pub visibility: Visibility,
}

impl Challenge {
    pub fn category(&self) -> String {
        self.spec
            .category
            .clone()
            .unwrap_or_else(|| self.spec.oracle.default_category().to_string())
    }

    pub fn title(&self) -> String {
        self.spec.title.clone().unwrap_or_else(|| {
            format!(
                "challenge `{}` failed on `{}`",
                self.spec.id, self.spec.target
            )
        })
    }
}

/// Parses public specs (`.rebut/challenges.toml`).
pub fn parse_public(toml_src: &str) -> Result<Vec<Challenge>, SpecError> {
    parse(toml_src, Visibility::Public)
}

/// Parses a sealed spec after checking its SHA-256 against the policy's
/// commitments; an uncommitted spec is rejected.
pub fn parse_sealed(toml_src: &str, commitments: &[Digest]) -> Result<Vec<Challenge>, SpecError> {
    let d = Digest::of(toml_src.as_bytes());
    if !commitments.contains(&d) {
        return Err(SpecError::UncommittedSealedSpec(d));
    }
    parse(toml_src, Visibility::Sealed)
}

fn parse(toml_src: &str, visibility: Visibility) -> Result<Vec<Challenge>, SpecError> {
    let file: SpecFile = toml::from_str(toml_src).map_err(|e| SpecError::Toml(e.to_string()))?;
    let mut ids = BTreeSet::new();
    file.challenges
        .into_iter()
        .map(|spec| {
            if !ids.insert(spec.id.clone()) {
                return Err(invalid(&spec.id, "duplicate id"));
            }
            validate(spec, visibility)
        })
        .collect()
}

fn invalid(id: &str, msg: impl Into<String>) -> SpecError {
    SpecError::Invalid {
        id: id.to_string(),
        msg: msg.into(),
    }
}

fn validate(spec: ChallengeSpec, visibility: Visibility) -> Result<Challenge, SpecError> {
    let id = spec.id.as_str();
    let id_ok = !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !id_ok {
        return Err(invalid(id, "id must be non-empty [A-Za-z0-9_-]"));
    }
    if !harness::is_plain_path(&spec.target) {
        return Err(invalid(
            id,
            "target must be a plain path like `krate::module::f`",
        ));
    }
    if spec.cases == 0 || spec.cases > MAX_CASES {
        return Err(invalid(id, format!("cases must be in 1..={MAX_CASES}")));
    }
    let mut args = Vec::new();
    let mut constraints = Vec::new();
    for (i, a) in spec.args.iter().enumerate() {
        let ty = ArgType::parse(&a.ty)
            .ok_or_else(|| invalid(id, format!("argument {i}: unsupported type `{}`", a.ty)))?;
        constraints
            .push(arg_constraints(a, &ty).map_err(|m| invalid(id, format!("argument {i}: {m}")))?);
        args.push(ty);
    }
    match &spec.oracle {
        Oracle::NoPanic => {}
        Oracle::EqualsReference { source } => {
            let file = syn::parse_file(source)
                .map_err(|e| invalid(id, format!("reference source: {e}")))?;
            let has_reference = file
                .items
                .iter()
                .any(|it| matches!(it, syn::Item::Fn(f) if f.sig.ident == "reference"));
            if !has_reference {
                return Err(invalid(id, "reference source must define `fn reference`"));
            }
        }
        Oracle::Roundtrip { decode, .. } => {
            if args.len() != 1 {
                return Err(invalid(id, "roundtrip needs exactly one argument"));
            }
            if !harness::is_plain_path(decode) {
                return Err(invalid(id, "decode must be a plain path"));
            }
        }
        Oracle::Property { expr } => {
            syn::parse_str::<syn::Expr>(expr)
                .map_err(|e| invalid(id, format!("property expression: {e}")))?;
        }
    }
    Ok(Challenge {
        spec,
        args,
        constraints,
        visibility,
    })
}

fn arg_constraints(a: &ArgSpec, ty: &ArgType) -> Result<Constraints, String> {
    let mut c = Constraints::default();
    match ty.scalar {
        Scalar::Int(it) => {
            let lo = a.min.map_or(it.min_i128(), i128::from);
            let hi = match a.max {
                Some(m) => i128::from(m),
                None => it.max_u128().min(i128::MAX as u128) as i128,
            };
            if a.min.is_some() || a.max.is_some() {
                if lo < it.min_i128() || (hi >= 0 && hi as u128 > it.max_u128()) {
                    return Err(format!("bounds outside the range of {}", a.ty));
                }
                if lo > hi {
                    return Err("min > max".into());
                }
                c.int_range = Some((lo, hi));
            }
        }
        _ if a.min.is_some() || a.max.is_some() => {
            return Err("min/max only apply to integers".into());
        }
        _ => {}
    }
    if let Some(alpha) = &a.alphabet {
        if !matches!(ty.scalar, Scalar::Str | Scalar::Char) {
            return Err("alphabet only applies to strings and chars".into());
        }
        let chars: Vec<char> = alpha.chars().collect();
        if chars.is_empty() {
            return Err("empty alphabet".into());
        }
        c.alphabet = Some(chars);
    }
    if let Some([lo, hi]) = a.len {
        if !matches!(ty.scalar, Scalar::Str | Scalar::Bytes) {
            return Err("len only applies to strings and byte vectors".into());
        }
        if lo > hi || hi > MAX_LEN {
            return Err(format!("len must satisfy lo <= hi <= {MAX_LEN}"));
        }
        c.len = Some((lo, hi));
    }
    Ok(c)
}

/// Boundary value of an argument under its constraints (`high` = upper end).
fn boundary(ty: &ArgType, c: &Constraints, high: bool) -> Value {
    if ty.optional && !high {
        return Value::None;
    }
    let (lo_len, hi_len) = c.len.unwrap_or(gen::DEFAULT_LEN);
    let len = if high { hi_len } else { lo_len };
    let v = match ty.scalar {
        Scalar::Int(it) => {
            let (lo, hi) = c
                .int_range
                .unwrap_or((it.min_i128(), it.max_u128().min(i128::MAX as u128) as i128));
            match (it.signed, high, c.int_range.is_some()) {
                // Full-range u128 max does not fit i128.
                (false, true, false) => Value::UInt(it.max_u128()),
                (false, _, _) => Value::UInt(if high { hi } else { lo } as u128),
                (true, _, _) => Value::Int(if high { hi } else { lo }),
            }
        }
        Scalar::Bool => Value::Bool(high),
        Scalar::Char | Scalar::Str => {
            let alphabet = c.alphabet.clone().unwrap_or_else(gen::default_alphabet);
            let ch = if high {
                alphabet[alphabet.len() - 1]
            } else {
                alphabet[0]
            };
            if ty.scalar == Scalar::Char {
                Value::Char(ch)
            } else {
                Value::Str(ch.to_string().repeat(len))
            }
        }
        Scalar::Bytes => Value::Bytes(vec![if high { 0xff } else { 0 }; len]),
    };
    if ty.optional {
        Value::Some(Box::new(v))
    } else {
        v
    }
}

/// Generates the cases of a challenge: a pure function of the spec and
/// `seed.fork(spec.id)`, so anyone holding the published seed and a public
/// spec regenerates exactly the same inputs. The first two cases are the
/// lower and upper boundaries; `n` cases are a prefix of `n + k` cases.
pub fn generate_cases(ch: &Challenge, seed: &Seed, n: usize) -> Vec<Vec<Value>> {
    let mut rng = Rng::new(&seed.fork(&ch.spec.id));
    (0..n)
        .map(|i| {
            ch.args
                .iter()
                .zip(&ch.constraints)
                .map(|(ty, c)| match i {
                    0 => boundary(ty, c, false),
                    1 => boundary(ty, c, true),
                    _ => gen::random_value(&mut rng, ty, c),
                })
                .collect()
        })
        .collect()
}

/// Harness source for a challenge. Payloads: `pass`, `fail`, `skip` (the
/// reference panicked) or `panic` (the target panicked).
pub fn harness_source(ch: &Challenge) -> String {
    let call = format!("{}({})", ch.spec.target, harness::call_args(&ch.args));
    let pass_fail = |cond: &str| {
        format!("if {cond} {{ String::from(\"pass\") }} else {{ String::from(\"fail\") }}")
    };
    let (items, body) = match &ch.spec.oracle {
        Oracle::NoPanic => (
            String::new(),
            format!("let _ = {call};\n            String::from(\"pass\")"),
        ),
        Oracle::EqualsReference { source } => {
            let reference = format!("reference({})", harness::call_args(&ch.args));
            (
                source.clone(),
                format!(
                    "let __want = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| format!(\"{{:?}}\", {reference}))) {{\n                \
                     Ok(w) => w,\n                Err(_) => return String::from(\"skip\"),\n            }};\n            \
                     let __got = format!(\"{{:?}}\", {call});\n            {}",
                    pass_fail("__got == __want")
                ),
            )
        }
        Oracle::Roundtrip {
            decode,
            decode_returns,
            decode_by_ref,
        } => {
            let enc = if *decode_by_ref { "&__enc" } else { "__enc" };
            let cond = match decode_returns {
                DecodeReturns::Value => "__dec == a0",
                DecodeReturns::Option => "__dec.as_ref() == Some(&a0)",
                DecodeReturns::Result => "__dec.as_ref().ok() == Some(&a0)",
            };
            (
                String::new(),
                format!(
                    "let __enc = {call};\n            let __dec = {decode}({enc});\n            {}",
                    pass_fail(cond)
                ),
            )
        }
        Oracle::Property { expr } => {
            let input = match ch.args.len() {
                0 => "()".to_string(),
                1 => "&a0".to_string(),
                n => format!(
                    "({})",
                    (0..n)
                        .map(|i| format!("&a{i}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            (
                String::new(),
                format!(
                    "let input = {input};\n            let output = {call};\n            {}",
                    pass_fail(&format!("({expr})"))
                ),
            )
        }
    };
    harness::harness_source(&ch.args, &items, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const SPECS: &str = r#"
[[challenge]]
id = "parse-no-panic"
target = "mylib::parse"
cases = 40
args = [{ ty = "&str", alphabet = "0123456789-", len = [0, 6] }]
oracle = { kind = "no_panic" }

[[challenge]]
id = "clamp"
target = "mylib::clamp"
category = "range"
args = [{ ty = "i32", min = -1000, max = 1000 }, { ty = "Option<u8>" }]
oracle = { kind = "property", expr = "output >= -100 && output <= 100" }

[[challenge]]
id = "hex-roundtrip"
target = "mylib::to_hex"
args = [{ ty = "&[u8]", len = [0, 8] }]

[challenge.oracle]
kind = "roundtrip"
decode = "mylib::from_hex"
decode_returns = "option"

[[challenge]]
id = "abs-matches"
target = "mylib::abs"
args = [{ ty = "i64" }]

[challenge.oracle]
kind = "equals_reference"
source = "fn reference(x: i64) -> i64 { x.abs() }"
"#;

    fn seed(s: &str) -> Seed {
        Seed(Digest::of(s.as_bytes()))
    }

    #[test]
    fn parses_all_oracles() {
        let chs = parse_public(SPECS).unwrap();
        assert_eq!(chs.len(), 4);
        assert_eq!(chs[0].category(), "panic");
        assert_eq!(chs[1].category(), "range");
        assert_eq!(chs[1].constraints[0].int_range, Some((-1000, 1000)));
        assert!(chs.iter().all(|c| c.visibility == Visibility::Public));
        assert!(matches!(
            chs[2].spec.oracle,
            Oracle::Roundtrip {
                decode_returns: DecodeReturns::Option,
                decode_by_ref: true,
                ..
            }
        ));
        for c in &chs {
            syn::parse_file(&harness_source(c)).expect("challenge harness parses");
        }
    }

    #[test]
    fn rejects_bad_specs() {
        let one = |body: &str| {
            parse_public(&format!(
                "[[challenge]]\nid = \"x\"\ntarget = \"a::f\"\n{body}"
            ))
        };
        assert!(matches!(
            one("oracle = { kind = \"no_panic\" }\nargs = [{ ty = \"f32\" }]"),
            Err(SpecError::Invalid { .. })
        ));
        assert!(
            one("oracle = { kind = \"no_panic\" }\nargs = [{ ty = \"u8\", min = -1 }]").is_err()
        );
        assert!(one(
            "oracle = { kind = \"no_panic\" }\nargs = [{ ty = \"u8\", min = 5, max = 1 }]"
        )
        .is_err());
        assert!(one(
            "oracle = { kind = \"no_panic\" }\nargs = [{ ty = \"u8\", alphabet = \"ab\" }]"
        )
        .is_err());
        assert!(one(
            "oracle = { kind = \"no_panic\" }\nargs = [{ ty = \"&str\", alphabet = \"\" }]"
        )
        .is_err());
        assert!(one("oracle = { kind = \"no_panic\" }\ncases = 0").is_err());
        assert!(one("oracle = { kind = \"property\", expr = \"output ==\" }").is_err());
        assert!(
            one("oracle = { kind = \"equals_reference\", source = \"fn other() {}\" }").is_err()
        );
        assert!(one("oracle = { kind = \"roundtrip\", decode = \"a::g\" }").is_err());
        assert!(one("oracle = { kind = \"telepathy\" }").is_err());
        assert!(one("oracle = { kind = \"no_panic\" }\nunknown = 1").is_err());
        assert!(parse_public("[[challenge]]\nid = \"x\"\ntarget = \"a::f(); evil\"\noracle = { kind = \"no_panic\" }").is_err());
        let dup =
            "[[challenge]]\nid = \"x\"\ntarget = \"a::f\"\noracle = { kind = \"no_panic\" }\n";
        assert!(parse_public(&format!("{dup}{dup}")).is_err());
    }

    #[test]
    fn sealed_specs_must_be_committed() {
        let committed = Digest::of(SPECS.as_bytes());
        let chs = parse_sealed(SPECS, &[committed]).unwrap();
        assert!(chs.iter().all(|c| c.visibility == Visibility::Sealed));
        let tampered = format!("{SPECS}\n# edited");
        assert_eq!(
            parse_sealed(&tampered, &[committed]),
            Err(SpecError::UncommittedSealedSpec(Digest::of(
                tampered.as_bytes()
            )))
        );
        assert!(parse_sealed(SPECS, &[]).is_err());
    }

    #[test]
    fn generation_is_deterministic_and_bounded() {
        let chs = parse_public(SPECS).unwrap();
        let s = seed("round-1234");
        for ch in &chs {
            let a = generate_cases(ch, &s, 40);
            assert_eq!(a, generate_cases(ch, &s, 40));
            assert_ne!(a, generate_cases(ch, &seed("round-1235"), 40));
            // Shorter runs are prefixes.
            assert_eq!(generate_cases(ch, &s, 10), a[..10].to_vec());
        }
        // Independent streams: the fork label is the spec id.
        let mut renamed = chs[1].clone();
        renamed.spec.id = "other".into();
        assert_ne!(
            generate_cases(&chs[1], &s, 20),
            generate_cases(&renamed, &s, 20)
        );

        let parse = generate_cases(&chs[0], &s, 40);
        assert_eq!(parse[0], vec![Value::Str(String::new())]);
        assert_eq!(parse[1], vec![Value::Str("------".into())]);
        for case in &parse {
            let Value::Str(v) = &case[0] else { panic!() };
            assert!(v.len() <= 6 && v.chars().all(|c| "0123456789-".contains(c)));
        }
        let clamp = generate_cases(&chs[1], &s, 40);
        assert_eq!(clamp[0], vec![Value::Int(-1000), Value::None]);
        assert_eq!(
            clamp[1],
            vec![Value::Int(1000), Value::Some(Box::new(Value::UInt(255)))]
        );
        for case in &clamp {
            let Value::Int(v) = case[0] else { panic!() };
            assert!((-1000..=1000).contains(&v));
        }
    }
}
