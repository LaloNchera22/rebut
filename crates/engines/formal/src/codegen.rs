//! Kani proof harness and replay harness generation.

use syn::visit::Visit;
use verifier_core::FnSignature;

/// A property to check about one function. Arguments are named `a0..aN`
/// (in declaration order) and the return value is `ret`.
///
/// Example for `fn clamp(x: i32, lo: i32, hi: i32) -> i32`:
/// `assumptions = ["a1 <= a2"]`, `property = "ret >= a1 && ret <= a2"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invariant {
    /// Preconditions, each a boolean Rust expression over the arguments.
    pub assumptions: Vec<String>,
    /// Postcondition, a boolean Rust expression over the arguments and `ret`.
    pub property: String,
}

impl Invariant {
    pub fn describe(&self) -> String {
        if self.assumptions.is_empty() {
            self.property.clone()
        } else {
            format!(
                "assuming {}: {}",
                self.assumptions.join(" && "),
                self.property
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodegenError {
    #[error("argument type `{0}` has no kani::Arbitrary impl we can generate")]
    UnsupportedArg(String),
    #[error("function path `{0}` is not `crate::...::function`")]
    BadPath(String),
    #[error("invariant expression does not parse: {0}")]
    Parse(String),
    #[error("invariant expression must be a pure boolean expression; found {0}")]
    Impure(&'static str),
}

/// Scalar types we can both generate with `kani::any()` and decode from a
/// concrete-playback byte vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scalar {
    Int(&'static str, usize),
    Bool,
    Char,
}

const INTS: &[(&str, usize)] = &[
    ("u8", 1),
    ("u16", 2),
    ("u32", 4),
    ("u64", 8),
    ("u128", 16),
    ("usize", 8),
    ("i8", 1),
    ("i16", 2),
    ("i32", 4),
    ("i64", 8),
    ("i128", 16),
    ("isize", 8),
];

impl Scalar {
    pub fn name(&self) -> &'static str {
        match self {
            Scalar::Int(n, _) => n,
            Scalar::Bool => "bool",
            Scalar::Char => "char",
        }
    }

    /// Width in bytes of Kani's concrete-playback encoding (little-endian,
    /// 64-bit target).
    pub fn width(&self) -> usize {
        match self {
            Scalar::Int(_, w) => *w,
            Scalar::Bool => 1,
            Scalar::Char => 4,
        }
    }
}

/// One argument: a scalar passed by value or by shared reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgType {
    pub scalar: Scalar,
    pub by_ref: bool,
}

impl ArgType {
    pub fn parse(s: &str) -> Result<Self, CodegenError> {
        let t = s.trim();
        let (by_ref, inner) = match t.strip_prefix('&') {
            Some(rest) if !rest.trim_start().starts_with("mut ") => (true, rest.trim()),
            Some(_) => return Err(CodegenError::UnsupportedArg(s.to_string())),
            None => (false, t),
        };
        let scalar = match inner {
            "bool" => Scalar::Bool,
            "char" => Scalar::Char,
            _ => INTS
                .iter()
                .find(|(n, _)| *n == inner)
                .map(|(n, w)| Scalar::Int(n, *w))
                .ok_or_else(|| CodegenError::UnsupportedArg(s.to_string()))?,
        };
        Ok(ArgType { scalar, by_ref })
    }
}

/// Rejects anything that is not a side-effect-free expression: an invariant is
/// a claim to check, not code to run. This keeps LLM-proposed text from
/// smuggling loops, `process::exit`, or macros into the proof.
struct Purity(Option<&'static str>);

impl<'ast> Visit<'ast> for Purity {
    fn visit_expr(&mut self, e: &'ast syn::Expr) {
        use syn::Expr::*;
        let bad = match e {
            Assign(_) => Some("an assignment"),
            Async(_) | Await(_) => Some("async code"),
            Block(_) | Unsafe(_) => Some("a block"),
            Break(_) | Continue(_) | Return(_) | Yield(_) => Some("control flow"),
            Closure(_) => Some("a closure"),
            ForLoop(_) | Loop(_) | While(_) => Some("a loop"),
            Let(_) => Some("a let binding"),
            Macro(_) => Some("a macro"),
            _ => None,
        };
        if bad.is_some() && self.0.is_none() {
            self.0 = bad;
        }
        syn::visit::visit_expr(self, e);
    }
}

pub fn check_expr(src: &str) -> Result<(), CodegenError> {
    let expr: syn::Expr =
        syn::parse_str(src).map_err(|e| CodegenError::Parse(format!("{src:?}: {e}")))?;
    let mut p = Purity(None);
    p.visit_expr(&expr);
    match p.0 {
        Some(what) => Err(CodegenError::Impure(what)),
        None => Ok(()),
    }
}

/// Signature and invariant, validated, ready to render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessSpec {
    pub function: FnSignature,
    pub args: Vec<ArgType>,
    pub invariant: Invariant,
    /// Unique, identifier-safe name used for both the proof and the replay.
    pub name: String,
}

/// A generated source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedHarness {
    pub name: String,
    pub source: String,
}

impl HarnessSpec {
    /// `index` disambiguates several invariants for the same function.
    pub fn new(
        function: &FnSignature,
        invariant: &Invariant,
        index: usize,
    ) -> Result<Self, CodegenError> {
        let segments: Vec<&str> = function.path.split("::").collect();
        if segments.len() < 2 || segments.iter().any(|s| !is_ident(s)) {
            return Err(CodegenError::BadPath(function.path.clone()));
        }
        let args = function
            .args
            .iter()
            .map(|a| ArgType::parse(a))
            .collect::<Result<Vec<_>, _>>()?;
        for a in &invariant.assumptions {
            check_expr(a)?;
        }
        check_expr(&invariant.property)?;
        let name = format!(
            "verifier_proof_{}_{index}",
            segments[1..].join("_").to_ascii_lowercase()
        );
        Ok(HarnessSpec {
            function: function.clone(),
            args,
            invariant: invariant.clone(),
            name,
        })
    }

    fn call(&self, root: &str) -> String {
        let mut segs: Vec<&str> = self.function.path.split("::").collect();
        segs[0] = root;
        let args: Vec<String> = self
            .args
            .iter()
            .enumerate()
            .map(|(i, a)| {
                if a.by_ref {
                    format!("&a{i}")
                } else {
                    format!("a{i}")
                }
            })
            .collect();
        format!("{}({})", segs.join("::"), args.join(", "))
    }

    /// The Kani proof, to be appended to the crate root (`src/lib.rs`) of
    /// the crate under test and run with [`kani_argv`]. It is `#[cfg(kani)]`,
    /// so it never affects normal builds.
    pub fn kani_harness(&self) -> GeneratedHarness {
        let mut s = String::new();
        s.push_str(&format!(
            "// Generated by verifier-formal for `{}`.\n// Invariant: {}\n",
            self.function.path,
            one_line(&self.invariant.describe())
        ));
        s.push_str("#[cfg(kani)]\n#[kani::proof]\n");
        s.push_str(&format!("fn {}() {{\n", self.name));
        for (i, a) in self.args.iter().enumerate() {
            s.push_str(&format!(
                "    let a{i}: {} = kani::any();\n",
                a.scalar.name()
            ));
        }
        for a in &self.invariant.assumptions {
            s.push_str(&format!("    kani::assume({a});\n"));
        }
        s.push_str(&format!("    let ret = {};\n", self.call("crate")));
        s.push_str(&format!(
            "    assert!({}, \"{{}}\", {:?});\n}}\n",
            self.invariant.property,
            format!("verifier-formal invariant: {}", self.invariant.property)
        ));
        GeneratedHarness {
            name: self.name.clone(),
            source: s,
        }
    }

    /// A normal program (a [`verifier_core::Step::Harness`]) that replays
    /// one concrete input against the real crate, outside Kani. Stdin is
    /// produced by [`encode_input`]. Its stdout protocol:
    ///
    /// * `verifier:start` — input decoded, about to call the function;
    /// * `verifier:assumption-violated` — the counterexample does not satisfy
    ///   the preconditions (so it proves nothing);
    /// * `verifier:invariant:held` / `verifier:invariant:violated`.
    ///
    /// A panic after `verifier:start` exits 101 with no verdict line.
    pub fn replay_harness(&self) -> GeneratedHarness {
        let mut s = String::new();
        s.push_str(&format!(
            "// Replay harness generated by verifier-formal for `{}`.\n",
            self.function.path
        ));
        s.push_str("use std::io::Read as _;\n\nfn main() {\n");
        s.push_str("    let mut buf = Vec::new();\n");
        s.push_str("    std::io::stdin().read_to_end(&mut buf).expect(\"stdin\");\n");
        s.push_str("    let mut vals: Vec<Vec<u8>> = Vec::new();\n");
        s.push_str("    let mut i = 0usize;\n");
        s.push_str("    while i + 4 <= buf.len() {\n");
        s.push_str("        let n = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;\n");
        s.push_str("        vals.push(buf[i + 4..i + 4 + n].to_vec());\n");
        s.push_str("        i += 4 + n;\n    }\n");
        s.push_str(&format!(
            "    assert_eq!(vals.len(), {}, \"argument count\");\n",
            self.args.len()
        ));
        for (i, a) in self.args.iter().enumerate() {
            let decode = match a.scalar {
                Scalar::Int(t, _) => format!(
                    "<{t}>::from_le_bytes(vals[{i}].as_slice().try_into().expect(\"width\"))"
                ),
                Scalar::Bool => format!("vals[{i}][0] != 0"),
                Scalar::Char => format!(
                    "char::from_u32(u32::from_le_bytes(vals[{i}].as_slice().try_into().expect(\"width\"))).expect(\"char\")"
                ),
            };
            s.push_str(&format!("    let a{i}: {} = {decode};\n", a.scalar.name()));
        }
        s.push_str("    println!(\"verifier:start\");\n");
        if !self.invariant.assumptions.is_empty() {
            let conds: Vec<String> = self
                .invariant
                .assumptions
                .iter()
                .map(|a| format!("({a})"))
                .collect();
            s.push_str(&format!(
                "    if !({}) {{\n        println!(\"verifier:assumption-violated\");\n        return;\n    }}\n",
                conds.join(" && ")
            ));
        }
        s.push_str(&format!(
            "    let ret = {};\n",
            self.call(&self.crate_ident())
        ));
        s.push_str(&format!(
            "    let holds: bool = {};\n",
            self.invariant.property
        ));
        s.push_str(
            "    println!(\"verifier:invariant:{}\", if holds { \"held\" } else { \"violated\" });\n}\n",
        );
        GeneratedHarness {
            name: format!("{}_replay", self.name),
            source: s,
        }
    }

    fn crate_ident(&self) -> String {
        self.function
            .path
            .split("::")
            .next()
            .unwrap_or_default()
            .to_string()
    }
}

/// `cargo kani` invocation for one generated harness, printing a concrete
/// playback test for any counterexample.
pub fn kani_argv(harness: &str) -> Vec<String> {
    [
        "cargo",
        "kani",
        "--harness",
        harness,
        "-Z",
        "concrete-playback",
        "--concrete-playback=print",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Stdin for [`HarnessSpec::replay_harness`]: each value length-prefixed
/// (`u32` little-endian), in argument order.
pub fn encode_input(values: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in values {
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

fn is_ident(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch == '_' || ch.is_ascii_alphabetic())
        && c.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(args: &[&str]) -> FnSignature {
        FnSignature {
            path: "mylib::math::clamp".into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            ret: "i32".into(),
            is_pub: true,
        }
    }

    fn inv() -> Invariant {
        Invariant {
            assumptions: vec!["a1 <= a2".into()],
            property: "ret >= a1 && ret <= a2".into(),
        }
    }

    #[test]
    fn kani_harness_uses_any_and_assume() {
        let spec = HarnessSpec::new(&sig(&["i32", "i32", "&i32"]), &inv(), 0).unwrap();
        let h = spec.kani_harness();
        assert_eq!(h.name, "verifier_proof_math_clamp_0");
        let expected = "\
#[cfg(kani)]
#[kani::proof]
fn verifier_proof_math_clamp_0() {
    let a0: i32 = kani::any();
    let a1: i32 = kani::any();
    let a2: i32 = kani::any();
    kani::assume(a1 <= a2);
    let ret = crate::math::clamp(a0, a1, &a2);
    assert!(ret >= a1 && ret <= a2, \"{}\", \"verifier-formal invariant: ret >= a1 && ret <= a2\");
}
";
        assert!(h.source.ends_with(expected), "{}", h.source);
        // The generated code must itself be valid Rust.
        syn::parse_file(&h.source).unwrap();
    }

    #[test]
    fn replay_harness_is_valid_rust_and_calls_the_crate() {
        let spec = HarnessSpec::new(&sig(&["i32", "bool", "char"]), &inv(), 1).unwrap();
        let h = spec.replay_harness();
        syn::parse_file(&h.source).unwrap();
        assert!(h
            .source
            .contains("let ret = mylib::math::clamp(a0, a1, a2);"));
        assert!(h.source.contains("verifier:assumption-violated"));
        assert_eq!(h.name, "verifier_proof_math_clamp_1_replay");
    }

    #[test]
    fn rejects_unsupported_types_and_impure_invariants() {
        assert_eq!(
            HarnessSpec::new(&sig(&["&str"]), &inv(), 0).unwrap_err(),
            CodegenError::UnsupportedArg("&str".into())
        );
        assert!(ArgType::parse("&mut u8").is_err());
        for bad in [
            "{ std::process::exit(0); true }",
            "loop {}",
            "println!(\"x\") == ()",
            "(|| true)()",
            "ret = 1",
        ] {
            let i = Invariant {
                assumptions: vec![],
                property: bad.into(),
            };
            assert!(
                HarnessSpec::new(&sig(&["i32"]), &i, 0).is_err(),
                "{bad} should be rejected"
            );
        }
        assert!(check_expr("ret.checked_add(1).is_some() || a0 == i32::MAX").is_ok());
    }

    #[test]
    fn encoding_is_length_prefixed() {
        assert_eq!(
            encode_input(&[vec![1, 2], vec![]]),
            vec![2, 0, 0, 0, 1, 2, 0, 0, 0, 0]
        );
    }
}
