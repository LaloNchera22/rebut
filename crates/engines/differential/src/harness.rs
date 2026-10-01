//! Harness code generation shared by the differential and challenge engines.
//!
//! A harness is a standalone `main.rs` that links the crate under test (the
//! fabric builds it as a binary depending on that crate) and reads one case
//! per stdin line. Each line is a space-separated list of argument tokens:
//!
//! | value           | token                       |
//! |-----------------|-----------------------------|
//! | integer         | decimal, e.g. `-5`          |
//! | bool            | `t` / `f`                   |
//! | char            | `c` + hex of the code point |
//! | string          | `s` + hex of the UTF-8      |
//! | bytes           | `x` + hex                   |
//! | `None`          | `~`                         |
//! | `Some(v)`       | `?` + token of `v`          |
//!
//! Tokens never contain spaces or newlines, so the encoding is trivially
//! self-delimiting and the decoder (embedded in the generated source, no
//! dependencies) stays tiny.
//!
//! The harness reports over the authenticated channel of
//! [`rebut_core::channel`] (the nonce is the first stdin line, before the
//! cases), so the code under test cannot print results itself. In canonical
//! form it reports `#harness-start` first (so "did not compile/start" is
//! distinguishable from "crashed on a case") and then exactly one line per
//! case, in order: `case <i> <payload>`, where the payload is `panic` when the
//! case panicked. Panics are caught with `catch_unwind`, so they are
//! observable behavior rather than crashes. The payload never contains a
//! newline.

use std::collections::BTreeMap;

use rebut_core::channel;
use syn::{GenericArgument, PathArguments, Type};

/// First message reported by every harness.
pub const START_MARKER: &str = "#harness-start";

/// Integer types, with their width in bits (`isize`/`usize` assumed 64-bit,
/// as on every target the fabric runs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntTy {
    pub signed: bool,
    pub bits: u32,
}

impl IntTy {
    pub fn from_name(name: &str) -> Option<IntTy> {
        let (signed, bits) = match name {
            "i8" => (true, 8),
            "i16" => (true, 16),
            "i32" => (true, 32),
            "i64" | "isize" => (true, 64),
            "i128" => (true, 128),
            "u8" => (false, 8),
            "u16" => (false, 16),
            "u32" => (false, 32),
            "u64" | "usize" => (false, 64),
            "u128" => (false, 128),
            _ => return None,
        };
        Some(IntTy { signed, bits })
    }

    /// A Rust type name with this width (the `size` types are not recovered).
    pub fn rust_name(&self) -> String {
        format!("{}{}", if self.signed { 'i' } else { 'u' }, self.bits)
    }

    pub fn min_i128(&self) -> i128 {
        match (self.signed, self.bits) {
            (false, _) => 0,
            (true, 128) => i128::MIN,
            (true, bits) => -(1i128 << (bits - 1)),
        }
    }

    /// Largest value, as `u128` (fits every type).
    pub fn max_u128(&self) -> u128 {
        let ones = u128::MAX >> (128 - self.bits);
        if self.signed {
            ones >> 1
        } else {
            ones
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scalar {
    Int(IntTy),
    Bool,
    Char,
    Str,
    Bytes,
}

/// How the decoded (owned) value is handed to the function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    /// By value (`u32`, `String`, `Option<String>`).
    Owned,
    /// By reference to the owned type (`&u32`, `&String`, `Option<&String>`).
    Ref,
    /// By reference to the unsized target (`&str`, `&[u8]`, `Option<&str>`).
    RefUnsized,
}

/// A supported argument type: a scalar, optionally wrapped in one `Option`,
/// passed by value or shared reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgType {
    pub scalar: Scalar,
    pub optional: bool,
    pub pass: Pass,
}

impl ArgType {
    /// Parses a type as written in source (`&str`, `Option<& [u8]>`, ...).
    /// Returns `None` for anything the harness cannot generate.
    pub fn parse(s: &str) -> Option<ArgType> {
        let ty: Type = syn::parse_str(s).ok()?;
        if let Some((inner, pass)) = parse_maybe_ref(&ty) {
            if let Some(opt_inner) = option_inner(inner) {
                if pass != Pass::Owned {
                    return None; // `&Option<T>` is not supported.
                }
                let (inner, pass) = parse_maybe_ref(opt_inner)?;
                return Some(ArgType {
                    scalar: parse_scalar(inner, pass)?,
                    optional: true,
                    pass,
                });
            }
            return Some(ArgType {
                scalar: parse_scalar(inner, pass)?,
                optional: false,
                pass,
            });
        }
        None
    }

    /// Expression passing variable `var` (the owned decoded value) to the
    /// function. Owned values are cloned so the originals stay available to
    /// oracles.
    pub fn pass_expr(&self, var: &str) -> String {
        match (self.optional, self.pass) {
            (_, Pass::Owned) => format!("{var}.clone()"),
            (false, _) => format!("&{var}"),
            (true, Pass::Ref) => format!("{var}.as_ref()"),
            (true, Pass::RefUnsized) => format!("{var}.as_deref()"),
        }
    }

    /// Expression decoding token expression `tok` into the owned value.
    pub fn decode_expr(&self, tok: &str) -> String {
        let scalar = |t: &str| match self.scalar {
            Scalar::Int(i) => format!("__int::<{}>({t})", i.rust_name()),
            Scalar::Bool => format!("__bool({t})"),
            Scalar::Char => format!("__char({t})"),
            Scalar::Str => format!("__str({t})"),
            Scalar::Bytes => format!("__bytes({t})"),
        };
        if self.optional {
            format!("__opt({tok}, |t| {})", scalar("t"))
        } else {
            scalar(tok)
        }
    }
}

fn parse_maybe_ref(ty: &Type) -> Option<(&Type, Pass)> {
    match ty {
        Type::Reference(r) if r.mutability.is_none() => {
            let unsized_target = match &*r.elem {
                Type::Slice(s) => is_ident(&s.elem, "u8"),
                Type::Path(p) => p.path.is_ident("str"),
                _ => false,
            };
            Some((
                &r.elem,
                if unsized_target {
                    Pass::RefUnsized
                } else {
                    Pass::Ref
                },
            ))
        }
        Type::Reference(_) => None,
        Type::Paren(p) => parse_maybe_ref(&p.elem),
        other => Some((other, Pass::Owned)),
    }
}

fn parse_scalar(ty: &Type, pass: Pass) -> Option<Scalar> {
    match ty {
        Type::Slice(s) if pass == Pass::RefUnsized && is_ident(&s.elem, "u8") => {
            Some(Scalar::Bytes)
        }
        Type::Path(p) if p.qself.is_none() => {
            let last = p.path.segments.last()?;
            let name = last.ident.to_string();
            if let Some(i) = IntTy::from_name(&name) {
                return plain(last).then_some(Scalar::Int(i));
            }
            match name.as_str() {
                "bool" if plain(last) => Some(Scalar::Bool),
                "char" if plain(last) => Some(Scalar::Char),
                "str" if pass == Pass::RefUnsized => Some(Scalar::Str),
                "String" if plain(last) && pass != Pass::RefUnsized => Some(Scalar::Str),
                "Vec" if pass != Pass::RefUnsized => {
                    single_generic(last).filter(|t| is_ident(t, "u8"))?;
                    Some(Scalar::Bytes)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn option_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(p) = ty else { return None };
    let last = p.path.segments.last()?;
    if last.ident != "Option" {
        return None;
    }
    let inner = single_generic(last)?;
    // A single level of Option only.
    option_inner(inner).is_none().then_some(inner)
}

fn single_generic(seg: &syn::PathSegment) -> Option<&Type> {
    let PathArguments::AngleBracketed(a) = &seg.arguments else {
        return None;
    };
    match a.args.iter().collect::<Vec<_>>().as_slice() {
        [GenericArgument::Type(t)] => Some(t),
        _ => None,
    }
}

fn plain(seg: &syn::PathSegment) -> bool {
    seg.arguments.is_none()
}

fn is_ident(ty: &Type, name: &str) -> bool {
    matches!(ty, Type::Path(p) if p.qself.is_none() && p.path.is_ident(name))
}

/// A concrete argument value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i128),
    UInt(u128),
    Bool(bool),
    Char(char),
    Str(String),
    Bytes(Vec<u8>),
    None,
    Some(Box<Value>),
}

impl Value {
    /// The stdin token for this value (see the module docs).
    pub fn token(&self) -> String {
        match self {
            Value::Int(i) => i.to_string(),
            Value::UInt(u) => u.to_string(),
            Value::Bool(b) => if *b { "t" } else { "f" }.to_string(),
            Value::Char(c) => format!("c{:x}", *c as u32),
            Value::Str(s) => format!("s{}", hex::encode(s.as_bytes())),
            Value::Bytes(b) => format!("x{}", hex::encode(b)),
            Value::None => "~".to_string(),
            Value::Some(v) => format!("?{}", v.token()),
        }
    }
}

/// One stdin line for a case.
pub fn encode_case(args: &[Value]) -> String {
    args.iter().map(Value::token).collect::<Vec<_>>().join(" ")
}

/// The stdin of a harness step: one line per case, newline-terminated.
pub fn encode_input(lines: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for l in lines {
        out.extend_from_slice(l.as_bytes());
        out.push(b'\n');
    }
    out
}

const PRELUDE: &str = r#"#![allow(dead_code, unused_imports, unused_variables, unused_mut, unused_parens, unreachable_code)]
// Generated by Rebut. Inputs arrive on stdin, one case per line, after the
// result channel's nonce line.

fn __hex(t: &str) -> Vec<u8> {
    assert!(t.len() % 2 == 0 && t.is_ascii(), "bad hex");
    (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).expect("bad hex"))
        .collect()
}
fn __int<T: std::str::FromStr>(t: &str) -> T {
    t.parse().ok().expect("bad int")
}
fn __bool(t: &str) -> bool {
    match t {
        "t" => true,
        "f" => false,
        _ => panic!("bad bool"),
    }
}
fn __char(t: &str) -> char {
    let t = t.strip_prefix('c').expect("bad char");
    char::from_u32(u32::from_str_radix(t, 16).expect("bad char")).expect("bad char")
}
fn __str(t: &str) -> String {
    String::from_utf8(__hex(t.strip_prefix('s').expect("bad str"))).expect("bad utf8")
}
fn __bytes(t: &str) -> Vec<u8> {
    __hex(t.strip_prefix('x').expect("bad bytes"))
}
fn __opt<T>(t: &str, f: impl Fn(&str) -> T) -> Option<T> {
    if t == "~" {
        None
    } else {
        Some(f(t.strip_prefix('?').expect("bad option")))
    }
}
"#;

/// Assembles a harness.
///
/// For each case the arguments are decoded into `a0`, `a1`, ... (owned
/// values), then `body` runs inside `catch_unwind` and must evaluate to a
/// `String` payload without newlines. `items` is extra top-level Rust source
/// (e.g. a reference implementation).
pub fn harness_source(args: &[ArgType], items: &str, body: &str) -> String {
    let mut src = String::from(PRELUDE);
    src.push_str(channel::HARNESS_SOURCE);
    src.push_str(items);
    src.push_str("\nfn main() {\n");
    src.push_str("    let mut __ch = __RebutChannel::open();\n");
    src.push_str("    std::panic::set_hook(Box::new(|_| {}));\n");
    src.push_str(&format!("    __ch.send(\"{START_MARKER}\");\n"));
    src.push_str("    let stdin = std::io::stdin();\n");
    src.push_str("    for (i, line) in std::io::BufRead::lines(stdin.lock()).enumerate() {\n");
    src.push_str("        let line = line.expect(\"stdin\");\n");
    src.push_str(
        "        let t: Vec<&str> = line.split(' ').filter(|s| !s.is_empty()).collect();\n",
    );
    src.push_str(&format!(
        "        assert_eq!(t.len(), {}, \"arity\");\n",
        args.len()
    ));
    for (i, a) in args.iter().enumerate() {
        src.push_str(&format!(
            "        let a{i} = {};\n",
            a.decode_expr(&format!("t[{i}]"))
        ));
    }
    src.push_str(
        "        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || -> String {\n",
    );
    src.push_str(&format!("            {body}\n"));
    src.push_str("        }));\n");
    src.push_str("        match r {\n");
    src.push_str("            Ok(s) => __ch.send(&format!(\"case {} {}\", i, s)),\n");
    src.push_str("            Err(_) => __ch.send(&format!(\"case {} panic\", i)),\n");
    src.push_str("        }\n    }\n}\n");
    src
}

/// Comma-separated call arguments for `a0..aN`.
pub fn call_args(args: &[ArgType]) -> String {
    args.iter()
        .enumerate()
        .map(|(i, a)| a.pass_expr(&format!("a{i}")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Checks that `path` is a plain Rust path (`a::b::C::f`), so it can be
/// spliced into generated source.
pub fn is_plain_path(path: &str) -> bool {
    match syn::parse_str::<syn::Path>(path) {
        Ok(p) => p.segments.iter().all(|s| s.arguments.is_none()) && !path.contains(['<', '>']),
        Err(_) => false,
    }
}

/// Differential harness: payload is `ok <escaped Debug of the result>`.
pub fn differential_source(path: &str, args: &[ArgType]) -> String {
    let body = format!(
        "format!(\"ok {{:?}}\", format!(\"{{:?}}\", {path}({})))",
        call_args(args)
    );
    harness_source(args, "", &body)
}

/// Parsed output of a harness step.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HarnessOutput {
    /// The start marker was reported (the harness compiled and ran).
    pub started: bool,
    /// Case index -> payload.
    pub cases: BTreeMap<usize, String>,
    /// An authenticated message was repeated, out of order or unknown:
    /// something other than the harness wrote to the channel, so nothing in
    /// this output can be trusted.
    pub tampered: bool,
}

impl HarnessOutput {
    /// Parses *canonical* output, as left in [`rebut_core::StepOutcome`]s by
    /// [`rebut_core::channel::execute`] (every engine runs harnesses through
    /// it). For raw stdout use [`HarnessOutput::parse_raw`].
    pub fn parse(canonical: &[u8]) -> HarnessOutput {
        let mut out = HarnessOutput::default();
        for line in String::from_utf8_lossy(canonical).lines() {
            if line == START_MARKER && !out.started {
                out.started = true;
                continue;
            }
            let case = line
                .strip_prefix("case ")
                .and_then(|rest| rest.split_once(' '))
                .and_then(|(idx, payload)| Some((idx.parse::<usize>().ok()?, payload)));
            match case {
                // Cases arrive once each, in order, after the start marker.
                Some((i, payload)) if out.started && i == out.cases.len() => {
                    out.cases.insert(i, payload.to_string());
                }
                _ => out.tampered = true,
            }
        }
        out
    }

    /// Parses raw harness stdout, keeping only lines carrying `nonce`.
    pub fn parse_raw(stdout: &[u8], nonce: &str) -> HarnessOutput {
        HarnessOutput::parse(&channel::authenticated(stdout, nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Option<ArgType> {
        ArgType::parse(s)
    }

    #[test]
    fn parses_supported_types() {
        let int = |signed, bits| Scalar::Int(IntTy { signed, bits });
        assert_eq!(t("u32").unwrap().scalar, int(false, 32));
        assert_eq!(t("isize").unwrap().scalar, int(true, 64));
        assert_eq!(t("&str").unwrap().pass, Pass::RefUnsized);
        assert_eq!(t("& 'a str").unwrap().scalar, Scalar::Str);
        assert_eq!(t("String").unwrap().pass, Pass::Owned);
        assert_eq!(t("&String").unwrap().pass, Pass::Ref);
        assert_eq!(t("&[u8]").unwrap().scalar, Scalar::Bytes);
        assert_eq!(t("Vec<u8>").unwrap().scalar, Scalar::Bytes);
        assert_eq!(t("std::vec::Vec<u8>").unwrap().scalar, Scalar::Bytes);
        let o = t("Option<&str>").unwrap();
        assert!(o.optional && o.pass == Pass::RefUnsized);
        assert_eq!(t("Option < u8 >").unwrap().scalar, int(false, 8));
        for bad in [
            "&mut str",
            "Vec<u32>",
            "&[u32]",
            "Option<Option<u8>>",
            "&Option<u8>",
            "T",
            "impl AsRef<str>",
            "&self",
            "f32",
            "str",
            "(u8, u8)",
        ] {
            assert_eq!(t(bad), None, "{bad}");
        }
    }

    #[test]
    fn int_bounds() {
        let i8t = IntTy::from_name("i8").unwrap();
        assert_eq!((i8t.min_i128(), i8t.max_u128()), (-128, 127));
        let i128t = IntTy::from_name("i128").unwrap();
        assert_eq!(i128t.min_i128(), i128::MIN);
        assert_eq!(i128t.max_u128(), i128::MAX as u128);
        assert_eq!(IntTy::from_name("u128").unwrap().max_u128(), u128::MAX);
        assert_eq!(IntTy::from_name("u8").unwrap().min_i128(), 0);
    }

    #[test]
    fn tokens() {
        let case = encode_case(&[
            Value::Int(-5),
            Value::Str("é ".into()),
            Value::Some(Box::new(Value::Bytes(vec![0, 255]))),
            Value::None,
            Value::Char('a'),
            Value::Bool(true),
            Value::Str(String::new()),
        ]);
        assert_eq!(case, "-5 sc3a920 ?x00ff ~ c61 t s");
    }

    #[test]
    fn output_parsing() {
        let o = HarnessOutput::parse(b"#harness-start\ncase 0 ok \"1\"\ncase 1 panic\n");
        assert!(o.started && !o.tampered);
        assert_eq!(o.cases[&0], "ok \"1\"");
        assert_eq!(o.cases[&1], "panic");
        assert!(!HarnessOutput::parse(b"case 0 ok").started);
    }

    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    /// What the code under test can print without the nonce is ignored.
    #[test]
    fn unauthenticated_lines_are_ignored() {
        let mut raw = b"#harness-start\ncase 0 pass\ncase 1 pass\n".to_vec();
        raw.extend(channel::frame(NONCE, b"#harness-start\n"));
        raw.extend_from_slice(
            b"case 0 pass\n#rebut 00000000000000000000000000000000 case 0 pass\n",
        );
        raw.extend(channel::frame(NONCE, b"case 0 fail\n"));
        let o = HarnessOutput::parse_raw(&raw, NONCE);
        assert!(o.started && !o.tampered);
        assert_eq!(o.cases, BTreeMap::from([(0, "fail".to_string())]));
        // Without the nonce, nothing was reported at all.
        assert!(!HarnessOutput::parse_raw(b"#harness-start\ncase 0 pass\n", NONCE).started);
    }

    /// Authenticated lines that the harness would never write mean someone
    /// else holds the nonce.
    #[test]
    fn duplicates_and_disorder_are_tampering() {
        for canonical in [
            "#harness-start\ncase 0 pass\ncase 0 fail\n",
            "#harness-start\ncase 0 fail\ncase 0 fail\n",
            "#harness-start\ncase 1 pass\ncase 0 fail\n",
            "#harness-start\ncase 0 pass\n#harness-start\n",
            "case 0 pass\n#harness-start\ncase 0 fail\n",
            "#harness-start\nhello\n",
        ] {
            let raw = channel::frame(NONCE, canonical.as_bytes());
            assert!(
                HarnessOutput::parse_raw(&raw, NONCE).tampered,
                "{canonical}"
            );
        }
    }

    #[test]
    fn plain_paths() {
        assert!(is_plain_path("my_lib::a::Foo::bar"));
        assert!(!is_plain_path("a::b(); std::process::exit(0); c"));
        assert!(!is_plain_path("Vec::<u8>::new"));
    }

    #[test]
    fn generated_source_is_valid_rust() {
        let args = [t("&str").unwrap(), t("Option<u8>").unwrap()];
        let src = differential_source("my_lib::f", &args);
        syn::parse_file(&src).expect("harness parses");
        assert!(src.contains("my_lib::f(&a0, a1.clone())"));
    }
}
