//! Per-tree index of functions, tests and `macro_rules!` definitions.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use rebut_core::FnSignature;
use syn::{Attribute, FnArg, ImplItem, Item, ReturnType, Signature, TraitItem, Visibility};

use crate::files::Entry;

/// Which cargo target a source file belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Lib,
    Bin,
    /// Integration test binary under `tests/`.
    Test,
}

/// A function found in a tree.
#[derive(Debug, Clone)]
pub(crate) struct FnEntry {
    pub sig: FnSignature,
    /// Bare function name (last path segment).
    pub name: String,
    /// Token text of everything that determines behavior (non-doc attributes,
    /// visibility, signature, body). Formatting and comments do not affect it.
    pub fingerprint: String,
    /// Every identifier appearing in the body, macro invocations included.
    pub idents: BTreeSet<String>,
    /// libtest name (`module::test_name`) when this is a test function.
    pub test_name: Option<String>,
    /// Part of the library/binary code (not a test target, not a
    /// `#[cfg(test)]` module): reported in `changed_functions`.
    pub reportable: bool,
}

#[derive(Debug, Default)]
pub(crate) struct TreeIndex {
    /// Unique key (crate dir, target, module path, qualified name) -> fn.
    pub fns: BTreeMap<String, FnEntry>,
    /// `macro_rules!` definitions: unique key -> token text.
    pub macros: BTreeMap<String, String>,
    /// Rust files that failed to parse (or were too large to load).
    pub unparsable: BTreeSet<String>,
    /// Crate directories (relative, `""` for the root) of proc-macro crates.
    pub proc_macro_dirs: BTreeSet<String>,
}

struct CrateInfo {
    dir: String,
    name: String,
    proc_macro: bool,
}

fn parse_manifest(dir: &str, bytes: &[u8]) -> Option<CrateInfo> {
    let v: toml::Value = toml::from_str(std::str::from_utf8(bytes).ok()?).ok()?;
    let package = v.get("package")?;
    let lib = v.get("lib");
    let name = lib
        .and_then(|l| l.get("name"))
        .or_else(|| package.get("name"))?
        .as_str()?
        .replace('-', "_");
    let proc_macro = lib
        .and_then(|l| l.get("proc-macro").or_else(|| l.get("proc_macro")))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    Some(CrateInfo {
        dir: dir.to_string(),
        name,
        proc_macro,
    })
}

/// Builds the index of a whole tree (possibly a workspace).
pub(crate) fn index_tree(files: &BTreeMap<String, Entry>) -> TreeIndex {
    let mut idx = TreeIndex::default();
    let crates: Vec<CrateInfo> = files
        .iter()
        .filter_map(|(path, e)| {
            let dir = match path.strip_suffix("Cargo.toml")? {
                "" => "",
                d => d.strip_suffix('/')?,
            };
            parse_manifest(dir, e.contents()?)
        })
        .collect();

    for krate in &crates {
        if krate.proc_macro {
            idx.proc_macro_dirs.insert(krate.dir.clone());
        }
        let prefix = if krate.dir.is_empty() {
            String::new()
        } else {
            format!("{}/", krate.dir)
        };
        let has_lib = files.contains_key(&format!("{prefix}src/lib.rs"));
        let mut indexer = CrateIndexer {
            krate,
            idx: &mut idx,
            mod_decls: HashMap::new(),
            raw: Vec::new(),
        };
        for (path, entry) in files.range(prefix.clone()..) {
            let Some(rel) = path.strip_prefix(&prefix) else {
                break;
            };
            if !rel.ends_with(".rs") {
                continue;
            }
            let Some((target, mods)) = classify(rel, has_lib) else {
                continue;
            };
            // A nested crate owns its own files.
            if crates
                .iter()
                .any(|c| c.dir.len() > krate.dir.len() && path.starts_with(&format!("{}/", c.dir)))
            {
                continue;
            }
            let parsed = entry
                .contents()
                .and_then(|b| std::str::from_utf8(b).ok())
                .and_then(|s| syn::parse_file(s).ok());
            match parsed {
                Some(file) => indexer.file(path, target, mods, &file),
                None => {
                    indexer.idx.unparsable.insert(path.clone());
                }
            }
        }
        indexer.finish();
    }
    idx
}

/// Maps a path relative to the crate dir to its target and module path.
fn classify(rel: &str, has_lib: bool) -> Option<(Target, Vec<String>)> {
    let parts: Vec<&str> = rel.split('/').collect();
    let mods = |rest: &[&str]| -> Vec<String> {
        let mut m: Vec<String> = rest.iter().map(|s| s.to_string()).collect();
        if let Some(last) = m.pop() {
            let stem = last.trim_end_matches(".rs");
            if stem != "mod" && stem != "main" && stem != "lib" {
                m.push(stem.to_string());
            }
        }
        m
    };
    match parts.as_slice() {
        ["src", "lib.rs"] => Some((Target::Lib, vec![])),
        ["src", "main.rs"] => Some((Target::Bin, vec![])),
        ["src", "bin", _] => Some((Target::Bin, vec![])),
        ["src", "bin", _, rest @ ..] => Some((Target::Bin, mods(rest))),
        ["src", rest @ ..] => Some((if has_lib { Target::Lib } else { Target::Bin }, mods(rest))),
        ["tests", _] => Some((Target::Test, vec![])),
        ["tests", _, rest @ ..] => Some((Target::Test, mods(rest))),
        _ => None,
    }
}

/// A function before module visibility is resolved.
struct RawFn {
    key: String,
    mods: Vec<String>,
    target: Target,
    in_test_mod: bool,
    fn_pub: bool,
    entry: FnEntry,
}

struct CrateIndexer<'a> {
    krate: &'a CrateInfo,
    idx: &'a mut TreeIndex,
    /// Module path (lib target) -> declared `pub`.
    mod_decls: HashMap<Vec<String>, bool>,
    raw: Vec<RawFn>,
}

/// Where an item sits while walking a file.
#[derive(Clone)]
struct Scope {
    file: String,
    target: Target,
    mods: Vec<String>,
    in_test_mod: bool,
}

impl CrateIndexer<'_> {
    fn file(&mut self, path: &str, target: Target, mods: Vec<String>, file: &syn::File) {
        let scope = Scope {
            file: path.to_string(),
            target,
            mods,
            in_test_mod: false,
        };
        self.items(&file.items, &scope);
    }

    fn items(&mut self, items: &[Item], scope: &Scope) {
        for item in items {
            match item {
                Item::Fn(f) => {
                    let body = f.block.to_token_stream();
                    self.push_fn(scope, None, &f.attrs, &f.vis, &f.sig, body, true);
                }
                Item::Impl(imp) => {
                    let ty = type_name(&imp.self_ty);
                    let is_trait_impl = imp.trait_.is_some();
                    let qual = match &imp.trait_ {
                        Some((_, path, _)) => {
                            let tr = path
                                .segments
                                .last()
                                .map(|s| s.ident.to_string())
                                .unwrap_or_default();
                            (ty.clone(), Some(tr))
                        }
                        None => (ty.clone(), None),
                    };
                    for ii in &imp.items {
                        if let ImplItem::Fn(m) = ii {
                            // Trait impl methods are not callable by path without
                            // importing the trait, so they are never `is_pub`.
                            let callable = !is_trait_impl;
                            let body = m.block.to_token_stream();
                            self.push_fn(
                                scope,
                                Some(&qual),
                                &m.attrs,
                                &m.vis,
                                &m.sig,
                                body,
                                callable,
                            );
                        }
                    }
                }
                Item::Trait(tr) => {
                    let qual = (tr.ident.to_string(), None);
                    for ti in &tr.items {
                        if let TraitItem::Fn(m) = ti {
                            if let Some(block) = &m.default {
                                self.push_fn(
                                    scope,
                                    Some(&qual),
                                    &m.attrs,
                                    &tr.vis,
                                    &m.sig,
                                    block.to_token_stream(),
                                    false,
                                );
                            }
                        }
                    }
                }
                Item::Mod(m) => {
                    let mut child = scope.clone();
                    child.mods.push(m.ident.to_string());
                    child.in_test_mod |= has_cfg_test(&m.attrs);
                    if scope.target == Target::Lib {
                        self.mod_decls
                            .insert(child.mods.clone(), matches!(m.vis, Visibility::Public(_)));
                    }
                    if let Some((_, items)) = &m.content {
                        self.items(items, &child);
                    }
                }
                Item::Macro(m) if m.mac.path.is_ident("macro_rules") => {
                    let name = m.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
                    let key = unique_key(
                        &self.idx.macros,
                        format!("{}::{}!{}", scope.file, scope.mods.join("::"), name),
                    );
                    self.idx.macros.insert(key, m.mac.tokens.to_string());
                }
                _ => {}
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn push_fn(
        &mut self,
        scope: &Scope,
        qual: Option<&(String, Option<String>)>,
        attrs: &[Attribute],
        vis: &Visibility,
        sig: &Signature,
        body: TokenStream,
        callable: bool,
    ) {
        let name = sig.ident.to_string();
        let mut local: Vec<String> = scope.mods.clone();
        let mut key_tail = String::new();
        if let Some((ty, tr)) = qual {
            local.push(ty.clone());
            if let Some(tr) = tr {
                key_tail = format!("<{tr}>");
            }
        }
        local.push(name.clone());
        let target_tag = match scope.target {
            Target::Lib => "lib",
            Target::Bin => "bin",
            Target::Test => "test",
        };
        let key = unique_key(
            &self.idx.fns,
            format!(
                "{}|{}|{}|{}{}",
                self.krate.dir,
                target_tag,
                scope.file,
                local.join("::"),
                key_tail
            ),
        );
        let is_test = attrs
            .iter()
            .any(|a| a.path().segments.last().is_some_and(|s| s.ident == "test"));
        let test_name = is_test.then(|| {
            let mut p = scope.mods.clone();
            p.push(name.clone());
            p.join("::")
        });
        let mut fingerprint = String::new();
        for a in attrs.iter().filter(|a| !a.path().is_ident("doc")) {
            fingerprint.push_str(&a.to_token_stream().to_string());
        }
        fingerprint.push_str(&vis.to_token_stream().to_string());
        fingerprint.push_str(&sig.to_token_stream().to_string());
        fingerprint.push_str(&body.to_string());
        let mut idents = BTreeSet::new();
        collect_idents(body, &mut idents);
        let entry = FnEntry {
            sig: FnSignature {
                path: format!("{}::{}", self.krate.name, local.join("::")),
                args: sig.inputs.iter().map(arg_text).collect(),
                ret: match &sig.output {
                    ReturnType::Default => "()".to_string(),
                    ReturnType::Type(_, ty) => pretty(ty.to_token_stream()),
                },
                is_pub: false,
            },
            name,
            fingerprint,
            idents,
            reportable: scope.target != Target::Test && !scope.in_test_mod && !is_test,
            test_name,
        };
        self.raw.push(RawFn {
            key,
            mods: scope.mods.clone(),
            target: scope.target.clone(),
            in_test_mod: scope.in_test_mod,
            fn_pub: callable && matches!(vis, Visibility::Public(_)),
            entry,
        });
    }

    /// Resolves `is_pub` (the fn and every enclosing module are `pub`, in the
    /// library target) and moves the functions into the index.
    fn finish(self) {
        for mut r in self.raw {
            r.entry.sig.is_pub = r.fn_pub
                && r.target == Target::Lib
                && !r.in_test_mod
                && (1..=r.mods.len())
                    .all(|n| self.mod_decls.get(&r.mods[..n]).copied() == Some(true));
            self.idx.fns.insert(r.key, r.entry);
        }
    }
}

/// Keys must be unique even for `#[cfg]`-duplicated items.
fn unique_key<V>(map: &BTreeMap<String, V>, base: String) -> String {
    if !map.contains_key(&base) {
        return base;
    }
    (2..)
        .map(|n| format!("{base}#{n}"))
        .find(|k| !map.contains_key(k))
        .expect("unbounded")
}

fn has_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && a.meta
                .to_token_stream()
                .into_iter()
                .any(|t| token_mentions(&t, "test"))
    })
}

fn token_mentions(t: &TokenTree, word: &str) -> bool {
    match t {
        TokenTree::Ident(i) => i == word,
        TokenTree::Group(g) => g.stream().into_iter().any(|t| token_mentions(&t, word)),
        _ => false,
    }
}

fn collect_idents(ts: TokenStream, out: &mut BTreeSet<String>) {
    for t in ts {
        match t {
            TokenTree::Ident(i) => {
                out.insert(i.to_string());
            }
            TokenTree::Group(g) => collect_idents(g.stream(), out),
            _ => {}
        }
    }
}

/// Last path segment of an impl's self type (`impl<T> a::Foo<T>` -> `Foo`).
fn type_name(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        other => pretty(other.to_token_stream()),
    }
}

fn arg_text(arg: &FnArg) -> String {
    match arg {
        FnArg::Receiver(r) => pretty(r.to_token_stream()),
        FnArg::Typed(t) => pretty(t.ty.to_token_stream()),
    }
}

/// Token printing with the spacing a human would write: `& 'a [u8]` ->
/// `&'a [u8]`, `Option < u32 >` -> `Option<u32>`.
pub(crate) fn pretty(ts: TokenStream) -> String {
    let mut s = ts.to_string();
    for (from, to) in [
        (" :: ", "::"),
        (":: ", "::"),
        (" ::", "::"),
        (" < ", "<"),
        ("< ", "<"),
        (" <", "<"),
        (" >", ">"),
        ("& ", "&"),
        (" ,", ","),
        ("[ ", "["),
        (" ]", "]"),
        ("( ", "("),
        (" )", ")"),
        (" ;", ";"),
        (" : ", ": "),
    ] {
        s = s.replace(from, to);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_prints_common_types() {
        let t = |s: &str| pretty(syn::parse_str::<syn::Type>(s).unwrap().to_token_stream());
        assert_eq!(t("&str"), "&str");
        assert_eq!(t("Option<Vec<u8>>"), "Option<Vec<u8>>");
        assert_eq!(t("&'a [u8]"), "&'a [u8]");
        assert_eq!(t("&mut std::string::String"), "&mut std::string::String");
        assert_eq!(t("[u8; 4]"), "[u8; 4]");
    }

    #[test]
    fn classifies_paths() {
        assert_eq!(classify("src/lib.rs", true), Some((Target::Lib, vec![])));
        assert_eq!(
            classify("src/a/mod.rs", true),
            Some((Target::Lib, vec!["a".to_string()]))
        );
        assert_eq!(
            classify("src/a/b.rs", true),
            Some((Target::Lib, vec!["a".to_string(), "b".to_string()]))
        );
        assert_eq!(classify("src/a.rs", false).unwrap().0, Target::Bin);
        assert_eq!(classify("tests/it.rs", true), Some((Target::Test, vec![])));
        assert_eq!(classify("benches/b.rs", true), None);
    }
}
