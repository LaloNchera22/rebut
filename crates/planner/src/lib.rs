//! The impact planner: diff → functions → tests.
//!
//! Input is two checkouts on disk (base and head). Every `.rs` file under
//! each crate's `src/` and `tests/` is parsed with `syn`; functions are keyed
//! by crate, target, module path and qualified name, and compared by the token
//! text of their attributes, signature and body (so formatting and comments
//! never count as changes). Tests are selected when their body mentions, by
//! identifier, a changed function or a helper that does.
//!
//! The planner is deliberately conservative: whenever the diff touches
//! something it cannot reason about (build scripts, manifests, the lockfile,
//! proc-macro crates, `macro_rules!` bodies, unparsable files, non-Rust files
//! under `src/`), it sets [`ImpactPlan::widen_to_full_suite`].

mod files;
mod index;

use std::collections::BTreeSet;
use std::path::Path;

use verifier_core::{FnSignature, ImpactPlan};

pub use files::{changed_files, MAX_FILE_BYTES};

/// Detailed planner output. [`Analysis::into_plan`] (or `From`) gives the
/// [`ImpactPlan`] engines consume.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Analysis {
    /// Present in both trees with a different body or signature (head
    /// signature).
    pub modified: Vec<FnSignature>,
    /// Only in head.
    pub added: Vec<FnSignature>,
    /// Only in base (base signature).
    pub removed: Vec<FnSignature>,
    /// libtest names (`module::path::test_name`, no crate prefix), sorted.
    pub tests: Vec<String>,
    pub changed_files: Vec<String>,
    /// Why the plan widens to the full suite; empty when it does not.
    pub widen_reasons: Vec<String>,
}

impl Analysis {
    pub fn widen_to_full_suite(&self) -> bool {
        !self.widen_reasons.is_empty()
    }

    /// `changed_functions` = modified ∪ added ∪ removed, sorted by path and
    /// deduplicated (trait impls of several traits may share a path).
    pub fn into_plan(self) -> ImpactPlan {
        let widen = self.widen_to_full_suite();
        let mut changed: Vec<FnSignature> = self
            .modified
            .into_iter()
            .chain(self.added)
            .chain(self.removed)
            .collect();
        changed.sort_by(|a, b| a.path.cmp(&b.path));
        changed.dedup_by(|a, b| a.path == b.path);
        ImpactPlan {
            changed_functions: changed,
            tests: self.tests,
            changed_files: self.changed_files,
            widen_to_full_suite: widen,
        }
    }
}

impl From<Analysis> for ImpactPlan {
    fn from(a: Analysis) -> Self {
        a.into_plan()
    }
}

/// Plans the impact of turning `base` into `head`.
pub fn plan(base: &Path, head: &Path) -> anyhow::Result<ImpactPlan> {
    Ok(analyze(base, head)?.into_plan())
}

/// Like [`plan`], keeping the modified/added/removed split and the reasons
/// for widening.
pub fn analyze(base: &Path, head: &Path) -> anyhow::Result<Analysis> {
    let base_files = files::walk(base)?;
    let head_files = files::walk(head)?;
    let changed_files = files::diff(&base_files, &head_files);
    let bi = index::index_tree(&base_files);
    let hi = index::index_tree(&head_files);

    let mut widen = BTreeSet::new();
    for f in &changed_files {
        let file_name = f.rsplit('/').next().unwrap_or(f);
        if matches!(file_name, "build.rs" | "Cargo.toml" | "Cargo.lock") {
            widen.insert(format!("{f} changed"));
        }
        if bi.unparsable.contains(f) || hi.unparsable.contains(f) {
            widen.insert(format!("{f} could not be parsed"));
        }
        let in_proc_macro = bi
            .proc_macro_dirs
            .iter()
            .chain(&hi.proc_macro_dirs)
            .any(|d| d.is_empty() || f.starts_with(&format!("{d}/")));
        if in_proc_macro {
            widen.insert(format!("{f} belongs to a proc-macro crate"));
        }
        let under_src = f.starts_with("src/") || f.contains("/src/");
        if under_src && !f.ends_with(".rs") {
            // Possibly pulled in by include_str!/include_bytes!.
            widen.insert(format!("{f} is a non-Rust file under src/"));
        }
    }
    let macro_keys: BTreeSet<&String> = bi.macros.keys().chain(hi.macros.keys()).collect();
    for k in macro_keys {
        if bi.macros.get(k) != hi.macros.get(k) {
            widen.insert(format!("macro_rules! {k} changed"));
        }
    }

    let (mut modified, mut added, mut removed) = (Vec::new(), Vec::new(), Vec::new());
    // Names of every changed function (library, binary, test helper or test).
    let mut changed_names = BTreeSet::new();
    // Tests that are themselves new or modified.
    let mut direct_tests = BTreeSet::new();
    for (k, h) in &hi.fns {
        let status = match bi.fns.get(k) {
            Some(b) if b.fingerprint == h.fingerprint => continue,
            Some(_) => &mut modified,
            None => &mut added,
        };
        changed_names.insert(h.name.clone());
        if let Some(t) = &h.test_name {
            direct_tests.insert(t.clone());
        }
        if h.reportable {
            status.push(h.sig.clone());
        }
    }
    for (k, b) in &bi.fns {
        if !hi.fns.contains_key(k) {
            changed_names.insert(b.name.clone());
            if b.reportable {
                removed.push(b.sig.clone());
            }
        }
    }

    // One level of indirection: helpers (non-test fns) that call a changed fn.
    let mut reach = changed_names.clone();
    for f in hi.fns.values() {
        if f.test_name.is_none() && !f.idents.is_disjoint(&changed_names) {
            reach.insert(f.name.clone());
        }
    }
    let mut tests: BTreeSet<String> = direct_tests;
    for f in hi.fns.values() {
        if let Some(t) = &f.test_name {
            if !f.idents.is_disjoint(&reach) {
                tests.insert(t.clone());
            }
        }
    }

    for v in [&mut modified, &mut added, &mut removed] {
        v.sort_by(|a, b| a.path.cmp(&b.path));
    }
    Ok(Analysis {
        modified,
        added,
        removed,
        tests: tests.into_iter().collect(),
        changed_files,
        widen_reasons: widen.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const MANIFEST: &str = "[package]\nname = \"my-lib\"\nversion = \"0.1.0\"\n";

    struct Fixture {
        base: TempDir,
        head: TempDir,
    }

    impl Fixture {
        /// Both trees start with the same files.
        fn new(files: &[(&str, &str)]) -> Self {
            let fx = Fixture {
                base: tempfile::tempdir().unwrap(),
                head: tempfile::tempdir().unwrap(),
            };
            for (p, c) in files {
                write(fx.base.path(), p, c);
                write(fx.head.path(), p, c);
            }
            fx
        }
        fn head(&self, p: &str, c: &str) -> &Self {
            write(self.head.path(), p, c);
            self
        }
        fn analyze(&self) -> Analysis {
            analyze(self.base.path(), self.head.path()).unwrap()
        }
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    fn paths(v: &[FnSignature]) -> Vec<&str> {
        v.iter().map(|s| s.path.as_str()).collect()
    }

    const LIB: &str = r#"
pub mod math;
mod private;

/// Adds.
pub fn add(a: u32, b: u32) -> u32 { a + b }

pub fn uses_add(x: u32) -> u32 { add(x, 1) }

pub struct Counter(u32);

impl Counter {
    pub fn bump(&mut self, by: u32) -> u32 { self.0 += by; self.0 }
    pub fn new() -> Self { Counter(0) }
}

impl std::fmt::Display for Counter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn adds() { assert_eq!(add(1, 2), 3); }
    #[test]
    fn via_helper() { assert_eq!(uses_add(1), 2); }
    #[test]
    fn counter() { let mut c = Counter::new(); assert_eq!(c.bump(2), 2); }
    #[tokio::test]
    async fn unrelated() { assert!(true); }
}
"#;

    const MATH: &str = r#"
pub fn parse(s: &str, radix: Option<u32>) -> Result<i64, String> { i64::from_str_radix(s, radix.unwrap_or(10)).map_err(|e| e.to_string()) }
pub mod inner {
    pub fn twice(v: &[u8]) -> Vec<u8> { v.iter().chain(v).copied().collect() }
}
"#;

    const PRIVATE: &str = "pub fn hidden() -> u8 { 1 }\n";

    fn base_fixture() -> Fixture {
        Fixture::new(&[
            ("Cargo.toml", MANIFEST),
            ("src/lib.rs", LIB),
            ("src/math.rs", MATH),
            ("src/private.rs", PRIVATE),
            (
                "tests/it.rs",
                "#[test]\nfn parses() { assert!(my_lib::math::parse(\"1\", None).is_ok()); }\n",
            ),
        ])
    }

    #[test]
    fn no_change_is_empty_plan() {
        let a = base_fixture().analyze();
        assert_eq!(a, Analysis::default());
    }

    #[test]
    fn formatting_and_doc_changes_are_not_changes() {
        let fx = base_fixture();
        let reformatted = LIB.replace(
            "/// Adds.\npub fn add(a: u32, b: u32) -> u32 { a + b }",
            "/// Adds two numbers.\npub fn add(a: u32,\n    b: u32) -> u32 {\n    // sum\n    a + b\n}",
        );
        fx.head("src/lib.rs", &reformatted);
        let a = fx.analyze();
        assert_eq!(a.changed_files, vec!["src/lib.rs"]);
        assert!(a.modified.is_empty() && a.tests.is_empty());
        assert!(!a.widen_to_full_suite());
    }

    #[test]
    fn body_change_selects_direct_and_helper_tests() {
        let fx = base_fixture();
        fx.head(
            "src/lib.rs",
            &LIB.replace("{ a + b }", "{ a.wrapping_add(b) }"),
        );
        let a = fx.analyze();
        assert_eq!(paths(&a.modified), vec!["my_lib::add"]);
        let sig = &a.modified[0];
        assert_eq!(sig.args, vec!["u32", "u32"]);
        assert_eq!(sig.ret, "u32");
        assert!(sig.is_pub);
        // `adds` calls add inside assert_eq!, `via_helper` through uses_add.
        assert_eq!(a.tests, vec!["tests::adds", "tests::via_helper"]);
    }

    #[test]
    fn nested_modules_and_signatures() {
        let fx = base_fixture();
        let math = MATH
            .replace("unwrap_or(10)", "unwrap_or(16)")
            .replace("chain(v)", "chain(v.iter().rev())");
        fx.head("src/math.rs", &math);
        let a = fx.analyze();
        assert_eq!(
            paths(&a.modified),
            vec!["my_lib::math::inner::twice", "my_lib::math::parse"]
        );
        assert_eq!(a.modified[0].args, vec!["&[u8]"]);
        assert_eq!(a.modified[1].args, vec!["&str", "Option<u32>"]);
        assert_eq!(a.modified[1].ret, "Result<i64, String>");
        assert!(a.modified.iter().all(|s| s.is_pub));
        // Integration test names carry no crate or file prefix.
        assert_eq!(a.tests, vec!["parses"]);
    }

    #[test]
    fn methods_trait_impls_and_privacy() {
        let fx = base_fixture();
        let lib = LIB
            .replace("self.0 += by;", "self.0 += by * 2;")
            .replace("write!(f, \"{}\"", "write!(f, \"#{}\"");
        fx.head("src/lib.rs", &lib)
            .head("src/private.rs", "pub fn hidden() -> u8 { 2 }\n");
        let a = fx.analyze();
        let plan = a.clone().into_plan();
        assert_eq!(
            paths(&plan.changed_functions),
            vec![
                "my_lib::Counter::bump",
                "my_lib::Counter::fmt",
                "my_lib::private::hidden"
            ]
        );
        let by_path = |p: &str| plan.changed_functions.iter().find(|s| s.path == p).unwrap();
        assert_eq!(
            by_path("my_lib::Counter::bump").args,
            vec!["&mut self", "u32"]
        );
        assert!(by_path("my_lib::Counter::bump").is_pub);
        // Trait impl methods and fns in private modules are not callable by path.
        assert!(!by_path("my_lib::Counter::fmt").is_pub);
        assert!(!by_path("my_lib::private::hidden").is_pub);
        assert_eq!(a.tests, vec!["tests::counter"]);
    }

    #[test]
    fn added_removed_and_changed_tests() {
        let fx = base_fixture();
        let lib = LIB
            .replace(
                "pub fn uses_add(x: u32) -> u32 { add(x, 1) }",
                "pub fn fresh() {}",
            )
            .replace("assert!(true)", "assert!(!false)");
        fx.head("src/lib.rs", &lib);
        let a = fx.analyze();
        assert_eq!(paths(&a.added), vec!["my_lib::fresh"]);
        assert_eq!(paths(&a.removed), vec!["my_lib::uses_add"]);
        // `unrelated` changed itself; `via_helper` mentions the removed fn.
        assert_eq!(a.tests, vec!["tests::unrelated", "tests::via_helper"]);
        assert!(a.modified.is_empty());
    }

    #[test]
    fn widening_triggers() {
        let fx = base_fixture();
        fx.head("build.rs", "fn main() {}");
        assert!(fx.analyze().widen_reasons[0].contains("build.rs"));

        let fx = base_fixture();
        fx.head("Cargo.toml", &format!("{MANIFEST}\n[dependencies]\n"));
        assert!(fx.analyze().widen_to_full_suite());

        let fx = base_fixture();
        fx.head("src/lib.rs", &format!("{LIB}\nfn broken( {{"));
        let a = fx.analyze();
        assert_eq!(a.widen_reasons, vec!["src/lib.rs could not be parsed"]);

        let fx = base_fixture();
        fx.head("src/data.txt", "included");
        assert!(fx.analyze().widen_to_full_suite());

        let with_macro = |body: &str| format!("{LIB}\nmacro_rules! m {{ () => {{ {body} }} }}\n");
        let fx = Fixture::new(&[("Cargo.toml", MANIFEST), ("src/lib.rs", &with_macro("1"))]);
        fx.head("src/lib.rs", &with_macro("2"));
        let a = fx.analyze();
        assert!(a.widen_reasons.iter().any(|r| r.contains("macro_rules! ")));
        assert!(a.into_plan().widen_to_full_suite);
    }

    #[test]
    fn proc_macro_crates_widen() {
        let pm = "[package]\nname = \"derive-x\"\nversion = \"0.1.0\"\n[lib]\nproc-macro = true\n";
        let fx = Fixture::new(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"derive\", \"app\"]\n",
            ),
            ("derive/Cargo.toml", pm),
            ("derive/src/lib.rs", "pub fn f() {}"),
            ("app/Cargo.toml", MANIFEST),
            ("app/src/lib.rs", "pub fn g() -> u8 { 1 }"),
        ]);
        fx.head("derive/src/lib.rs", "pub fn f() { let _ = 1; }");
        let a = fx.analyze();
        assert_eq!(
            a.widen_reasons,
            vec!["derive/src/lib.rs belongs to a proc-macro crate"]
        );

        // Workspace member crates get their own crate name.
        fx.head("derive/src/lib.rs", "pub fn f() {}")
            .head("app/src/lib.rs", "pub fn g() -> u8 { 2 }");
        let a = fx.analyze();
        assert!(!a.widen_to_full_suite());
        assert_eq!(paths(&a.modified), vec!["my_lib::g"]);
    }
}
