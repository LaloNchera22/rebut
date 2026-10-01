//! The example files under `policies/` must stay in sync with the schema.

use std::path::PathBuf;

use rebut_core::{EnforcementMode, IntentManifest, Policy};

fn read(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../policies")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[test]
fn example_policies_parse() {
    let default = Policy::from_toml(&read("default.toml")).unwrap();
    assert_eq!(default.mode, EnforcementMode::Mark);
    let strict = Policy::from_toml(&read("strict.toml")).unwrap();
    assert_eq!(strict.mode, EnforcementMode::Block);
    IntentManifest::from_toml(&read("intent.example.toml")).unwrap();
}
