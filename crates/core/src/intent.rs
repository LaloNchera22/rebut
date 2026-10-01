//! The intent manifest: what the contributor *claims* the PR does.
//!
//! The differential engine checks the claim. A PR that declares
//! `refactor` promises that no observable behavior changes, so any divergence
//! between base and head on the same inputs is a finding.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// No observable behavior change anywhere.
    Refactor,
    /// Behavior changes only in the functions listed in `changes_behavior_of`.
    Bugfix,
    Feature,
    Performance,
    /// No claim; differential divergences are reported as informational.
    #[default]
    Unspecified,
}

/// Parsed from `.rebut/intent.toml` in the head commit, or from a fenced
/// ```rebut-intent``` block in the PR body (the file wins).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IntentManifest {
    #[serde(default)]
    pub kind: ChangeKind,
    /// Fully qualified paths (`crate::module::function`) whose behavior is
    /// allowed to change.
    #[serde(default)]
    pub changes_behavior_of: Vec<String>,
    #[serde(default)]
    pub summary: String,
}

impl IntentManifest {
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Extract a ```rebut-intent fenced block from a PR body.
    pub fn from_pr_body(body: &str) -> Option<Result<Self, toml::de::Error>> {
        let start = body.find("```rebut-intent")?;
        let rest = &body[start + "```rebut-intent".len()..];
        let rest = rest
            .strip_prefix('\n')
            .or_else(|| rest.strip_prefix("\r\n"))
            .unwrap_or(rest);
        let end = rest.find("```")?;
        Some(Self::from_toml(&rest[..end]))
    }

    /// Is a behavior change in `path` consistent with the declared intent?
    pub fn allows_behavior_change(&self, path: &str) -> bool {
        match self.kind {
            ChangeKind::Refactor | ChangeKind::Performance => false,
            ChangeKind::Bugfix => self.lists(path),
            ChangeKind::Feature | ChangeKind::Unspecified => true,
        }
    }

    /// Is `path` (or an enclosing module/type) listed in
    /// `changes_behavior_of`? Whatever the kind, this is the only way to
    /// explain a behavior change in a function whose own code did not change
    /// (e.g. after a dependency update).
    pub fn lists(&self, path: &str) -> bool {
        self.changes_behavior_of
            .iter()
            .any(|p| p == path || path.starts_with(&format!("{p}::")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_body_block() {
        let body = "Fixes overflow.\n\n```rebut-intent\nkind = \"bugfix\"\nchanges_behavior_of = [\"mylib::parse\"]\n```\n";
        let m = IntentManifest::from_pr_body(body).unwrap().unwrap();
        assert_eq!(m.kind, ChangeKind::Bugfix);
        assert!(m.allows_behavior_change("mylib::parse"));
        assert!(m.allows_behavior_change("mylib::parse::inner"));
        assert!(!m.allows_behavior_change("mylib::parser"));
    }

    #[test]
    fn refactor_allows_nothing() {
        let m = IntentManifest {
            kind: ChangeKind::Refactor,
            ..Default::default()
        };
        assert!(!m.allows_behavior_change("anything"));
    }
}
