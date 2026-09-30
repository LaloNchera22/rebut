use serde::{Deserialize, Serialize};

/// A full 40-hex-character git commit id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CommitSha(String);

impl CommitSha {
    pub fn new(s: impl Into<String>) -> Result<Self, String> {
        let s = s.into().to_ascii_lowercase();
        if s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(CommitSha(s))
        } else {
            Err(format!("not a full commit sha: {s:?}"))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CommitSha {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for CommitSha {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        CommitSha::new(s)
    }
}

impl From<CommitSha> for String {
    fn from(c: CommitSha) -> String {
        c.0
    }
}

/// `owner/name` on the forge.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RepoId {
    pub owner: String,
    pub name: String,
}

impl std::fmt::Display for RepoId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullRequest {
    pub repo: RepoId,
    pub number: u64,
    pub base_sha: CommitSha,
    pub head_sha: CommitSha,
    /// Clone URL of the head repository (may be a fork).
    pub head_clone_url: String,
    pub base_clone_url: String,
    pub author: String,
    pub body: String,
}
