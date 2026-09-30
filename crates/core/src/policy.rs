//! Maintainer policy, read from `.verifier/policy.toml` on the **base** branch
//! (never from the PR head: a PR must not be able to relax its own checks).

use serde::{Deserialize, Serialize};

use crate::EngineKind;

/// Phase 1 ships in `Mark` mode: the check run concludes `neutral` and
/// annotates, it never fails a PR. `Block` is opt-in per repository once the
/// maintainer has seen weeks without false positives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    #[default]
    Mark,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Wall-clock limit for one microVM run, in seconds.
    pub vm_timeout_secs: u64,
    pub vcpus: u8,
    pub memory_mib: u32,
    /// Max total VM-seconds spent on one PR across all engines.
    pub pr_vm_seconds: u64,
    /// Public challenge cases generated per PR.
    pub public_challenges: u32,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            vm_timeout_secs: 600,
            vcpus: 2,
            memory_mib: 4096,
            pr_vm_seconds: 1800,
            public_challenges: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub mode: EnforcementMode,
    #[serde(default = "Policy::default_engines")]
    pub engines: Vec<EngineKind>,
    #[serde(default)]
    pub budget: Budget,
    /// SHA-256 commitments to the maintainer's sealed challenge specs. The
    /// specs themselves live outside the repo; only their hashes are public.
    #[serde(default)]
    pub sealed_commitments: Vec<crate::Digest>,
}

impl Policy {
    fn default_engines() -> Vec<EngineKind> {
        vec![EngineKind::Differential, EngineKind::Challenges]
    }

    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            mode: EnforcementMode::Mark,
            engines: Self::default_engines(),
            budget: Budget::default(),
            sealed_commitments: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_is_mark_mode() {
        let p = Policy::from_toml("").unwrap();
        assert_eq!(p.mode, EnforcementMode::Mark);
        assert_eq!(
            p.engines,
            vec![EngineKind::Differential, EngineKind::Challenges]
        );
    }
}
