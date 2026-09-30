//! Process configuration, from flags or environment variables.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Clone, Parser)]
#[command(name = "verifier-control", about = "rebut control plane", version)]
pub struct Config {
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    pub database_url: String,
    #[arg(long, env = "GITHUB_WEBHOOK_SECRET", hide_env_values = true)]
    pub github_webhook_secret: String,
    #[arg(long, env = "GITHUB_APP_ID")]
    pub github_app_id: u64,
    #[arg(long, env = "GITHUB_PRIVATE_KEY_PATH")]
    pub github_private_key_path: PathBuf,
    #[arg(long, env = "GITHUB_API_URL", default_value = crate::github::DEFAULT_API)]
    pub github_api_url: String,
    /// ed25519 seed (32 raw bytes or 64 hex chars) that signs receipts.
    #[arg(long, env = "SIGNING_KEY_PATH")]
    pub signing_key_path: PathBuf,
    #[arg(long, env = "BIND", default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,
    /// Bearer token for the maintainer-only verdict endpoint (disabled if unset).
    #[arg(long, env = "MAINTAINER_TOKEN", hide_env_values = true)]
    pub maintainer_token: Option<String>,
    /// Public base URL of this service, for receipt links in check runs.
    #[arg(long, env = "PUBLIC_URL")]
    pub public_url: Option<String>,
    /// Append receipts to this Rekor instance instead of the in-memory log.
    #[arg(long, env = "REKOR_URL")]
    pub rekor_url: Option<String>,
    #[arg(long, env = "WORKERS", default_value_t = 4)]
    pub workers: usize,
    #[arg(long, env = "JOB_LEASE_SECS", default_value_t = 3600)]
    pub job_lease_secs: u64,
    #[arg(long, env = "JOB_MAX_ATTEMPTS", default_value_t = 3)]
    pub job_max_attempts: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flags_with_defaults() {
        let c = Config::try_parse_from([
            "verifier-control",
            "--database-url=postgres://x",
            "--github-webhook-secret=s",
            "--github-app-id=42",
            "--github-private-key-path=/k.pem",
            "--signing-key-path=/sign.key",
        ])
        .unwrap();
        assert_eq!(c.github_app_id, 42);
        assert_eq!(c.bind.port(), 8080);
        assert_eq!(c.workers, 4);
        assert!(c.maintainer_token.is_none());
    }
}
