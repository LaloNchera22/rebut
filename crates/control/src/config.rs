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
    /// Where untrusted code runs. `none` refuses to run anything (every
    /// verdict is inconclusive); `insecure-local` runs it UNSANDBOXED on this
    /// host and exists only for development.
    #[arg(long, env = "EXECUTOR", value_enum, default_value = "none")]
    pub executor: ExecutorKind,
    /// Cache of source checkouts (read-only use on the host).
    #[arg(long, env = "CHECKOUT_DIR", default_value = "/var/lib/rebut/checkouts")]
    pub checkout_dir: PathBuf,
    /// Maintainers' sealed challenge specs: `<dir>/<owner>/<repo>/*.toml`.
    #[arg(long, env = "SEALED_SPECS_DIR")]
    pub sealed_specs_dir: Option<PathBuf>,
    /// drand relay; defaults to the League of Entropy quicknet endpoint.
    #[arg(long, env = "DRAND_URL")]
    pub drand_url: Option<String>,
    /// Enables the formal engine's invariant proposer and the rival agent
    /// (phase 2). Their output is only ever a hypothesis to replay (ADR-6).
    /// Models: `VERIFIER_FORMAL_MODEL`, `VERIFIER_ADVERSARY_MODEL`.
    #[arg(long, env = "ANTHROPIC_API_KEY", hide_env_values = true)]
    pub anthropic_api_key: Option<String>,
    #[command(flatten)]
    pub firecracker: FirecrackerArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExecutorKind {
    None,
    Firecracker,
    InsecureLocal,
}

/// Required when `EXECUTOR=firecracker` (ADR-4: bare metal with KVM).
#[derive(Debug, Clone, clap::Args)]
pub struct FirecrackerArgs {
    #[arg(long, env = "FC_JAILER", default_value = "/usr/local/bin/jailer")]
    pub fc_jailer: PathBuf,
    #[arg(
        long,
        env = "FC_FIRECRACKER",
        default_value = "/usr/local/bin/firecracker"
    )]
    pub fc_firecracker: PathBuf,
    #[arg(long, env = "FC_KERNEL", default_value = "/var/lib/rebut/vmlinux")]
    pub fc_kernel: PathBuf,
    #[arg(long, env = "FC_ROOTFS", default_value = "/var/lib/rebut/rootfs.ext4")]
    pub fc_rootfs: PathBuf,
    #[arg(
        long,
        env = "FC_BOOT_ARGS",
        default_value = "console=ttyS0 reboot=k panic=1 pci=off"
    )]
    pub fc_boot_args: String,
    #[arg(long, env = "FC_UID", default_value_t = 10000)]
    pub fc_uid: u32,
    #[arg(long, env = "FC_GID", default_value_t = 10000)]
    pub fc_gid: u32,
    #[arg(long, env = "FC_CHROOT_BASE", default_value = "/srv/jailer")]
    pub fc_chroot_base: PathBuf,
    #[arg(
        long,
        env = "FC_CGROUP_ROOT",
        default_value = "/sys/fs/cgroup/firecracker"
    )]
    pub fc_cgroup_root: PathBuf,
    #[arg(long, env = "FC_SECCOMP_FILTER")]
    pub fc_seccomp_filter: Option<PathBuf>,
    #[arg(long, env = "FC_SCRATCH_MIB", default_value_t = 16384)]
    pub fc_scratch_mib: u64,
    #[arg(long, env = "FC_TOOLCHAIN", default_value = "stable")]
    pub fc_toolchain: String,
    #[arg(long, env = "FC_SNAPSHOT_DIR")]
    pub fc_snapshot_dir: Option<PathBuf>,
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
