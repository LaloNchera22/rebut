//! Production executor: one ephemeral Firecracker microVM per request.
//!
//! ADR-4 in code:
//! * Firecracker runs under `jailer` (chroot, unprivileged uid/gid, new PID
//!   namespace, cgroup v2 CPU/memory limits) with its seccomp filter on.
//! * The VM has **no network device** ([`vmconfig`] cannot express one); the
//!   only channel is vsock, carrying the framed [`rebut_guest::protocol`].
//! * Each request gets a fresh VM: cold-booted from a read-only rootfs, or
//!   restored from a [`SnapshotCache`] snapshot holding a warm cargo cache for
//!   the repository. The VM, its jail and its scratch drive are destroyed
//!   afterwards; the hard deadline is enforced by killing the VM.
//! * Building (`build.rs`, proc-macros) happens inside the VM.
//!
//! Rootfs contract: an init that mounts tmpfs over the writable paths,
//! formats/mounts the scratch drive (`/dev/vdb`) at `/scratch`, mounts the
//! optional cargo cache drive read-only as `CARGO_HOME`, and runs
//! `rebut-guest --work-root /scratch`. Snapshots must be taken with the
//! agent listening and the scratch drive not yet mounted, since the drive is
//! recreated empty for every restore.

pub mod api;
pub mod jailer;
pub mod vmconfig;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use rebut_core::{Digest, ExecutionRequest, ExecutionResult, Executor};
use rebut_guest::protocol::GUEST_VSOCK_PORT;

use crate::session::{fill_timed_out, run_session};
use crate::snapshot::{digest_file, SnapshotCache, SnapshotEntry, SnapshotKey};
use crate::source::SourceProvider;
use jailer::{jailer_args, JailerConfig};
use vmconfig::{jail_paths, snapshot_load_body, vm_config, VmSpec};

const RETRY_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    pub jailer: JailerConfig,
    /// Uncompressed guest kernel (`vmlinux`).
    pub kernel: PathBuf,
    /// Read-only ext4 root filesystem with the toolchain and the agent.
    pub rootfs: PathBuf,
    pub boot_args: String,
    /// Size of the ephemeral scratch drive (sparse file).
    pub scratch_mib: u64,
    /// Toolchain baked into the rootfs; part of the snapshot key.
    pub toolchain: String,
    /// Time allowed on top of `timeout_secs` for boot/restore and teardown
    /// before the VM is killed.
    pub boot_grace: Duration,
}

/// `environment` digest of an execution: which kernel, rootfs and snapshot
/// the code ran on.
pub fn environment_digest(kernel: &Digest, rootfs: &Digest, snapshot: Option<&Digest>) -> Digest {
    Digest::of_parts(&[
        b"rebut/environment/firecracker/v1",
        &kernel.0,
        &rootfs.0,
        snapshot.map(|d| &d.0[..]).unwrap_or_default(),
    ])
}

pub struct FirecrackerExecutor {
    config: FirecrackerConfig,
    source: Arc<dyn SourceProvider>,
    snapshots: Option<Arc<SnapshotCache>>,
    kernel_digest: Digest,
    rootfs_digest: Digest,
}

impl FirecrackerExecutor {
    /// Hashes the kernel and rootfs once, up front.
    pub async fn new(
        config: FirecrackerConfig,
        source: impl SourceProvider + 'static,
        snapshots: Option<Arc<SnapshotCache>>,
    ) -> anyhow::Result<Self> {
        let (k, r) = (config.kernel.clone(), config.rootfs.clone());
        let (kernel_digest, rootfs_digest) = tokio::task::spawn_blocking(move || {
            anyhow::Ok((
                digest_file(&k).with_context(|| format!("hashing {}", k.display()))?,
                digest_file(&r).with_context(|| format!("hashing {}", r.display()))?,
            ))
        })
        .await??;
        Ok(FirecrackerExecutor {
            config,
            source: Arc::new(source),
            snapshots,
            kernel_digest,
            rootfs_digest,
        })
    }

    fn find_snapshot(&self, req: &ExecutionRequest, tgz: &[u8]) -> Option<SnapshotEntry> {
        let cache = self.snapshots.as_ref()?;
        let lock = rebut_guest::archive::read_file(tgz, Path::new("Cargo.lock")).ok()??;
        cache.get(&SnapshotKey {
            repo: req.repo_url.clone(),
            cargo_lock: Digest::of(&lock),
            toolchain: self.config.toolchain.clone(),
        })
    }
}

#[async_trait::async_trait]
impl Executor for FirecrackerExecutor {
    async fn execute(&self, req: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
        let tgz = self.source.fetch(&req).await?;
        let snapshot = self.find_snapshot(&req, &tgz);
        let id = req.id.to_string();
        let spec = VmSpec {
            vcpus: req.vcpus,
            memory_mib: req.memory_mib,
            boot_args: self.config.boot_args.clone(),
            cargo_cache: snapshot.as_ref().is_some_and(|s| s.cache_drive.is_some()),
        };
        tracing::info!(request = %req.id, snapshot = snapshot.is_some(), "starting microVM");

        let jail = Jail::stage(&self.config, &id, &spec, snapshot.as_ref())?;
        let args = jailer_args(
            &self.config.jailer,
            &id,
            req.vcpus,
            req.memory_mib,
            snapshot.is_none(),
        )?;
        // Console output never reaches our logs: it could carry sealed data.
        let mut jailer = tokio::process::Command::new(&self.config.jailer.jailer_bin)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("spawning jailer")?;

        let mut outcomes = Vec::with_capacity(req.steps.len());
        let hard_deadline = Duration::from_secs(req.timeout_secs) + self.config.boot_grace;
        let run = async {
            if snapshot.is_some() {
                let api = self.config.jailer.host_path(&id, jail_paths::API_SOCK);
                poll_ready(&mut jailer, || {
                    let ready = api.exists().then_some(());
                    async move { ready }
                })
                .await?;
                api::api_request(&api, "PUT", "/snapshot/load", &snapshot_load_body()).await?;
            }
            let uds = self.config.jailer.host_path(&id, jail_paths::VSOCK_UDS);
            let stream = poll_ready(&mut jailer, || {
                let uds = &uds;
                async move { api::vsock_connect(uds, GUEST_VSOCK_PORT).await.ok() }
            })
            .await?;
            run_session(stream, &req, &tgz, &mut outcomes).await?;
            anyhow::Ok(())
        };
        let result = tokio::time::timeout(hard_deadline, run).await;
        drop(jail); // Kills the VM and removes the jail.
        let _ = jailer.kill().await;

        match result {
            Ok(res) => res?,
            Err(_) => {
                tracing::warn!(request = %req.id, "hard deadline reached; microVM killed");
                fill_timed_out(&req, &mut outcomes);
            }
        }
        Ok(ExecutionResult {
            request_id: req.id,
            transcript: ExecutionResult::compute_transcript(&req, &outcomes),
            environment: environment_digest(
                &self.kernel_digest,
                &self.rootfs_digest,
                snapshot.as_ref().map(|s| &s.digest),
            ),
            outcomes,
        })
    }
}

/// Fails if the jailer exited unsuccessfully. (With `--new-pid-ns` it exits
/// with success once Firecracker is running in its namespace.)
fn check_jailer(jailer: &mut tokio::process::Child) -> anyhow::Result<()> {
    match jailer.try_wait()? {
        Some(status) if !status.success() => anyhow::bail!("jailer exited with {status}"),
        _ => Ok(()),
    }
}

/// Retries `attempt` until it yields a value, failing early if the jailer
/// died. The caller's deadline bounds the wait.
async fn poll_ready<T, F, Fut>(
    jailer: &mut tokio::process::Child,
    mut attempt: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    loop {
        if let Some(v) = attempt().await {
            return Ok(v);
        }
        check_jailer(jailer)?;
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

/// A staged jail directory. Dropping it kills the VM and deletes the jail.
struct Jail {
    cfg: JailerConfig,
    id: String,
}

impl Jail {
    fn stage(
        config: &FirecrackerConfig,
        id: &str,
        spec: &VmSpec,
        snapshot: Option<&SnapshotEntry>,
    ) -> anyhow::Result<Jail> {
        jailer::validate_id(id)?;
        let jail = Jail {
            cfg: config.jailer.clone(),
            id: id.to_string(),
        };
        let root = jail.cfg.jail_root(id);
        std::fs::create_dir_all(&root)?;
        let at = |p: &str| jail.cfg.host_path(id, p);

        link_or_copy(&config.kernel, &at(jail_paths::KERNEL))?;
        link_or_copy(&config.rootfs, &at(jail_paths::ROOTFS))?;
        let scratch = at(jail_paths::SCRATCH);
        std::fs::File::create(&scratch)?.set_len(config.scratch_mib * 1024 * 1024)?;
        let mut owned = vec![root.clone(), scratch];

        match snapshot {
            Some(s) => {
                link_or_copy(&s.vmstate, &at(jail_paths::SNAPSHOT_STATE))?;
                link_or_copy(&s.memory, &at(jail_paths::SNAPSHOT_MEM))?;
                if let Some(c) = &s.cache_drive {
                    link_or_copy(c, &at(jail_paths::CARGO_CACHE))?;
                }
            }
            None => {
                let cfg_path = at(jail_paths::CONFIG);
                std::fs::write(&cfg_path, serde_json::to_vec_pretty(&vm_config(spec)?)?)?;
                owned.push(cfg_path);
            }
        }
        let (uid, gid) = (jail.cfg.uid, jail.cfg.gid);
        for p in owned {
            std::os::unix::fs::chown(&p, Some(uid), Some(gid))
                .with_context(|| format!("chown {}", p.display()))?;
        }
        Ok(jail)
    }
}

impl Drop for Jail {
    fn drop(&mut self) {
        if let Ok(pid) = std::fs::read_to_string(self.cfg.pid_file(&self.id)) {
            if let Ok(pid) = pid.trim().parse::<i32>() {
                if pid > 1 {
                    // SAFETY: plain syscall on a pid we read from our own jail.
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
        // Belt and braces: kill everything left in the VM's cgroup.
        let _ = std::fs::write(self.cfg.cgroup_kill_file(&self.id), "1");
        if let Some(jail_dir) = self.cfg.jail_root(&self.id).parent() {
            let _ = std::fs::remove_dir_all(jail_dir);
        }
    }
}

/// Hard-links a read-only image into the jail, copying across filesystems.
fn link_or_copy(src: &Path, dst: &Path) -> anyhow::Result<()> {
    if std::fs::hard_link(src, dst).is_err() {
        std::fs::copy(src, dst).with_context(|| format!("staging {} into jail", src.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_digest_depends_on_every_input() {
        let (k, r, s) = (Digest::of(b"k"), Digest::of(b"r"), Digest::of(b"s"));
        let base = environment_digest(&k, &r, None);
        assert_eq!(base, environment_digest(&k, &r, None));
        assert_ne!(base, environment_digest(&k, &r, Some(&s)));
        assert_ne!(base, environment_digest(&r, &k, None));
        assert_ne!(base, crate::local::local_environment_digest());
    }

    fn config(dir: &Path) -> FirecrackerConfig {
        std::fs::write(dir.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"rootfs").unwrap();
        // SAFETY: getuid/getgid have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        FirecrackerConfig {
            jailer: JailerConfig {
                jailer_bin: "/nonexistent/jailer".into(),
                firecracker_bin: "/nonexistent/firecracker".into(),
                uid,
                gid,
                chroot_base: dir.join("jail"),
                cgroup_root: dir.join("cgroup"),
                seccomp_filter: None,
            },
            kernel: dir.join("vmlinux"),
            rootfs: dir.join("rootfs.ext4"),
            boot_args: vmconfig::DEFAULT_BOOT_ARGS.into(),
            scratch_mib: 4,
            toolchain: "1.80.0".into(),
            boot_grace: Duration::from_secs(1),
        }
    }

    #[test]
    fn stage_cold_boot_jail_and_clean_up() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let spec = VmSpec {
            vcpus: 1,
            memory_mib: 256,
            boot_args: cfg.boot_args.clone(),
            cargo_cache: false,
        };
        let jail = Jail::stage(&cfg, "vm-test", &spec, None).unwrap();
        let root = cfg.jailer.jail_root("vm-test");
        assert_eq!(std::fs::read(root.join("vmlinux")).unwrap(), b"kernel");
        assert_eq!(
            std::fs::metadata(root.join("scratch.img")).unwrap().len(),
            4 << 20
        );
        let vm: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("vm.json")).unwrap()).unwrap();
        assert!(vm.get("network-interfaces").is_none());
        assert!(!root.join("snapshot.vmstate").exists());
        drop(jail);
        assert!(!root.exists());
        // The source images are untouched.
        assert!(d.path().join("rootfs.ext4").exists());
    }

    #[tokio::test]
    async fn missing_jailer_is_an_error_not_a_hang() {
        let d = tempfile::tempdir().unwrap();
        let src = crate::source::TarballSource(Vec::new());
        let exec = FirecrackerExecutor::new(config(d.path()), src, None)
            .await
            .unwrap();
        let req = ExecutionRequest {
            id: uuid::Uuid::new_v4(),
            repo_url: "local".into(),
            commit: rebut_core::CommitSha::new("c".repeat(40)).unwrap(),
            steps: vec![],
            timeout_secs: 1,
            vcpus: 1,
            memory_mib: 256,
            sealed: false,
            env: Default::default(),
        };
        assert!(exec.execute(req.clone()).await.is_err());
        assert!(!d
            .path()
            .join("jail/firecracker")
            .join(req.id.to_string())
            .exists());
    }
}
