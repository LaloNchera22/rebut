//! Pure construction of the `jailer` command line and jail layout.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::vmconfig::jail_paths;

/// Memory the Firecracker process may use beyond guest RAM (VMM, device
/// emulation, page tables).
pub const VMM_MEMORY_OVERHEAD_MIB: u64 = 128;

/// CFS period used to express the vCPU quota in `cpu.max`.
const CPU_PERIOD_US: u64 = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JailerConfig {
    pub jailer_bin: PathBuf,
    pub firecracker_bin: PathBuf,
    /// Unprivileged uid/gid Firecracker drops to.
    pub uid: u32,
    pub gid: u32,
    /// `--chroot-base-dir`; jails live in `<base>/<exec name>/<id>/root`.
    pub chroot_base: PathBuf,
    /// cgroup v2 hierarchy the jailer creates `<id>` under
    /// (`/sys/fs/cgroup/firecracker` by default); used to kill the VM.
    pub cgroup_root: PathBuf,
    /// Custom seccomp filter for Firecracker. `None` keeps Firecracker's
    /// built-in default filter; seccomp is never disabled.
    pub seccomp_filter: Option<PathBuf>,
}

impl JailerConfig {
    fn exec_name(&self) -> OsString {
        self.firecracker_bin
            .file_name()
            .map(OsString::from)
            .unwrap_or_else(|| "firecracker".into())
    }

    /// Host path of the chroot root for VM `id`.
    pub fn jail_root(&self, id: &str) -> PathBuf {
        self.chroot_base
            .join(self.exec_name())
            .join(id)
            .join("root")
    }

    /// Host path of a file given by its in-jail absolute path.
    pub fn host_path(&self, id: &str, in_jail: &str) -> PathBuf {
        self.jail_root(id).join(in_jail.trim_start_matches('/'))
    }

    /// Where the jailer writes Firecracker's pid (with `--new-pid-ns` the
    /// jailer itself exits and this is the only handle on the VMM).
    pub fn pid_file(&self, id: &str) -> PathBuf {
        let mut name = self.exec_name();
        name.push(".pid");
        self.jail_root(id).join(name)
    }

    /// `cgroup.kill` of the VM's cgroup (cgroup v2).
    pub fn cgroup_kill_file(&self, id: &str) -> PathBuf {
        self.cgroup_root.join(id).join("cgroup.kill")
    }
}

/// VM ids become paths and cgroup names: `[A-Za-z0-9-]{1,64}` only.
pub fn validate_id(id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !id.is_empty()
            && id.len() <= 64
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid VM id {id:?}"
    );
    Ok(())
}

/// Arguments for `jailer`. Firecracker is started in a new PID namespace,
/// not daemonized (we keep a handle and kill it at the deadline), and gets
/// the VM config file unless it will be restored from a snapshot.
pub fn jailer_args(
    cfg: &JailerConfig,
    id: &str,
    vcpus: u8,
    memory_mib: u32,
    cold_boot: bool,
) -> anyhow::Result<Vec<OsString>> {
    validate_id(id)?;
    let cpu_quota = u64::from(vcpus) * CPU_PERIOD_US;
    let mem_bytes = (u64::from(memory_mib) + VMM_MEMORY_OVERHEAD_MIB) * 1024 * 1024;
    let mut args: Vec<OsString> = Vec::new();
    let mut push = |a: &dyn AsRef<std::ffi::OsStr>| args.push(a.as_ref().to_os_string());
    push(&"--id");
    push(&id);
    push(&"--exec-file");
    push(&cfg.firecracker_bin);
    push(&"--uid");
    push(&cfg.uid.to_string());
    push(&"--gid");
    push(&cfg.gid.to_string());
    push(&"--chroot-base-dir");
    push(&cfg.chroot_base);
    push(&"--cgroup-version");
    push(&"2");
    push(&"--cgroup");
    push(&format!("cpu.max={cpu_quota} {CPU_PERIOD_US}"));
    push(&"--cgroup");
    push(&format!("memory.max={mem_bytes}"));
    push(&"--cgroup");
    push(&"memory.swap.max=0");
    push(&"--resource-limit");
    push(&"no-file=1024");
    push(&"--new-pid-ns");
    // Everything after `--` goes to Firecracker.
    push(&"--");
    push(&"--api-sock");
    push(&jail_paths::API_SOCK);
    if cold_boot {
        push(&"--config-file");
        push(&jail_paths::CONFIG);
    }
    if let Some(filter) = &cfg.seccomp_filter {
        push(&"--seccomp-filter");
        push(&Path::new(filter));
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> JailerConfig {
        JailerConfig {
            jailer_bin: "/usr/bin/jailer".into(),
            firecracker_bin: "/usr/bin/firecracker".into(),
            uid: 10_000,
            gid: 10_000,
            chroot_base: "/srv/jail".into(),
            cgroup_root: "/sys/fs/cgroup/firecracker".into(),
            seccomp_filter: None,
        }
    }

    fn strs(v: &[OsString]) -> Vec<String> {
        v.iter().map(|s| s.to_string_lossy().into_owned()).collect()
    }

    fn value_after<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
        args.windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].as_str())
            .collect()
    }

    #[test]
    fn jailer_args_limits_and_isolation() {
        let id = "0b0f6a7e-5f2b-4c1f-9a53-1c2d3e4f5a6b";
        let a = strs(&jailer_args(&cfg(), id, 2, 1024, true).unwrap());
        assert_eq!(value_after(&a, "--id"), [id]);
        assert_eq!(value_after(&a, "--uid"), ["10000"]);
        assert_eq!(value_after(&a, "--chroot-base-dir"), ["/srv/jail"]);
        assert_eq!(value_after(&a, "--cgroup-version"), ["2"]);
        let cg = value_after(&a, "--cgroup");
        assert!(cg.contains(&"cpu.max=200000 100000"));
        assert!(cg.contains(&format!("memory.max={}", (1024 + 128) * 1024 * 1024).as_str()));
        assert!(a.contains(&"--new-pid-ns".to_string()));
        assert!(!a.contains(&"--daemonize".to_string()));
        assert!(!a.iter().any(|s| s.contains("no-seccomp")));
        assert_eq!(value_after(&a, "--config-file"), [jail_paths::CONFIG]);
        // Firecracker args come after the separator.
        let sep = a.iter().position(|s| s == "--").unwrap();
        let api = a.iter().position(|s| s == "--api-sock").unwrap();
        assert!(api > sep);
    }

    #[test]
    fn snapshot_restore_has_no_config_file_and_custom_seccomp() {
        let mut c = cfg();
        c.seccomp_filter = Some("/etc/verifier/fc.bpf".into());
        let a = strs(&jailer_args(&c, "vm-1", 1, 256, false).unwrap());
        assert!(!a.contains(&"--config-file".to_string()));
        assert_eq!(
            value_after(&a, "--seccomp-filter"),
            ["/etc/verifier/fc.bpf"]
        );
    }

    #[test]
    fn ids_are_validated() {
        assert!(jailer_args(&cfg(), "../escape", 1, 256, true).is_err());
        assert!(jailer_args(&cfg(), "", 1, 256, true).is_err());
        assert!(jailer_args(&cfg(), &"a".repeat(65), 1, 256, true).is_err());
    }

    #[test]
    fn jail_layout() {
        let c = cfg();
        assert_eq!(
            c.jail_root("vm-1"),
            Path::new("/srv/jail/firecracker/vm-1/root")
        );
        assert_eq!(
            c.host_path("vm-1", jail_paths::VSOCK_UDS),
            Path::new("/srv/jail/firecracker/vm-1/root/v.sock")
        );
        assert_eq!(
            c.pid_file("vm-1"),
            Path::new("/srv/jail/firecracker/vm-1/root/firecracker.pid")
        );
        assert_eq!(
            c.cgroup_kill_file("vm-1"),
            Path::new("/sys/fs/cgroup/firecracker/vm-1/cgroup.kill")
        );
    }
}
