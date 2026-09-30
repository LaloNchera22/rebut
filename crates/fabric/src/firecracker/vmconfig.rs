//! Pure generation of the Firecracker VM configuration.
//!
//! The configuration types deliberately have **no field for network
//! interfaces**: a VM built by this crate cannot have a network, by
//! construction rather than by a runtime check.

use serde::Serialize;
use serde_json::json;

/// Paths as seen by Firecracker inside the jailer chroot.
pub mod jail_paths {
    pub const KERNEL: &str = "/vmlinux";
    pub const ROOTFS: &str = "/rootfs.ext4";
    pub const SCRATCH: &str = "/scratch.img";
    pub const CARGO_CACHE: &str = "/cargo-cache.ext4";
    pub const VSOCK_UDS: &str = "/v.sock";
    pub const API_SOCK: &str = "/api.sock";
    pub const CONFIG: &str = "/vm.json";
    pub const SNAPSHOT_STATE: &str = "/snapshot.vmstate";
    pub const SNAPSHOT_MEM: &str = "/snapshot.mem";
}

/// Guest CID; every VM lives in its own jail, so a constant is fine.
pub const GUEST_CID: u32 = 3;

/// Kernel command line: serial console off (its output would otherwise reach
/// host logs), panic reboots, which Firecracker turns into an exit.
pub const DEFAULT_BOOT_ARGS: &str = "reboot=k panic=1 pci=off quiet 8250.nr_uarts=0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmSpec {
    pub vcpus: u8,
    pub memory_mib: u32,
    pub boot_args: String,
    /// Attach the read-only warm cargo cache drive.
    pub cargo_cache: bool,
}

/// Firecracker `--config-file` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VmConfig {
    #[serde(rename = "boot-source")]
    pub boot_source: BootSource,
    pub drives: Vec<Drive>,
    #[serde(rename = "machine-config")]
    pub machine_config: MachineConfig,
    pub vsock: Vsock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootSource {
    pub kernel_image_path: String,
    pub boot_args: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachineConfig {
    pub vcpu_count: u8,
    pub mem_size_mib: u32,
    pub smt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Vsock {
    pub guest_cid: u32,
    pub uds_path: String,
}

/// Builds the VM configuration: read-only rootfs, writable ephemeral scratch
/// drive, optional read-only cargo cache, vsock, and nothing else.
pub fn vm_config(spec: &VmSpec) -> anyhow::Result<VmConfig> {
    anyhow::ensure!(
        (1..=32).contains(&spec.vcpus),
        "vcpus must be in 1..=32, got {}",
        spec.vcpus
    );
    anyhow::ensure!(
        spec.memory_mib >= 128,
        "memory_mib must be at least 128, got {}",
        spec.memory_mib
    );
    let drive = |id: &str, path: &str, root: bool, ro: bool| Drive {
        drive_id: id.into(),
        path_on_host: path.into(),
        is_root_device: root,
        is_read_only: ro,
    };
    let mut drives = vec![
        drive("rootfs", jail_paths::ROOTFS, true, true),
        drive("scratch", jail_paths::SCRATCH, false, false),
    ];
    if spec.cargo_cache {
        drives.push(drive("cargo-cache", jail_paths::CARGO_CACHE, false, true));
    }
    Ok(VmConfig {
        boot_source: BootSource {
            kernel_image_path: jail_paths::KERNEL.into(),
            boot_args: spec.boot_args.clone(),
        },
        drives,
        machine_config: MachineConfig {
            vcpu_count: spec.vcpus,
            mem_size_mib: spec.memory_mib,
            smt: false,
        },
        vsock: Vsock {
            guest_cid: GUEST_CID,
            uds_path: jail_paths::VSOCK_UDS.into(),
        },
    })
}

/// Body of `PUT /snapshot/load`: restore from the staged snapshot and resume.
pub fn snapshot_load_body() -> serde_json::Value {
    json!({
        "snapshot_path": jail_paths::SNAPSHOT_STATE,
        "mem_backend": {
            "backend_type": "File",
            "backend_path": jail_paths::SNAPSHOT_MEM,
        },
        "enable_diff_snapshots": false,
        "resume_vm": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(cache: bool) -> VmSpec {
        VmSpec {
            vcpus: 2,
            memory_mib: 2048,
            boot_args: DEFAULT_BOOT_ARGS.into(),
            cargo_cache: cache,
        }
    }

    #[test]
    fn never_emits_network_interfaces() {
        for cache in [false, true] {
            let v = serde_json::to_value(vm_config(&spec(cache)).unwrap()).unwrap();
            let obj = v.as_object().unwrap();
            assert!(!obj.contains_key("network-interfaces"));
            assert!(!v.to_string().contains("network"));
            assert!(!v.to_string().contains("iface"));
            let mut keys: Vec<_> = obj.keys().cloned().collect();
            keys.sort();
            assert_eq!(keys, ["boot-source", "drives", "machine-config", "vsock"]);
        }
    }

    #[test]
    fn rootfs_and_cache_are_read_only_scratch_is_not() {
        let cfg = vm_config(&spec(true)).unwrap();
        let roots: Vec<_> = cfg.drives.iter().filter(|d| d.is_root_device).collect();
        assert_eq!(roots.len(), 1);
        assert!(roots[0].is_read_only);
        assert_eq!(roots[0].path_on_host, jail_paths::ROOTFS);
        for d in &cfg.drives {
            let ro = d.drive_id != "scratch";
            assert_eq!(d.is_read_only, ro, "{}", d.drive_id);
        }
    }

    #[test]
    fn machine_config_and_json_shape() {
        let v = serde_json::to_value(vm_config(&spec(false)).unwrap()).unwrap();
        assert_eq!(v["machine-config"]["vcpu_count"], 2);
        assert_eq!(v["machine-config"]["mem_size_mib"], 2048);
        assert_eq!(v["machine-config"]["smt"], false);
        assert_eq!(v["boot-source"]["kernel_image_path"], "/vmlinux");
        assert_eq!(v["vsock"]["guest_cid"], GUEST_CID);
        assert_eq!(v["drives"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn rejects_bad_sizes() {
        let mut s = spec(false);
        s.vcpus = 0;
        assert!(vm_config(&s).is_err());
        s.vcpus = 33;
        assert!(vm_config(&s).is_err());
        s.vcpus = 1;
        s.memory_mib = 64;
        assert!(vm_config(&s).is_err());
    }

    #[test]
    fn snapshot_load_resumes_from_jailed_files() {
        let b = snapshot_load_body();
        assert_eq!(b["snapshot_path"], jail_paths::SNAPSHOT_STATE);
        assert_eq!(b["mem_backend"]["backend_path"], jail_paths::SNAPSHOT_MEM);
        assert_eq!(b["resume_vm"], true);
    }
}
