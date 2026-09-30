//! Real-VM integration test.
//!
//! Ignored by default. Prerequisites:
//! * bare-metal (or nested-virt) Linux host with `/dev/kvm`, cgroup v2, run
//!   as root (the jailer needs it);
//! * `jailer` and `firecracker` binaries;
//! * an uncompressed guest kernel and an ext4 rootfs built to the contract in
//!   `rebut_fabric::firecracker` (toolchain + `rebut-guest` agent);
//! * environment: `REBUT_FC_JAILER`, `REBUT_FC_FIRECRACKER`,
//!   `REBUT_FC_KERNEL`, `REBUT_FC_ROOTFS`, `REBUT_FC_CHROOT_BASE`,
//!   and `REBUT_FC_UID`/`REBUT_FC_GID` for the unprivileged user.
//!
//! Run with `cargo test -p rebut-fabric --test firecracker_vm -- --ignored`.

use std::collections::BTreeMap;
use std::time::Duration;

use rebut_core::{CommitSha, ExecutionRequest, Executor, Step};
use rebut_fabric::firecracker::jailer::JailerConfig;
use rebut_fabric::firecracker::vmconfig::DEFAULT_BOOT_ARGS;
use rebut_fabric::{FirecrackerConfig, FirecrackerExecutor, TarballSource};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

#[tokio::test]
#[ignore = "needs KVM, root, jailer/firecracker binaries and a guest image"]
async fn runs_a_step_in_a_microvm() {
    let src = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(src.path().join("src")).unwrap();
    std::fs::write(
        src.path().join("Cargo.toml"),
        "[package]\nname = \"fc-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        src.path().join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"fc-fixture\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    std::fs::write(src.path().join("src/lib.rs"), "#[test]\nfn ok() {}\n").unwrap();
    let tgz = rebut_guest::archive::pack_directory(src.path()).unwrap();

    let config = FirecrackerConfig {
        jailer: JailerConfig {
            jailer_bin: env("REBUT_FC_JAILER").into(),
            firecracker_bin: env("REBUT_FC_FIRECRACKER").into(),
            uid: env("REBUT_FC_UID").parse().unwrap(),
            gid: env("REBUT_FC_GID").parse().unwrap(),
            chroot_base: env("REBUT_FC_CHROOT_BASE").into(),
            cgroup_root: "/sys/fs/cgroup/firecracker".into(),
            seccomp_filter: None,
        },
        kernel: env("REBUT_FC_KERNEL").into(),
        rootfs: env("REBUT_FC_ROOTFS").into(),
        boot_args: DEFAULT_BOOT_ARGS.into(),
        scratch_mib: 2048,
        toolchain: "baked".into(),
        boot_grace: Duration::from_secs(30),
    };
    let exec = FirecrackerExecutor::new(config, TarballSource(tgz), None)
        .await
        .unwrap();
    let req = ExecutionRequest {
        id: uuid::Uuid::new_v4(),
        repo_url: "file://fc-fixture".into(),
        commit: CommitSha::new("e".repeat(40)).unwrap(),
        steps: vec![Step::Test { filters: vec![] }],
        timeout_secs: 120,
        vcpus: 2,
        memory_mib: 1024,
        sealed: false,
        env: BTreeMap::new(),
    };
    let res = exec.execute(req).await.unwrap();
    assert!(res.outcomes[0].success(), "{:?}", res.outcomes[0]);
}
