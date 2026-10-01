//! Smoke test of the `rebut-guest` binary in `--stdio` mode.

use std::collections::BTreeMap;
use std::process::Stdio;

use rebut_core::{CommitSha, Digest, ExecutionRequest, Step};
use rebut_guest::protocol::{read_frame, write_frame, GuestMessage, HostMessage, SourceManifest};

#[tokio::test]
async fn serves_a_session_over_stdio() {
    let work = tempfile::tempdir().unwrap();
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("README"), "hi").unwrap();
    let tgz = rebut_guest::archive::pack_directory(src.path()).unwrap();

    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_rebut-guest"))
        .arg("--stdio")
        .arg("--work-root")
        .arg(work.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    let request = ExecutionRequest {
        id: uuid::Uuid::new_v4(),
        repo_url: "local".into(),
        commit: CommitSha::new("f".repeat(40)).unwrap(),
        // Rejected before cargo runs: exercises the full path cheaply.
        steps: vec![Step::Build {
            profile: "../evil".into(),
        }],
        timeout_secs: 30,
        vcpus: 1,
        memory_mib: 256,
        sealed: false,
        env: BTreeMap::new(),
    };
    let run = HostMessage::Run {
        request,
        source: SourceManifest {
            size: tgz.len() as u64,
            digest: Digest::of(&tgz),
        },
    };
    write_frame(&mut stdin, &run).await.unwrap();
    write_frame(&mut stdin, &HostMessage::SourceChunk { data: tgz })
        .await
        .unwrap();
    write_frame(&mut stdin, &HostMessage::SourceEnd)
        .await
        .unwrap();

    let first: GuestMessage = read_frame(&mut stdout).await.unwrap().unwrap();
    match first {
        GuestMessage::StepDone { outcome } => {
            assert_eq!(outcome.step_index, 0);
            assert!(!outcome.success());
            assert!(String::from_utf8_lossy(&outcome.stderr).contains("invalid profile"));
        }
        other => panic!("unexpected {other:?}"),
    }
    let done: GuestMessage = read_frame(&mut stdout).await.unwrap().unwrap();
    assert_eq!(done, GuestMessage::Finished);
    drop(stdin);
    assert!(child.wait().await.unwrap().success());
}
