//! Sealed step output must never reach a log line.
//!
//! This is its own test binary on purpose: `tracing` caches each callsite's
//! interest process-wide, so a test running in parallel with no subscriber
//! could cache the TRACE callsite as disabled and make the unsealed control
//! run below miss its log line. Here one global subscriber captures
//! everything and no other test shares the process.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use rebut_core::{CommitSha, ExecutionRequest, Executor, Step};
use rebut_fabric::{DirectorySource, LocalProcessExecutor};

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl LogBuf {
    fn take(&self) -> String {
        String::from_utf8(std::mem::take(&mut *self.0.lock().unwrap())).unwrap()
    }
}

impl Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn fixture(dir: &Path) {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"tiny-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(dir.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    let status = Command::new("cargo")
        .args(["generate-lockfile", "--offline"])
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(status.success());
}

/// Runs a harness that leaks a secret on stdout and stderr and fails.
/// Returns its stdout.
async fn run_leaky(src: &Path, sealed: bool) -> Vec<u8> {
    let exec = LocalProcessExecutor::insecure_for_development(DirectorySource::new(src));
    let leak = r#"fn main() {
    println!("SECRET-STDOUT-7f3a");
    eprintln!("SECRET-STDERR-7f3a");
    std::process::exit(3);
}
"#;
    let res = exec
        .execute(ExecutionRequest {
            id: uuid::Uuid::new_v4(),
            repo_url: "file://fixture".into(),
            commit: CommitSha::new("d".repeat(40)).unwrap(),
            steps: vec![Step::Harness {
                name: "leak".into(),
                source: leak.into(),
                input: vec![],
            }],
            timeout_secs: 300,
            vcpus: 1,
            memory_mib: 512,
            sealed,
            env: BTreeMap::new(),
        })
        .await
        .unwrap();
    assert_eq!(res.outcomes[0].exit_code, Some(3));
    res.outcomes[0].stdout.clone()
}

#[tokio::test]
async fn sealed_outputs_never_reach_logs() {
    let logs = LogBuf::default();
    let sink = logs.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || sink.clone())
            .with_ansi(false)
            .finish(),
    )
    .unwrap();
    let src = tempfile::tempdir().unwrap();
    fixture(src.path());

    let stdout = run_leaky(src.path(), true).await;
    // The caller (control plane) still gets the output...
    assert!(String::from_utf8_lossy(&stdout).contains("SECRET-STDOUT-7f3a"));
    // ...but no log line carries it.
    let sealed = logs.take();
    assert!(sealed.contains("sealed step finished"), "{sealed}");
    assert!(sealed.contains("UNSANDBOXED"), "{sealed}");
    assert!(!sealed.contains("SECRET"), "{sealed}");
    assert!(!sealed.contains("exit_code"), "{sealed}");

    // Control: the same failing run, unsealed, does log its stderr tail at
    // TRACE level, so the assertions above are meaningful.
    run_leaky(src.path(), false).await;
    let unsealed = logs.take();
    assert!(unsealed.contains("SECRET-STDERR-7f3a"), "{unsealed}");
}
