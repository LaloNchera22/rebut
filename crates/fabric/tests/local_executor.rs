//! End-to-end tests of the insecure local executor on a tiny zero-dependency
//! cargo project (cargo works offline here only for crates without deps).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use verifier_core::{CommitSha, ExecutionRequest, Executor, Step};
use verifier_fabric::{DirectorySource, LocalProcessExecutor};

fn fixture(dir: &Path) {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"tiny-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("src/lib.rs"),
        r#"pub fn shout(s: &str) -> String {
    s.trim().to_uppercase()
}

#[cfg(test)]
mod tests {
    #[test]
    fn shouts() {
        assert_eq!(super::shout(" hi \n"), "HI");
    }
}
"#,
    )
    .unwrap();
    let status = Command::new("cargo")
        .args(["generate-lockfile", "--offline"])
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(status.success());
}

fn request(steps: Vec<Step>, sealed: bool) -> ExecutionRequest {
    ExecutionRequest {
        id: uuid::Uuid::new_v4(),
        repo_url: "file://fixture".into(),
        commit: CommitSha::new("d".repeat(40)).unwrap(),
        steps,
        timeout_secs: 300,
        vcpus: 1,
        memory_mib: 512,
        sealed,
        env: BTreeMap::new(),
    }
}

const HARNESS: &str = r#"use std::io::Read;
fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    println!("{}", tiny_fixture::shout(&s));
}
"#;

#[tokio::test(flavor = "multi_thread")]
async fn build_test_and_harness_succeed() {
    let src = tempfile::tempdir().unwrap();
    fixture(src.path());
    let exec = LocalProcessExecutor::insecure_for_development(DirectorySource::new(src.path()));
    let req = request(
        vec![
            Step::Build {
                profile: "dev".into(),
            },
            Step::Test {
                filters: vec!["shouts".into()],
            },
            Step::Harness {
                name: "shout".into(),
                source: HARNESS.into(),
                input: b"hello verifier\n".to_vec(),
            },
        ],
        false,
    );
    let res = exec.execute(req.clone()).await.unwrap();
    assert_eq!(res.request_id, req.id);
    assert_eq!(res.outcomes.len(), 3);
    for o in &res.outcomes {
        assert!(
            o.success(),
            "step {} failed: {}",
            o.step_index,
            String::from_utf8_lossy(&o.stderr)
        );
    }
    let test_out = String::from_utf8_lossy(&res.outcomes[1].stdout);
    assert!(test_out.contains("test tests::shouts ... ok"), "{test_out}");
    assert_eq!(res.outcomes[2].stdout, b"HELLO VERIFIER\n");
    assert_eq!(
        res.transcript,
        verifier_core::ExecutionResult::compute_transcript(&req, &res.outcomes)
    );
    assert_eq!(
        res.environment,
        verifier_fabric::local::local_environment_digest()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failing_build_is_reported_not_an_error() {
    let src = tempfile::tempdir().unwrap();
    fixture(src.path());
    std::fs::write(src.path().join("src/lib.rs"), "pub fn broken( {").unwrap();
    let exec = LocalProcessExecutor::insecure_for_development(DirectorySource::new(src.path()));
    let res = exec
        .execute(request(
            vec![Step::Build {
                profile: "dev".into(),
            }],
            false,
        ))
        .await
        .unwrap();
    assert_eq!(res.outcomes[0].exit_code, Some(101));
    assert!(String::from_utf8_lossy(&res.outcomes[0].stderr).contains("error"));
}

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs a harness that leaks a secret on stdout and stderr and fails, with
/// all tracing captured at TRACE level. Returns (captured logs, stdout).
async fn run_leaky(sealed: bool) -> (String, Vec<u8>) {
    let src = tempfile::tempdir().unwrap();
    fixture(src.path());
    let logs = LogBuf::default();
    let sink = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || sink.clone())
        .with_ansi(false)
        .finish();
    // Current-thread runtime: the thread-local default covers every task.
    let _guard = tracing::subscriber::set_default(subscriber);
    let exec = LocalProcessExecutor::insecure_for_development(DirectorySource::new(src.path()));
    let leak = r#"fn main() {
    println!("SECRET-STDOUT-7f3a");
    eprintln!("SECRET-STDERR-7f3a");
    std::process::exit(3);
}
"#;
    let res = exec
        .execute(request(
            vec![Step::Harness {
                name: "leak".into(),
                source: leak.into(),
                input: vec![],
            }],
            sealed,
        ))
        .await
        .unwrap();
    assert_eq!(res.outcomes[0].exit_code, Some(3));
    let captured = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    (captured, res.outcomes[0].stdout.clone())
}

#[tokio::test]
async fn sealed_outputs_never_reach_logs() {
    let (logs, stdout) = run_leaky(true).await;
    // The caller (control plane) still gets the output...
    assert!(String::from_utf8_lossy(&stdout).contains("SECRET-STDOUT-7f3a"));
    // ...but no log line carries it.
    assert!(logs.contains("sealed step finished"), "{logs}");
    assert!(logs.contains("UNSANDBOXED"), "{logs}");
    assert!(!logs.contains("SECRET"), "{logs}");
    assert!(!logs.contains("exit_code"), "{logs}");

    // Control: the same failing run, unsealed, does log its stderr tail at
    // TRACE level, so the assertion above is meaningful.
    let (logs, _) = run_leaky(false).await;
    assert!(logs.contains("SECRET-STDERR-7f3a"), "{logs}");
}
