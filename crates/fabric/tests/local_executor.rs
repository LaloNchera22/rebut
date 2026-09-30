//! End-to-end tests of the insecure local executor on a tiny zero-dependency
//! cargo project (cargo works offline here only for crates without deps).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

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
