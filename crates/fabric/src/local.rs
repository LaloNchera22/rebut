//! **INSECURE** development executor: runs PR code directly on the host.

use std::sync::Arc;
use std::time::Duration;

use verifier_core::{Digest, ExecutionRequest, ExecutionResult, Executor};

use crate::session::{fill_timed_out, run_session};
use crate::source::SourceProvider;

/// Extra time on top of `timeout_secs` before the session is abandoned; the
/// guest runner enforces the per-step budget itself.
const HARD_DEADLINE_GRACE: Duration = Duration::from_secs(10);

/// Environment digest reported by this executor. Distinct from any VM
/// environment so receipts can never pass a local run off as isolated.
pub fn local_environment_digest() -> Digest {
    Digest::of(b"verifier/environment/local-insecure/v1")
}

/// Runs the guest agent in-process, with cargo executing on the host in a
/// temporary directory. **There is no isolation whatsoever**: `build.rs`,
/// proc-macros and tests of the code under test run with your privileges and
/// your network access.
///
/// Only for running the verifier on your own code (the CLI's local mode) and
/// for tests. Never use it on untrusted pull requests; production uses
/// [`crate::FirecrackerExecutor`].
///
/// It goes through the same protocol path as the VM executor (framed
/// messages over an in-memory duplex pipe, tarball unpacking, the guest
/// [`verifier_guest::Runner`]), so it exercises the real guest logic.
pub struct LocalProcessExecutor {
    source: Arc<dyn SourceProvider>,
}

impl LocalProcessExecutor {
    /// The only constructor, named so that no call site can look innocent.
    pub fn insecure_for_development(source: impl SourceProvider + 'static) -> Self {
        tracing::warn!(
            "LocalProcessExecutor created: untrusted code will run UNSANDBOXED on this host; \
             development use only"
        );
        LocalProcessExecutor {
            source: Arc::new(source),
        }
    }
}

#[async_trait::async_trait]
impl Executor for LocalProcessExecutor {
    async fn execute(&self, req: ExecutionRequest) -> anyhow::Result<ExecutionResult> {
        tracing::warn!(request = %req.id, "executing WITHOUT a sandbox (LocalProcessExecutor)");
        let tgz = self.source.fetch(&req).await?;
        let work_root = tempfile::Builder::new()
            .prefix("verifier-local-")
            .tempdir()?;

        let (host, guest) = tokio::io::duplex(1 << 20);
        let guest_root = work_root.path().to_path_buf();
        let guest_task = tokio::spawn(async move {
            let (r, w) = tokio::io::split(guest);
            verifier_guest::serve_connection(r, w, &guest_root).await
        });

        let mut outcomes = Vec::with_capacity(req.steps.len());
        let deadline = Duration::from_secs(req.timeout_secs) + HARD_DEADLINE_GRACE;
        let session = tokio::time::timeout(deadline, run_session(host, &req, &tgz, &mut outcomes));
        match session.await {
            Ok(res) => res?,
            Err(_) => {
                guest_task.abort();
                fill_timed_out(&req, &mut outcomes);
            }
        }
        drop(work_root);

        Ok(ExecutionResult {
            request_id: req.id,
            transcript: ExecutionResult::compute_transcript(&req, &outcomes),
            environment: local_environment_digest(),
            outcomes,
        })
    }
}
