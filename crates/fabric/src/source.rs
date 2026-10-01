//! Where the source tree shipped into the VM comes from.

use std::path::PathBuf;

use verifier_core::ExecutionRequest;

/// Produces the `.tar.gz` of the source tree to run `req` against.
///
/// The production provider (checkout of `req.commit` from `req.repo_url`)
/// lives in the control plane; the fabric only needs the bytes.
#[async_trait::async_trait]
pub trait SourceProvider: Send + Sync {
    async fn fetch(&self, req: &ExecutionRequest) -> anyhow::Result<Vec<u8>>;
}

/// Packs a local directory as-is, ignoring `req.repo_url`/`req.commit`.
/// `target/` and `.git/` at the root are skipped.
#[derive(Debug, Clone)]
pub struct DirectorySource {
    root: PathBuf,
}

impl DirectorySource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DirectorySource { root: root.into() }
    }
}

#[async_trait::async_trait]
impl SourceProvider for DirectorySource {
    async fn fetch(&self, _req: &ExecutionRequest) -> anyhow::Result<Vec<u8>> {
        let root = self.root.clone();
        let tgz =
            tokio::task::spawn_blocking(move || verifier_guest::archive::pack_directory(&root))
                .await??;
        Ok(tgz)
    }
}

/// A fixed, pre-built tarball.
#[derive(Debug, Clone)]
pub struct TarballSource(pub Vec<u8>);

#[async_trait::async_trait]
impl SourceProvider for TarballSource {
    async fn fetch(&self, _req: &ExecutionRequest) -> anyhow::Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}
