//! Guest side of one protocol session: receive request and source, unpack,
//! run steps, stream outcomes back.

use std::path::Path;

use rebut_core::{Digest, ExecutionRequest};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::archive::unpack_tarball;
use crate::protocol::{
    read_frame, write_frame, FrameError, GuestMessage, HostMessage, MAX_SOURCE_SIZE,
};
use crate::runner::Runner;

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("{0}")]
    Setup(String),
}

/// Serves one session. On failure the guest reports `Error { message }` to
/// the host (best effort) before returning the error.
pub async fn serve_connection<R, W>(
    mut reader: R,
    mut writer: W,
    work_root: &Path,
) -> Result<(), ServeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let result = serve_inner(&mut reader, &mut writer, work_root).await;
    if let Err(e) = &result {
        if !matches!(e, ServeError::Frame(FrameError::Io(_))) {
            let msg = GuestMessage::Error {
                message: e.to_string(),
            };
            let _ = write_frame(&mut writer, &msg).await;
        }
    }
    result
}

async fn serve_inner<R, W>(
    reader: &mut R,
    writer: &mut W,
    work_root: &Path,
) -> Result<(), ServeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (request, source) = receive(reader).await?;
    tracing::info!(request = %request.id, steps = request.steps.len(), "request received");

    let workdir = tempfile::Builder::new()
        .prefix("src-")
        .tempdir_in(work_root)
        .map_err(|e| ServeError::Setup(format!("creating workdir: {e}")))?;
    let dest = workdir.path().to_path_buf();
    tokio::task::spawn_blocking(move || unpack_tarball(&source, &dest))
        .await
        .map_err(|e| ServeError::Setup(format!("unpack task: {e}")))?
        .map_err(|e| ServeError::Setup(format!("unpacking source: {e}")))?;

    let runner = Runner::new(&request, workdir.path());
    for i in 0..request.steps.len() {
        let outcome = runner.run_step(i).await;
        // Never log output: the request may be sealed.
        tracing::info!(step = i, success = outcome.success(), "step done");
        write_frame(writer, &GuestMessage::StepDone { outcome }).await?;
    }
    write_frame(writer, &GuestMessage::Finished).await?;
    Ok(())
}

async fn receive<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(ExecutionRequest, Vec<u8>), ServeError> {
    let eof = || ServeError::Protocol("connection closed early".into());
    let (request, manifest) = match read_frame(reader).await?.ok_or_else(eof)? {
        HostMessage::Run { request, source } => (request, source),
        other => return Err(ServeError::Protocol(format!("expected run, got {other:?}"))),
    };
    if manifest.size > MAX_SOURCE_SIZE {
        return Err(ServeError::Protocol(format!(
            "source of {} bytes exceeds limit",
            manifest.size
        )));
    }
    let mut source = Vec::with_capacity(manifest.size as usize);
    loop {
        match read_frame(reader).await?.ok_or_else(eof)? {
            HostMessage::SourceChunk { data } => {
                if (source.len() + data.len()) as u64 > manifest.size {
                    return Err(ServeError::Protocol("source larger than announced".into()));
                }
                source.extend_from_slice(&data);
            }
            HostMessage::SourceEnd => break,
            HostMessage::Run { .. } => {
                return Err(ServeError::Protocol("unexpected second run".into()))
            }
        }
    }
    if source.len() as u64 != manifest.size || Digest::of(&source) != manifest.digest {
        return Err(ServeError::Protocol("source digest mismatch".into()));
    }
    Ok((request, source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SourceManifest;
    use rebut_core::{CommitSha, Step};
    use std::collections::BTreeMap;
    use tokio::io::duplex;

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            id: uuid::Uuid::nil(),
            repo_url: "local".into(),
            commit: CommitSha::new("a".repeat(40)).unwrap(),
            steps: vec![Step::Test { filters: vec![] }],
            timeout_secs: 10,
            vcpus: 1,
            memory_mib: 256,
            sealed: false,
            env: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn digest_mismatch_is_reported_to_host() {
        let root = tempfile::tempdir().unwrap();
        let (host, guest) = duplex(1 << 16);
        let (gr, gw) = tokio::io::split(guest);
        let server = tokio::spawn({
            let root = root.path().to_path_buf();
            async move { serve_connection(gr, gw, &root).await }
        });
        let (mut hr, mut hw) = tokio::io::split(host);
        let run = HostMessage::Run {
            request: request(),
            source: SourceManifest {
                size: 3,
                digest: Digest::of(b"abc"),
            },
        };
        write_frame(&mut hw, &run).await.unwrap();
        write_frame(
            &mut hw,
            &HostMessage::SourceChunk {
                data: b"xyz".to_vec(),
            },
        )
        .await
        .unwrap();
        write_frame(&mut hw, &HostMessage::SourceEnd).await.unwrap();
        let reply: GuestMessage = read_frame(&mut hr).await.unwrap().unwrap();
        assert!(
            matches!(&reply, GuestMessage::Error { message } if message.contains("digest")),
            "{reply:?}"
        );
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn oversized_announcement_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let (host, guest) = duplex(1 << 16);
        let (gr, gw) = tokio::io::split(guest);
        let (mut hr, mut hw) = tokio::io::split(host);
        let run = HostMessage::Run {
            request: request(),
            source: SourceManifest {
                size: MAX_SOURCE_SIZE + 1,
                digest: Digest::of(b""),
            },
        };
        write_frame(&mut hw, &run).await.unwrap();
        assert!(serve_connection(gr, gw, root.path()).await.is_err());
        let reply: GuestMessage = read_frame(&mut hr).await.unwrap().unwrap();
        assert!(matches!(reply, GuestMessage::Error { .. }));
    }
}
