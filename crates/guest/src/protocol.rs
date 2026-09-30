//! Host <-> guest wire protocol, spoken over vsock.
//!
//! Every message is one frame: a `u32` big-endian length followed by that many
//! bytes of JSON. Frames larger than [`MAX_FRAME_SIZE`] are rejected on both
//! the read and the write side, so a hostile guest cannot make the host
//! allocate unbounded memory (and vice versa).
//!
//! A session is:
//!
//! ```text
//! host  -> guest   Run { request, source }
//! host  -> guest   SourceChunk { data } *      (tar.gz, split in chunks)
//! host  -> guest   SourceEnd
//! guest -> host    StepDone { outcome } *      (one per executed step)
//! guest -> host    Finished | Error { message }
//! ```

use rebut_core::{Digest, ExecutionRequest, StepOutcome};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest frame accepted or produced. Step outputs are capped at 1 MiB each
/// (see [`crate::runner::OUTPUT_CAP`]), which is at most ~8 MiB once JSON
/// encodes the bytes as a number array.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Raw bytes of source carried per [`HostMessage::SourceChunk`] (base64
/// inflates this by 4/3, well below [`MAX_FRAME_SIZE`]).
pub const SOURCE_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Upper bound on the compressed source tarball.
pub const MAX_SOURCE_SIZE: u64 = 512 * 1024 * 1024;

/// vsock port the guest agent listens on.
pub const GUEST_VSOCK_PORT: u32 = 5005;

/// Describes the tarball that follows a [`HostMessage::Run`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceManifest {
    /// Size in bytes of the gzip-compressed tarball.
    pub size: u64,
    /// SHA-256 of the compressed tarball; the guest verifies it.
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMessage {
    Run {
        request: ExecutionRequest,
        source: SourceManifest,
    },
    SourceChunk {
        #[serde(with = "b64")]
        data: Vec<u8>,
    },
    SourceEnd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuestMessage {
    StepDone { outcome: StepOutcome },
    Finished,
    Error { message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame of {len} bytes exceeds the {max} byte limit")]
    TooLarge { len: usize, max: usize },
    #[error("connection closed in the middle of a frame")]
    Truncated,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed frame: {0}")]
    Json(#[from] serde_json::Error),
}

/// Serializes `msg` and writes it as one frame.
pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge {
            len: body.len(),
            max: MAX_FRAME_SIZE,
        });
    }
    // Checked above: MAX_FRAME_SIZE < u32::MAX.
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

/// Reads one frame. Returns `Ok(None)` on a clean EOF at a frame boundary.
pub async fn read_frame<R, T>(r: &mut R) -> Result<Option<T>, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    read_frame_limited(r, MAX_FRAME_SIZE).await
}

/// [`read_frame`] with an explicit size limit.
pub async fn read_frame_limited<R, T>(r: &mut R, max: usize) -> Result<Option<T>, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    let mut filled = 0;
    while filled < len_buf.len() {
        let n = r.read(&mut len_buf[filled..]).await?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(FrameError::Truncated)
            };
        }
        filled += n;
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        return Err(FrameError::TooLarge { len, max });
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            FrameError::Io(e)
        }
    })?;
    Ok(Some(serde_json::from_slice(&body)?))
}

mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn outcome() -> StepOutcome {
        StepOutcome {
            step_index: 2,
            exit_code: Some(0),
            timed_out: false,
            stdout: b"hi\n".to_vec(),
            stderr: vec![],
            duration_ms: 12,
        }
    }

    #[tokio::test]
    async fn roundtrip_over_duplex() {
        let (mut a, mut b) = duplex(64);
        let msgs = vec![
            GuestMessage::StepDone { outcome: outcome() },
            GuestMessage::Error {
                message: "boom".into(),
            },
            GuestMessage::Finished,
        ];
        let sent = msgs.clone();
        let writer = tokio::spawn(async move {
            for m in &sent {
                write_frame(&mut a, m).await.unwrap();
            }
        });
        for m in &msgs {
            let got: GuestMessage = read_frame(&mut b).await.unwrap().unwrap();
            assert_eq!(&got, m);
        }
        writer.await.unwrap();
        // Writer dropped: clean EOF.
        assert!(read_frame::<_, GuestMessage>(&mut b)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn source_chunks_are_base64() {
        let msg = HostMessage::SourceChunk {
            data: vec![0, 1, 2, 255],
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"type":"source_chunk","data":"AAEC/w=="}"#);
        let (mut a, mut b) = duplex(1024);
        write_frame(&mut a, &msg).await.unwrap();
        let got: HostMessage = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn oversize_frame_is_rejected_before_allocation() {
        let (mut a, mut b) = duplex(64);
        // Announce a 4 GiB frame; only the header is ever sent.
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        match read_frame::<_, GuestMessage>(&mut b).await {
            Err(FrameError::TooLarge { len, max }) => {
                assert_eq!(len, u32::MAX as usize);
                assert_eq!(max, MAX_FRAME_SIZE);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn custom_limit_applies() {
        let (mut a, mut b) = duplex(1024);
        write_frame(
            &mut a,
            &GuestMessage::Error {
                message: "x".repeat(100),
            },
        )
        .await
        .unwrap();
        let err = read_frame_limited::<_, GuestMessage>(&mut b, 50)
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::TooLarge { max: 50, .. }));
    }

    #[tokio::test]
    async fn oversize_frame_is_not_written() {
        let (mut a, _b) = duplex(64);
        let big = GuestMessage::Error {
            message: "x".repeat(MAX_FRAME_SIZE),
        };
        assert!(matches!(
            write_frame(&mut a, &big).await,
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn truncated_frame_is_an_error() {
        let (mut a, mut b) = duplex(64);
        a.write_all(&10u32.to_be_bytes()).await.unwrap();
        a.write_all(b"{\"ty").await.unwrap();
        drop(a);
        assert!(matches!(
            read_frame::<_, GuestMessage>(&mut b).await,
            Err(FrameError::Truncated)
        ));

        let (mut a, mut b) = duplex(64);
        a.write_all(&[0, 0]).await.unwrap();
        drop(a);
        assert!(matches!(
            read_frame::<_, GuestMessage>(&mut b).await,
            Err(FrameError::Truncated)
        ));
    }

    #[tokio::test]
    async fn garbage_json_is_an_error() {
        let (mut a, mut b) = duplex(64);
        a.write_all(&3u32.to_be_bytes()).await.unwrap();
        a.write_all(b"nop").await.unwrap();
        assert!(matches!(
            read_frame::<_, GuestMessage>(&mut b).await,
            Err(FrameError::Json(_))
        ));
    }
}
