//! Minimal clients for the two unix sockets Firecracker exposes: its HTTP
//! API (only the handful of requests we need, HTTP/1.1 with Content-Length)
//! and the host end of the vsock device (`CONNECT <port>` handshake).

use std::path::Path;

use anyhow::{bail, Context as _};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Sends one JSON request to the Firecracker API and fails on a non-2xx
/// status (the error includes Firecracker's `fault_message`).
pub async fn api_request(
    socket: &Path,
    method: &str,
    path: &str,
    body: &serde_json::Value,
) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to {}", socket.display()))?;
    let body = serde_json::to_vec(body)?;
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;

    let (status, resp_body) = read_response(&mut stream).await?;
    if !(200..300).contains(&status) {
        bail!(
            "firecracker API {method} {path} returned {status}: {}",
            String::from_utf8_lossy(&resp_body)
        );
    }
    Ok(())
}

/// Reads a response: status line, headers, then exactly `Content-Length`
/// bytes (Firecracker keeps connections alive, so EOF can't delimit it).
async fn read_response<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<(u16, Vec<u8>)> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEADER_BYTES {
            bail!("response headers too large");
        }
        if r.read(&mut byte).await? == 0 {
            bail!("connection closed inside response headers");
        }
        head.push(byte[0]);
    }
    let head = std::str::from_utf8(&head).context("non-UTF-8 response headers")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let (Some(version), Some(code)) = (parts.next(), parts.next()) else {
        bail!("malformed status line {status_line:?}");
    };
    if !version.starts_with("HTTP/1.") {
        bail!("unexpected protocol {version:?}");
    }
    let status: u16 = code.parse().context("malformed status code")?;
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().context("bad Content-Length")?;
            }
        }
    }
    if content_length > MAX_BODY_BYTES {
        bail!("response body too large");
    }
    let mut body = vec![0u8; content_length];
    r.read_exact(&mut body).await?;
    Ok((status, body))
}

/// Connects to guest vsock `port` through Firecracker's host-side unix
/// socket: send `CONNECT <port>\n`, expect `OK <host port>\n`.
pub async fn vsock_connect(uds: &Path, port: u32) -> anyhow::Result<UnixStream> {
    let mut stream = UnixStream::connect(uds)
        .await
        .with_context(|| format!("connecting to {}", uds.display()))?;
    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .await?;
    // Byte by byte: nothing after the newline may be consumed here.
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte).await? == 0 {
            bail!("vsock handshake: connection closed (guest not listening yet?)");
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > 64 {
            bail!("vsock handshake: reply too long");
        }
    }
    if !line.starts_with(b"OK ") {
        bail!(
            "vsock handshake rejected: {:?}",
            String::from_utf8_lossy(&line)
        );
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::UnixListener;

    /// Accepts one connection, returns the raw request, replies with `reply`.
    fn fake_server(sock: &Path, reply: &'static [u8]) -> tokio::task::JoinHandle<String> {
        let listener = UnixListener::bind(sock).unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut req = Vec::new();
            // Read headers + body (small; content length from header).
            loop {
                let n = s.read(&mut buf).await.unwrap();
                req.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&req);
                if let Some(idx) = text.find("\r\n\r\n") {
                    let cl: usize = text
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    if req.len() >= idx + 4 + cl {
                        break;
                    }
                }
            }
            s.write_all(reply).await.unwrap();
            // Keep the connection open like Firecracker does (keep-alive).
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            String::from_utf8(req).unwrap()
        })
    }

    #[tokio::test]
    async fn put_snapshot_load_succeeds_on_204() {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("api.sock");
        let server = fake_server(
            &sock,
            b"HTTP/1.1 204 No Content\r\nServer: Firecracker API\r\n\r\n",
        );
        let body = super::super::vmconfig::snapshot_load_body();
        api_request(&sock, "PUT", "/snapshot/load", &body)
            .await
            .unwrap();
        let req = server.await.unwrap();
        assert!(req.starts_with("PUT /snapshot/load HTTP/1.1\r\n"));
        let json = req.split("\r\n\r\n").nth(1).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(parsed, body);
    }

    #[tokio::test]
    async fn error_status_carries_fault_message() {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("api.sock");
        let _server = fake_server(
            &sock,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 29\r\n\r\n{\"fault_message\":\"bad state\"}",
        );
        let err = api_request(&sock, "PUT", "/snapshot/load", &serde_json::json!({}))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("400") && msg.contains("bad state"), "{msg}");
    }

    #[tokio::test]
    async fn vsock_handshake() {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("v.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let mut s = BufReader::new(s);
            let mut line = String::new();
            s.read_line(&mut line).await.unwrap();
            assert_eq!(line, "CONNECT 5005\n");
            // Reply and the first payload byte in one write: must not be eaten.
            s.get_mut().write_all(b"OK 1073741824\nX").await.unwrap();
        });
        let mut stream = vsock_connect(&sock, 5005).await.unwrap();
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"X");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn vsock_handshake_refused() {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("v.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            // Firecracker closes the connection when nobody listens on the port.
            let (s, _) = listener.accept().await.unwrap();
            drop(s);
        });
        assert!(vsock_connect(&sock, 5005).await.is_err());
    }
}
