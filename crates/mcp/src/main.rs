use std::sync::Arc;

use rebut_challenges::DrandClient;
use rebut_mcp::Server;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Line-delimited JSON-RPC over stdio. Logs go to stderr; stdout is protocol.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,rebut_fabric::local=error".into()),
        )
        .init();
    let server = Server::new(Arc::new(DrandClient::quicknet()?));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = server.handle_line(&line).await {
            stdout.write_all(response.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}
