//! `verifier-guest` binary: serves protocol sessions on vsock (inside the VM)
//! or on stdin/stdout (`--stdio`, for testing).
//!
//! The VM's init mounts the ephemeral scratch drive and starts this binary
//! with `--work-root` pointing at it.

use std::path::PathBuf;

use anyhow::Context as _;
use clap::Parser;

#[derive(Parser)]
#[command(name = "verifier-guest", about = "In-VM execution agent")]
struct Args {
    /// Serve a single session over stdin/stdout instead of vsock.
    #[arg(long)]
    stdio: bool,
    /// vsock port to listen on.
    #[arg(long, default_value_t = verifier_guest::protocol::GUEST_VSOCK_PORT)]
    port: u32,
    /// Directory where sources are unpacked (the scratch drive).
    #[arg(long, default_value = "/scratch")]
    work_root: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logs go to stderr; stdout carries frames in --stdio mode.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.work_root)
        .with_context(|| format!("creating {}", args.work_root.display()))?;

    if args.stdio {
        verifier_guest::serve_connection(tokio::io::stdin(), tokio::io::stdout(), &args.work_root)
            .await?;
        return Ok(());
    }
    serve_vsock(args).await
}

#[cfg(feature = "vsock")]
async fn serve_vsock(args: Args) -> anyhow::Result<()> {
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, args.port))
        .with_context(|| format!("binding vsock port {}", args.port))?;
    tracing::info!(port = args.port, "listening on vsock");
    // Sessions are served one at a time: a VM runs exactly one request.
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::info!(?peer, "host connected");
        let (r, w) = stream.into_split();
        if let Err(e) = verifier_guest::serve_connection(r, w, &args.work_root).await {
            tracing::error!(error = %e, "session failed");
        }
    }
}

#[cfg(not(feature = "vsock"))]
async fn serve_vsock(_args: Args) -> anyhow::Result<()> {
    anyhow::bail!("built without the `vsock` feature; use --stdio")
}
