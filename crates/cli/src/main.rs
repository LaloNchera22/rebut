use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use rebut::audit::parse_public_key;
use rebut::local::LocalRun;
use rebut::{derive_seed, regenerate_challenges, verify_local, verify_receipt, LocalOptions};
use rebut_challenges::drand::QUICKNET_CHAIN_HASH;
use rebut_challenges::DrandClient;
use rebut_core::{CommitSha, DrandBeacon, EngineKind, Seed, VerdictStatus, Visibility};
use rebut_receipts::{Envelope, LogEntry};

#[derive(Parser)]
#[command(
    name = "rebut",
    version,
    about = "Verify pull requests: locally, and audit the service"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the public checks on the current branch against a base.
    ///
    /// Builds and runs your code on this machine WITHOUT a sandbox, exactly
    /// like `cargo test`. Only use it on code you would run yourself.
    Verify {
        /// Branch or commit to compare against (the merge base is used).
        #[arg(long, default_value = "main")]
        base: String,
        /// Repository path.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Use a local pseudo-beacon instead of fetching drand.
        #[arg(long)]
        offline: bool,
        /// Only run these engines (default: the base policy's engines).
        #[arg(long, value_delimiter = ',', value_parser = parse_engine)]
        engines: Option<Vec<EngineKind>>,
        /// Print the full result as JSON.
        #[arg(long)]
        json: bool,
        /// Exit non-zero on actionable findings (default: mark, don't block).
        #[arg(long)]
        fail_on_findings: bool,
    },
    /// Recompute the challenge seed for a commit from a drand round (ADR-7).
    Seed(SeedArgs),
    /// Public challenges.
    Challenges {
        #[command(subcommand)]
        command: ChallengesCmd,
    },
    /// Signed receipts.
    Receipt {
        #[command(subcommand)]
        command: ReceiptCmd,
    },
}

#[derive(clap::Args)]
struct SeedArgs {
    #[arg(long)]
    commit: String,
    #[arg(long)]
    round: u64,
    /// Beacon JSON (as printed by `seed` or stored in a receipt) for an
    /// offline audit; otherwise the round is fetched from drand.
    #[arg(long)]
    beacon: Option<PathBuf>,
    #[arg(long, env = "DRAND_URL")]
    drand_url: Option<String>,
}

#[derive(Subcommand)]
enum ChallengesCmd {
    /// Regenerate the public challenge inputs a PR was tested with.
    Regenerate {
        #[command(flatten)]
        seed: SeedArgs,
        /// The base branch's `.rebut/challenges.toml`.
        #[arg(long)]
        spec: PathBuf,
        /// Cap the cases printed per challenge.
        #[arg(long)]
        max_cases: Option<usize>,
    },
}

#[derive(Subcommand)]
enum ReceiptCmd {
    /// Check a receipt's signature and, optionally, its log inclusion.
    Verify {
        /// DSSE envelope JSON (GET /v1/receipts/:id).
        #[arg(long)]
        envelope: PathBuf,
        /// Operator's ed25519 public key, hex or base64.
        #[arg(long)]
        key: String,
        /// Log entry JSON (GET /v1/log/:index).
        #[arg(long)]
        log_entry: Option<PathBuf>,
    },
}

fn parse_engine(s: &str) -> Result<EngineKind, String> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|_| format!("unknown engine {s:?}"))
}

fn drand_client(url: Option<&str>) -> anyhow::Result<DrandClient> {
    match url {
        Some(u) => DrandClient::new(u, QUICKNET_CHAIN_HASH),
        None => DrandClient::quicknet(),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> anyhow::Result<T> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

async fn seed_info(args: &SeedArgs) -> anyhow::Result<rebut::SeedInfo> {
    let commit = CommitSha::new(&args.commit).map_err(anyhow::Error::msg)?;
    let beacon: Option<DrandBeacon> = args.beacon.as_ref().map(read_json).transpose()?;
    let client = drand_client(args.drand_url.as_deref())?;
    derive_seed(&commit, args.round, beacon, &client).await
}

fn print_human(run: &LocalRun) {
    let v = &run.verdict;
    println!(
        "base {}  head {}{}",
        run.base_sha,
        run.head_sha,
        if run.synthetic_head {
            " (uncommitted tree)"
        } else {
            ""
        }
    );
    println!(
        "seed {} ({})",
        v.seed.map(|s| s.0.to_hex()).unwrap_or_default(),
        if run.offline_seed {
            "offline pseudo-beacon".to_string()
        } else {
            format!("drand round {}", run.beacon.round)
        }
    );
    println!(
        "plan: {} changed fn(s), {} test(s){}",
        run.plan.changed_functions.len(),
        run.plan.tests.len(),
        if run.plan.widen_to_full_suite {
            ", full suite"
        } else {
            ""
        }
    );
    for f in &v.findings {
        let tag = if f.is_actionable() { "FINDING" } else { "info" };
        println!("\n[{tag}] {} / {}: {}", f.engine, f.category, f.title);
        if let Some(t) = &f.target {
            println!("  target:   {t}");
        }
        if f.visibility == Visibility::Public {
            let r = f.reproduction();
            println!(
                "  input:    {}",
                String::from_utf8_lossy(r.input()).trim_end()
            );
            println!(
                "  expected: {}",
                String::from_utf8_lossy(r.expected())
                    .trim_end()
                    .replace('\n', " | ")
            );
            println!(
                "  observed: {}",
                String::from_utf8_lossy(r.observed())
                    .trim_end()
                    .replace('\n', " | ")
            );
            println!("  transcript: {}", r.transcript());
        }
    }
    if run.unreproduced > 0 {
        println!(
            "\n{} hypothesis(es) could not be reproduced and were discarded",
            run.unreproduced
        );
    }
    let status = match v.status() {
        VerdictStatus::Pass => "PASS".to_string(),
        VerdictStatus::Flagged => "FLAGGED (mark mode: not blocking)".to_string(),
        VerdictStatus::Fail => "FAIL".to_string(),
        VerdictStatus::Inconclusive => format!(
            "INCONCLUSIVE: {}",
            v.inconclusive_reason.as_deref().unwrap_or("")
        ),
    };
    println!("\n{status}");
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Cmd::Verify {
            base,
            repo,
            offline,
            engines,
            json,
            fail_on_findings,
        } => {
            eprintln!(
                "note: building and running your code locally, unsandboxed (like `cargo test`)"
            );
            let beacon = if offline {
                None
            } else {
                Some(Arc::new(drand_client(None)?) as Arc<dyn rebut_challenges::BeaconSource>)
            };
            let run = verify_local(
                &repo,
                LocalOptions {
                    base,
                    beacon,
                    engines,
                },
            )
            .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&run)?);
            } else {
                print_human(&run);
            }
            let flagged = matches!(
                run.verdict.status(),
                VerdictStatus::Flagged | VerdictStatus::Fail
            );
            Ok(if fail_on_findings && flagged {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Cmd::Seed(args) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&seed_info(&args).await?)?
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Challenges {
            command:
                ChallengesCmd::Regenerate {
                    seed,
                    spec,
                    max_cases,
                },
        } => {
            let info = seed_info(&seed).await?;
            let seed =
                Seed(rebut_core::Digest::try_from(info.seed.clone()).map_err(anyhow::Error::msg)?);
            let toml = std::fs::read_to_string(&spec)
                .with_context(|| format!("reading {}", spec.display()))?;
            let out = serde_json::json!({
                "seed": info,
                "challenges": regenerate_challenges(&toml, &seed, max_cases)?,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Receipt {
            command:
                ReceiptCmd::Verify {
                    envelope,
                    key,
                    log_entry,
                },
        } => {
            let env: Envelope = read_json(&envelope)?;
            let entry: Option<LogEntry> = log_entry.as_ref().map(read_json).transpose()?;
            let check = verify_receipt(&env, &parse_public_key(&key)?, entry.as_ref())?;
            println!("{}", serde_json::to_string_pretty(&check)?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,rebut_fabric::local=error".into()),
        )
        .init();
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}
