//! MCP server for agents.
//!
//! Tools mirror the `rebut` CLI: run the public checks on a local
//! checkout, recompute a seed, regenerate public challenges, verify a receipt,
//! and fetch a PR's contributor report from a running control plane.
//!
//! Results are evidence only when they carry a reproduction (ADR-6); an agent
//! calling these tools gets the same verdicts a human would.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use rebut::audit::parse_public_key;
use rebut::{derive_seed, regenerate_challenges, verify_local, verify_receipt, LocalOptions};
use rebut_challenges::BeaconSource;
use rebut_core::{CommitSha, DrandBeacon, EngineKind, Seed};
use rebut_receipts::{Envelope, LogEntry};
use serde::Deserialize;
use serde_json::{json, Value};

pub const PROTOCOL_VERSION: &str = "2025-06-18";

pub struct Server {
    beacon: Arc<dyn BeaconSource>,
    http: reqwest::Client,
}

fn tools() -> Value {
    json!([
        {
            "name": "verify_local",
            "description": "Run the public checks (differential + challenges) on a local git checkout, comparing HEAD (or the uncommitted tree) against the merge base with `base`. Builds and runs the code on this machine WITHOUT a sandbox, like `cargo test`: only use on code you would run yourself. Returns the verdict; a finding always carries a concrete input and the expected vs observed behavior.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path inside the git repository"},
                    "base": {"type": "string", "default": "main"},
                    "offline": {"type": "boolean", "default": false, "description": "Use a local pseudo-beacon instead of drand"},
                    "engines": {"type": "array", "items": {"enum": ["differential", "challenges"]}}
                },
                "required": ["path"]
            }
        },
        {
            "name": "derive_seed",
            "description": "Recompute the challenge seed H(commit ‖ drand round ‖ generator version) for a commit, fetching the drand round unless a beacon is given.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "commit": {"type": "string"},
                    "round": {"type": "integer", "minimum": 1},
                    "beacon": {"type": "object", "description": "Optional DrandBeacon for offline audits"}
                },
                "required": ["commit", "round"]
            }
        },
        {
            "name": "regenerate_challenges",
            "description": "Regenerate the public challenge inputs a PR was tested with, from the base branch's .rebut/challenges.toml and the seed inputs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "spec_toml": {"type": "string"},
                    "commit": {"type": "string"},
                    "round": {"type": "integer", "minimum": 1},
                    "beacon": {"type": "object"},
                    "max_cases": {"type": "integer", "minimum": 1}
                },
                "required": ["spec_toml", "commit", "round"]
            }
        },
        {
            "name": "verify_receipt",
            "description": "Verify a DSSE receipt's signature against the operator key and, if given, its transparency-log inclusion proof.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "envelope": {"type": "object"},
                    "public_key": {"type": "string", "description": "ed25519 public key, hex or base64"},
                    "log_entry": {"type": "object"}
                },
                "required": ["envelope", "public_key"]
            }
        },
        {
            "name": "get_report",
            "description": "Fetch the contributor report for a pull request from a Rebut control plane. Sealed challenge failures appear only as categories.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "api_url": {"type": "string"},
                    "owner": {"type": "string"},
                    "repo": {"type": "string"},
                    "number": {"type": "integer", "minimum": 1}
                },
                "required": ["api_url", "owner", "repo", "number"]
            }
        }
    ])
}

#[derive(Deserialize)]
struct VerifyLocalArgs {
    path: PathBuf,
    #[serde(default = "default_base")]
    base: String,
    #[serde(default)]
    offline: bool,
    engines: Option<Vec<EngineKind>>,
}

fn default_base() -> String {
    "main".into()
}

#[derive(Deserialize)]
struct SeedArgs {
    commit: String,
    round: u64,
    beacon: Option<DrandBeacon>,
}

#[derive(Deserialize)]
struct RegenerateArgs {
    spec_toml: String,
    #[serde(flatten)]
    seed: SeedArgs,
    max_cases: Option<usize>,
}

#[derive(Deserialize)]
struct ReceiptArgs {
    envelope: Envelope,
    public_key: String,
    log_entry: Option<LogEntry>,
}

#[derive(Deserialize)]
struct ReportArgs {
    api_url: String,
    owner: String,
    repo: String,
    number: u64,
}

fn is_safe_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

impl Server {
    pub fn new(beacon: Arc<dyn BeaconSource>) -> Self {
        Server {
            beacon,
            http: reqwest::Client::new(),
        }
    }

    /// Handles one JSON-RPC message; `None` for notifications.
    pub async fn handle_line(&self, line: &str) -> Option<String> {
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return Some(
                    error_response(Value::Null, -32700, &format!("parse error: {e}")).to_string(),
                )
            }
        };
        self.handle(msg).await.map(|v| v.to_string())
    }

    pub async fn handle(&self, msg: Value) -> Option<Value> {
        let id = msg.get("id").cloned();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let id = id?; // Notifications (no id) get no response.
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "rebut-mcp", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Tools to verify Rust changes and audit the Rebut. \
                    Only findings with a concrete reproduction are evidence.",
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                // Tool failures are results with isError, not protocol errors.
                Ok(match self.call(name, args).await {
                    Ok(v) => json!({
                        "content": [{"type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default()}],
                        "structuredContent": v,
                        "isError": false,
                    }),
                    Err(e) => json!({
                        "content": [{"type": "text", "text": format!("{e:#}")}],
                        "isError": true,
                    }),
                })
            }
            _ => Err((-32601, format!("method not found: {method}"))),
        };
        Some(match result {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err((code, m)) => error_response(id, code, &m),
        })
    }

    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        match name {
            "verify_local" => {
                let a: VerifyLocalArgs = serde_json::from_value(args)?;
                let run = verify_local(
                    &a.path,
                    LocalOptions {
                        base: a.base,
                        beacon: (!a.offline).then(|| self.beacon.clone()),
                        engines: a.engines,
                    },
                )
                .await?;
                Ok(json!({"status": run.verdict.status(), "run": run}))
            }
            "derive_seed" => {
                let a: SeedArgs = serde_json::from_value(args)?;
                Ok(serde_json::to_value(self.seed(&a).await?)?)
            }
            "regenerate_challenges" => {
                let a: RegenerateArgs = serde_json::from_value(args)?;
                let info = self.seed(&a.seed).await?;
                let seed = Seed(info.seed.clone().try_into().map_err(anyhow::Error::msg)?);
                Ok(json!({
                    "seed": info,
                    "challenges": regenerate_challenges(&a.spec_toml, &seed, a.max_cases)?,
                }))
            }
            "verify_receipt" => {
                let a: ReceiptArgs = serde_json::from_value(args)?;
                let key = parse_public_key(&a.public_key)?;
                Ok(serde_json::to_value(verify_receipt(
                    &a.envelope,
                    &key,
                    a.log_entry.as_ref(),
                )?)?)
            }
            "get_report" => {
                let a: ReportArgs = serde_json::from_value(args)?;
                if !(a.api_url.starts_with("https://") || a.api_url.starts_with("http://")) {
                    bail!("api_url must be http(s)");
                }
                if !is_safe_segment(&a.owner) || !is_safe_segment(&a.repo) {
                    bail!("invalid owner or repo");
                }
                let url = format!(
                    "{}/v1/prs/{}/{}/{}/report",
                    a.api_url.trim_end_matches('/'),
                    a.owner,
                    a.repo,
                    a.number
                );
                let resp = self.http.get(&url).send().await?.error_for_status()?;
                resp.json().await.context("report is not JSON")
            }
            other => bail!("unknown tool {other:?}"),
        }
    }

    async fn seed(&self, a: &SeedArgs) -> anyhow::Result<rebut::SeedInfo> {
        let commit = CommitSha::new(&a.commit).map_err(anyhow::Error::msg)?;
        derive_seed(&commit, a.round, a.beacon.clone(), self.beacon.as_ref()).await
    }
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use rebut_challenges::FixedBeacon;

    fn server() -> Server {
        // randomness = sha256(signature) for signature = 0xab * 48.
        let signature = "ab".repeat(48);
        let randomness = rebut_core::Digest::of(&[0xab; 48]).to_hex();
        Server::new(Arc::new(FixedBeacon(DrandBeacon {
            chain_hash: "c".into(),
            round: 9,
            randomness,
            signature,
        })))
    }

    async fn call(s: &Server, msg: Value) -> Value {
        s.handle(msg).await.expect("response")
    }

    #[tokio::test]
    async fn handshake_and_tool_listing() {
        let s = server();
        let r = call(
            &s,
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        )
        .await;
        assert_eq!(r["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(s
            .handle(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await
            .is_none());
        let r = call(&s, json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).await;
        let names: Vec<_> = r["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            names,
            [
                "verify_local",
                "derive_seed",
                "regenerate_challenges",
                "verify_receipt",
                "get_report"
            ]
        );
        let r = call(&s, json!({"jsonrpc":"2.0","id":3,"method":"nope"})).await;
        assert_eq!(r["error"]["code"], -32601);
        let r = s.handle_line("{not json").await.unwrap();
        assert!(r.contains("-32700"));
    }

    #[tokio::test]
    async fn seed_and_challenges_tools() {
        let s = server();
        let commit = "e".repeat(40);
        let r = call(
            &s,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                   "params":{"name":"derive_seed","arguments":{"commit":commit,"round":9}}}),
        )
        .await;
        assert_eq!(r["result"]["isError"], false, "{r}");
        let seed = r["result"]["structuredContent"]["seed"].clone();

        let spec = "[[challenge]]\nid = \"p\"\ntarget = \"demo::p\"\ncases = 3\nargs = [{ ty = \"bool\" }]\noracle = { kind = \"no_panic\" }\n";
        let r = call(
            &s,
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
                   "params":{"name":"regenerate_challenges","arguments":{"commit":commit,"round":9,"spec_toml":spec}}}),
        )
        .await;
        let out = &r["result"]["structuredContent"];
        assert_eq!(out["seed"]["seed"], seed);
        assert_eq!(out["challenges"][0]["cases"].as_array().unwrap().len(), 3);

        // Wrong round: a tool error, not a protocol error.
        let r = call(
            &s,
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                   "params":{"name":"derive_seed","arguments":{"commit":commit,"round":10}}}),
        )
        .await;
        assert_eq!(r["result"]["isError"], true);
    }

    #[tokio::test]
    async fn get_report_rejects_path_injection() {
        let s = server();
        let r = call(
            &s,
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                   "params":{"name":"get_report","arguments":{"api_url":"https://x","owner":"..","repo":"r","number":1}}}),
        )
        .await;
        assert_eq!(r["result"]["isError"], true);
    }
}
