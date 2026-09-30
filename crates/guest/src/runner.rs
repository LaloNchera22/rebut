//! Deterministic execution of [`Step`]s inside the VM.
//!
//! Every step is a `cargo` invocation with a scrubbed environment, a share of
//! the request's total time budget, and capped output capture. Nothing here
//! logs step output: a request may be sealed, and the guest console can end
//! up in host logs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use verifier_core::{ExecutionRequest, Step, StepOutcome};

/// Maximum bytes kept from each of stdout and stderr per step.
pub const OUTPUT_CAP: usize = 1024 * 1024;

/// `SOURCE_DATE_EPOCH` used unless the request overrides it
/// (1980-01-01T00:00:00Z, the earliest timestamp zip-based tools accept).
pub const DEFAULT_SOURCE_DATE_EPOCH: &str = "315532800";

/// Inherited variables that survive the environment scrub.
const KEPT_VARS: &[&str] = &["PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME"];

/// How long to wait for output pipes after the process group is gone.
const PIPE_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Builds the step environment: only [`KEPT_VARS`] from `inherited`, then the
/// fixed determinism knobs, then the request's own `env` (which wins).
pub fn deterministic_env(
    inherited: impl IntoIterator<Item = (String, String)>,
    request_env: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = inherited
        .into_iter()
        .filter(|(k, _)| KEPT_VARS.contains(&k.as_str()))
        .collect();
    for (k, v) in [
        ("SOURCE_DATE_EPOCH", DEFAULT_SOURCE_DATE_EPOCH),
        ("CARGO_INCREMENTAL", "0"),
        ("CARGO_TERM_COLOR", "never"),
        ("RUST_TEST_THREADS", "1"),
        ("TZ", "UTC"),
        ("LANG", "C"),
        ("LC_ALL", "C"),
    ] {
        env.insert(k.to_string(), v.to_string());
    }
    env.extend(request_env.iter().map(|(k, v)| (k.clone(), v.clone())));
    env
}

/// Executes the steps of one request against an unpacked source tree.
pub struct Runner<'a> {
    req: &'a ExecutionRequest,
    workdir: PathBuf,
    deadline: Instant,
    env: BTreeMap<String, String>,
}

impl<'a> Runner<'a> {
    /// Starts the clock: the whole request shares `req.timeout_secs`.
    pub fn new(req: &'a ExecutionRequest, workdir: &Path) -> Self {
        Runner {
            req,
            workdir: workdir.to_path_buf(),
            deadline: Instant::now() + Duration::from_secs(req.timeout_secs),
            env: deterministic_env(std::env::vars(), &req.env),
        }
    }

    /// Runs step `index`. Never fails: problems become a failed outcome with
    /// the reason on stderr.
    pub async fn run_step(&self, index: usize) -> StepOutcome {
        let started = Instant::now();
        let budget = self.deadline.saturating_duration_since(started);
        let mut outcome = StepOutcome {
            step_index: index,
            exit_code: None,
            timed_out: false,
            stdout: Vec::new(),
            stderr: Vec::new(),
            duration_ms: 0,
        };
        if budget.is_zero() {
            outcome.timed_out = true;
            return outcome;
        }
        let prepared = match self.req.steps.get(index) {
            Some(step) => self.prepare(step),
            None => Err(format!("no step with index {index}")),
        };
        match prepared {
            Ok((cmd, stdin)) => {
                let c = run_command(cmd, stdin, budget).await;
                outcome.exit_code = c.exit_code;
                outcome.timed_out = c.timed_out;
                outcome.stdout = c.stdout;
                outcome.stderr = c.stderr;
            }
            Err(msg) => outcome.stderr = format!("verifier-guest: {msg}\n").into_bytes(),
        }
        outcome.duration_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        outcome
    }

    fn cargo(&self, dir: &Path) -> Command {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(dir).env_clear().envs(&self.env);
        cmd
    }

    fn prepare(&self, step: &Step) -> Result<(Command, Option<Vec<u8>>), String> {
        match step {
            Step::Build { profile } => {
                if !is_ident(profile) {
                    return Err(format!("invalid profile name {profile:?}"));
                }
                let mut cmd = self.cargo(&self.workdir);
                cmd.args(["build", "--locked", "--offline", "--tests", "--profile"])
                    .arg(profile);
                Ok((cmd, None))
            }
            Step::Test { filters } => {
                let mut cmd = self.cargo(&self.workdir);
                cmd.args(["test", "--locked", "--offline", "--"])
                    .args(filters);
                Ok((cmd, None))
            }
            Step::Harness {
                name,
                source,
                input,
            } => {
                let dir = self.write_harness(name, source)?;
                let mut cmd = self.cargo(&dir);
                // Share the crate's target dir so the dependency is built once.
                cmd.env("CARGO_TARGET_DIR", self.workdir.join("target"))
                    .args(["run", "--quiet", "--offline"]);
                Ok((cmd, Some(input.clone())))
            }
        }
    }

    /// Creates `target/verifier-harness/<name>`: a standalone binary crate
    /// whose only dependency is the crate under test, by path.
    fn write_harness(&self, name: &str, source: &str) -> Result<PathBuf, String> {
        if !is_ident(name) {
            return Err(format!("invalid harness name {name:?}"));
        }
        let manifest = std::fs::read_to_string(self.workdir.join("Cargo.toml"))
            .map_err(|e| format!("reading Cargo.toml: {e}"))?;
        let krate = package_name(&manifest)?;
        let dir = self.workdir.join("target/verifier-harness").join(name);
        let io = |e: std::io::Error| format!("writing harness: {e}");
        std::fs::create_dir_all(dir.join("src")).map_err(io)?;
        let harness_manifest = format!(
            "[package]\nname = \"verifier-harness-{name}\"\nversion = \"0.0.0\"\n\
             edition = \"2021\"\npublish = false\n\n[dependencies]\n{krate} = {{ path = {} }}\n\n\
             [workspace]\n",
            toml_string(&self.workdir.to_string_lossy()),
        );
        std::fs::write(dir.join("Cargo.toml"), harness_manifest).map_err(io)?;
        std::fs::write(dir.join("src/main.rs"), source).map_err(io)?;
        // Reuse the crate's resolved versions; resolution stays offline.
        let lock = self.workdir.join("Cargo.lock");
        if lock.exists() {
            std::fs::copy(&lock, dir.join("Cargo.lock")).map_err(io)?;
        }
        Ok(dir)
    }
}

/// Runs every step of `req` in `workdir`, sequentially.
pub async fn run_request(req: &ExecutionRequest, workdir: &Path) -> Vec<StepOutcome> {
    let runner = Runner::new(req, workdir);
    let mut out = Vec::with_capacity(req.steps.len());
    for i in 0..req.steps.len() {
        out.push(runner.run_step(i).await);
    }
    out
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn toml_string(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn package_name(manifest: &str) -> Result<String, String> {
    let table: toml::Table = manifest
        .parse()
        .map_err(|e| format!("parsing Cargo.toml: {e}"))?;
    table
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .filter(|n| is_ident(n))
        .map(str::to_string)
        .ok_or_else(|| "Cargo.toml has no valid [package] name".to_string())
}

struct Captured {
    exit_code: Option<i32>,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn run_command(mut cmd: Command, stdin: Option<Vec<u8>>, budget: Duration) -> Captured {
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    // Own process group, so a timeout kills cargo and everything it spawned.
    .process_group(0);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Captured {
                exit_code: None,
                timed_out: false,
                stdout: Vec::new(),
                stderr: format!("verifier-guest: spawn failed: {e}\n").into_bytes(),
            }
        }
    };
    let pgid = child.id();
    if let (Some(mut pipe), Some(data)) = (child.stdin.take(), stdin) {
        tokio::spawn(async move {
            // The child may exit without reading; a broken pipe is fine.
            let _ = pipe.write_all(&data).await;
        });
    }
    let out = tokio::spawn(read_capped(child.stdout.take()));
    let err = tokio::spawn(read_capped(child.stderr.take()));

    let (status, timed_out) = match tokio::time::timeout(budget, child.wait()).await {
        Ok(status) => (status.ok(), false),
        Err(_) => {
            kill_group(pgid);
            (child.wait().await.ok(), true)
        }
    };
    // Reap stragglers that still hold the pipes open.
    kill_group(pgid);
    let drain = |h: tokio::task::JoinHandle<Vec<u8>>| async move {
        match tokio::time::timeout(PIPE_DRAIN_GRACE, h).await {
            Ok(Ok(buf)) => buf,
            _ => b"[verifier: output lost]\n".to_vec(),
        }
    };
    Captured {
        exit_code: if timed_out {
            None
        } else {
            status.and_then(|s| s.code())
        },
        timed_out,
        stdout: drain(out).await,
        stderr: drain(err).await,
    }
}

fn kill_group(pgid: Option<u32>) {
    if let Some(pid) = pgid.and_then(|p| i32::try_from(p).ok()) {
        // SAFETY: plain syscall; a stale or already-dead group just yields ESRCH.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}

/// Reads to EOF, keeping at most [`OUTPUT_CAP`] bytes and appending a marker
/// with the number of dropped bytes. Keeps draining so the child never blocks.
async fn read_capped<R: AsyncRead + Unpin>(pipe: Option<R>) -> Vec<u8> {
    let Some(mut pipe) = pipe else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    let mut dropped: u64 = 0;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match pipe.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let keep = n.min(OUTPUT_CAP - buf.len());
                buf.extend_from_slice(&chunk[..keep]);
                dropped += (n - keep) as u64;
            }
        }
    }
    if dropped > 0 {
        buf.extend_from_slice(
            format!("\n[verifier: output truncated, {dropped} bytes omitted]\n").as_bytes(),
        );
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_is_scrubbed_and_request_wins() {
        let inherited = [
            ("PATH", "/bin"),
            ("HOME", "/root"),
            ("AWS_SECRET_ACCESS_KEY", "leak"),
            ("TZ", "Europe/Madrid"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        let req_env = BTreeMap::from([("SOURCE_DATE_EPOCH".to_string(), "42".to_string())]);
        let env = deterministic_env(inherited, &req_env);
        assert_eq!(env["PATH"], "/bin");
        assert_eq!(env["HOME"], "/root");
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert_eq!(env["TZ"], "UTC");
        assert_eq!(env["LANG"], "C");
        assert_eq!(env["CARGO_INCREMENTAL"], "0");
        assert_eq!(env["RUST_TEST_THREADS"], "1");
        assert_eq!(env["SOURCE_DATE_EPOCH"], "42");
    }

    #[test]
    fn package_name_and_idents() {
        assert_eq!(
            package_name("[package]\nname = \"my-crate\"\n").unwrap(),
            "my-crate"
        );
        assert!(package_name("[workspace]\n").is_err());
        assert!(package_name("[package]\nname = \"a\\\"b\"\n").is_err());
        assert!(is_ident("release_lto-2"));
        assert!(!is_ident("../x"));
        assert!(!is_ident(""));
    }

    #[tokio::test]
    async fn output_is_capped_with_marker() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "head -c 1100000 /dev/zero; echo err >&2"]);
        let c = run_command(cmd, None, Duration::from_secs(30)).await;
        assert_eq!(c.exit_code, Some(0));
        assert!(!c.timed_out);
        let marker = format!(
            "\n[verifier: output truncated, {} bytes omitted]\n",
            1_100_000 - OUTPUT_CAP
        );
        assert_eq!(c.stdout.len(), OUTPUT_CAP + marker.len());
        assert!(c.stdout.ends_with(marker.as_bytes()));
        assert_eq!(c.stderr, b"err\n");
    }

    #[tokio::test]
    async fn timeout_kills_the_whole_group() {
        let mut cmd = Command::new("sh");
        // The background sleep keeps stdout open; it must die with the group.
        cmd.args(["-c", "sleep 30 & echo started; wait"]);
        let t = Instant::now();
        let c = run_command(cmd, None, Duration::from_millis(300)).await;
        assert!(c.timed_out);
        assert_eq!(c.exit_code, None);
        assert_eq!(c.stdout, b"started\n");
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn stdin_is_delivered() {
        let cmd = Command::new("cat");
        let c = run_command(cmd, Some(b"payload".to_vec()), Duration::from_secs(10)).await;
        assert_eq!(c.exit_code, Some(0));
        assert_eq!(c.stdout, b"payload");
    }

    #[tokio::test]
    async fn exhausted_budget_marks_step_timed_out() {
        let req = ExecutionRequest {
            id: uuid::Uuid::nil(),
            repo_url: "local".into(),
            commit: verifier_core::CommitSha::new("0".repeat(40)).unwrap(),
            steps: vec![Step::Test { filters: vec![] }],
            timeout_secs: 0,
            vcpus: 1,
            memory_mib: 256,
            sealed: false,
            env: BTreeMap::new(),
        };
        let out = run_request(&req, Path::new("/nonexistent")).await;
        assert_eq!(out.len(), 1);
        assert!(out[0].timed_out);
        assert_eq!(out[0].exit_code, None);
    }
}
