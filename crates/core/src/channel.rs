//! The authenticated result channel of generated harnesses.
//!
//! A harness runs the code under test in its own process and reports what it
//! saw on stdout. Without protection, that code can print the report itself
//! (`println!("case 0 pass")`, `rebut:invariant:held`) and have a failure
//! read as a pass: the obvious shortcut for an agent iterating against us.
//! So:
//!
//! * [`execute`] gives every [`Step::Harness`] of a request a fresh 128-bit
//!   nonce from OS randomness, as the first line of its stdin. The harness
//!   reads it ([`HARNESS_SOURCE`]) before any code under test runs; it is
//!   not in argv or the environment, where that code could simply look.
//! * The harness then moves the real stdout to a private descriptor and
//!   points fd 1 at stderr, so ordinary prints never reach the channel
//!   (unix; elsewhere only the nonce protects it).
//! * Every report line is `#rebut <nonce> <message>`. [`open`] keeps only
//!   complete lines carrying the right nonce and strips the prefix. Engines,
//!   findings and receipts therefore see the nonce-free *canonical* form
//!   (one `<message>` per line), which is identical across runs and so stays
//!   reproducible; the transcript digest still binds the raw run.
//!
//! Engines additionally validate the message sequence of their protocol and
//! treat a duplicate or out-of-order message as tampering: an untrusted
//! result is inconclusive, never a pass. Residual limit: code in the same
//! process can in principle read the nonce and the private descriptor from
//! memory; only a separate process or sandbox isolates the reporter fully.

use std::collections::BTreeMap;

use rand::RngCore;

use crate::{ExecutionRequest, ExecutionResult, Executor, Step};

/// Prefix of every channel line, followed by the nonce and a space.
pub const LINE_PREFIX: &str = "#rebut ";

/// Rust source (edition 2021, no dependencies) defining `__RebutChannel`.
/// A harness calls `__RebutChannel::open()` first thing in `main` and
/// reports with `send(message)`; messages must not contain newlines.
pub const HARNESS_SOURCE: &str = r##"
// Result channel (rebut_core::channel). Opened before any code under test
// runs: the nonce is the first stdin line, and the real stdout moves to a
// private descriptor while fd 1 is pointed at stderr.
struct __RebutChannel {
    nonce: String,
    out: Box<dyn std::io::Write>,
}
impl __RebutChannel {
    fn open() -> __RebutChannel {
        let mut nonce = String::new();
        std::io::stdin().read_line(&mut nonce).expect("stdin");
        let nonce = nonce.trim_end().to_string();
        assert!(
            nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit()),
            "bad channel nonce"
        );
        __RebutChannel { nonce, out: __rebut_private_stdout() }
    }
    fn send(&mut self, msg: &str) {
        let line = format!("#rebut {} {}\n", self.nonce, msg);
        std::io::Write::write_all(&mut self.out, line.as_bytes()).expect("channel");
        std::io::Write::flush(&mut self.out).expect("channel");
    }
}
#[cfg(unix)]
fn __rebut_private_stdout() -> Box<dyn std::io::Write> {
    use std::os::unix::io::FromRawFd as _;
    extern "C" {
        fn dup(fd: i32) -> i32;
        fn dup2(src: i32, dst: i32) -> i32;
    }
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let fd = unsafe { dup(1) };
    assert!(fd >= 0 && unsafe { dup2(2, 1) } == 1, "channel descriptor");
    Box::new(unsafe { std::fs::File::from_raw_fd(fd) })
}
#[cfg(not(unix))]
fn __rebut_private_stdout() -> Box<dyn std::io::Write> {
    Box::new(std::io::stdout())
}
"##;

/// A fresh 128-bit nonce from OS randomness, hex-encoded.
pub fn fresh_nonce() -> String {
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// The stdin actually fed to a harness: the nonce line, then `input`.
pub fn seal_input(nonce: &str, input: &[u8]) -> Vec<u8> {
    [nonce.as_bytes(), b"\n", input].concat()
}

/// Splits a sealed stdin into nonce and the engine's input.
pub fn unseal_input(sealed: &[u8]) -> Option<(&str, &[u8])> {
    let nl = sealed.iter().position(|&b| b == b'\n')?;
    let nonce = std::str::from_utf8(&sealed[..nl]).ok()?;
    Some((nonce, &sealed[nl + 1..]))
}

/// Frames canonical output as a harness with `nonce` would print it (one
/// channel line per line of `canonical`). For fakes and tests.
pub fn frame(nonce: &str, canonical: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in canonical.split_inclusive(|&b| b == b'\n') {
        out.extend_from_slice(format!("{LINE_PREFIX}{nonce} ").as_bytes());
        out.extend_from_slice(line);
        if !line.ends_with(b"\n") {
            out.push(b'\n');
        }
    }
    out
}

/// The canonical form of a harness's raw stdout: the messages of complete
/// lines carrying `nonce`, one per line. Everything else is dropped.
pub fn authenticated(stdout: &[u8], nonce: &str) -> Vec<u8> {
    let prefix = format!("{LINE_PREFIX}{nonce} ");
    let mut out = Vec::new();
    for line in stdout.split_inclusive(|&b| b == b'\n') {
        if let Some(msg) = line.strip_prefix(prefix.as_bytes()) {
            if msg.ends_with(b"\n") {
                out.extend_from_slice(msg);
            }
        }
    }
    out
}

/// Gives every harness step of `req` a fresh nonce. Returns step index ->
/// nonce, for [`open`].
pub fn seal(req: &mut ExecutionRequest) -> BTreeMap<usize, String> {
    let mut nonces = BTreeMap::new();
    for (i, step) in req.steps.iter_mut().enumerate() {
        if let Step::Harness { input, .. } = step {
            let nonce = fresh_nonce();
            *input = seal_input(&nonce, input);
            nonces.insert(i, nonce);
        }
    }
    nonces
}

/// Replaces the stdout of each sealed harness step with its canonical form.
pub fn open(mut result: ExecutionResult, nonces: &BTreeMap<usize, String>) -> ExecutionResult {
    for o in &mut result.outcomes {
        if let Some(nonce) = nonces.get(&o.step_index) {
            o.stdout = authenticated(&o.stdout, nonce);
        }
    }
    result
}

/// Runs `req` with sealed harness steps and returns canonical harness
/// output. Every engine that runs generated harnesses goes through this.
pub async fn execute(
    executor: &dyn Executor,
    mut req: ExecutionRequest,
) -> anyhow::Result<ExecutionResult> {
    let nonces = seal(&mut req);
    Ok(open(executor.execute(req).await?, &nonces))
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn nonces_are_fresh_and_well_formed() {
        let (a, b) = (fresh_nonce(), fresh_nonce());
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn input_roundtrip() {
        let sealed = seal_input(N, b"1 2\n3 4\n");
        assert_eq!(unseal_input(&sealed), Some((N, b"1 2\n3 4\n".as_slice())));
        assert_eq!(
            unseal_input(&seal_input(N, b"\xff\n")).unwrap().1,
            b"\xff\n"
        );
    }

    #[test]
    fn only_lines_with_the_nonce_survive() {
        let mut raw = b"case 0 pass\n#harness-start\n".to_vec();
        raw.extend(frame(N, b"#harness-start\n"));
        raw.extend_from_slice(b"#rebut ffffffffffffffffffffffffffffffff case 0 pass\n");
        raw.extend_from_slice(format!("{N} case 0 pass\n").as_bytes());
        raw.extend_from_slice(format!("x#rebut {N} case 0 pass\n").as_bytes());
        raw.extend(frame(N, b"case 0 panic\n"));
        // A truncated final line is not a complete message.
        raw.extend_from_slice(format!("#rebut {N} case 1 pass").as_bytes());
        assert_eq!(authenticated(&raw, N), b"#harness-start\ncase 0 panic\n");
        assert_eq!(authenticated(&raw, &fresh_nonce()), b"");
    }

    #[test]
    fn frame_matches_the_harness_format() {
        assert_eq!(
            frame(N, b"a\nb"),
            format!("#rebut {N} a\n#rebut {N} b\n").into_bytes()
        );
        assert_eq!(authenticated(&frame(N, b"a\nb\n"), N), b"a\nb\n");
    }
}
