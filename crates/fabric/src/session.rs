//! Host side of a guest session: send the request and source, collect
//! `StepDone` frames until `Finished`.

use tokio::io::{AsyncRead, AsyncWrite};
use verifier_core::{Digest, ExecutionRequest, StepOutcome};
use verifier_guest::protocol::{
    read_frame, write_frame, FrameError, GuestMessage, HostMessage, SourceManifest,
    SOURCE_CHUNK_SIZE,
};

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("guest reported an error: {0}")]
    Guest(String),
    #[error("protocol violation by guest: {0}")]
    Protocol(String),
}

/// Runs one session over `stream`. Outcomes are appended to `outcomes` as
/// they arrive, so a caller that times the session out keeps partial results.
pub async fn run_session<S>(
    stream: S,
    req: &ExecutionRequest,
    source_tar_gz: &[u8],
    outcomes: &mut Vec<StepOutcome>,
) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let send = async {
        let run = HostMessage::Run {
            request: req.clone(),
            source: SourceManifest {
                size: source_tar_gz.len() as u64,
                digest: Digest::of(source_tar_gz),
            },
        };
        write_frame(&mut writer, &run).await?;
        for chunk in source_tar_gz.chunks(SOURCE_CHUNK_SIZE) {
            let msg = HostMessage::SourceChunk {
                data: chunk.to_vec(),
            };
            write_frame(&mut writer, &msg).await?;
        }
        write_frame(&mut writer, &HostMessage::SourceEnd).await
    };
    let recv = async {
        loop {
            let msg: GuestMessage = read_frame(&mut reader)
                .await?
                .ok_or_else(|| SessionError::Protocol("closed before finishing".into()))?;
            match msg {
                GuestMessage::StepDone { outcome } => {
                    if outcome.step_index != outcomes.len() || outcome.step_index >= req.steps.len()
                    {
                        return Err(SessionError::Protocol(format!(
                            "unexpected step index {}",
                            outcome.step_index
                        )));
                    }
                    log_outcome(req, &outcome);
                    outcomes.push(outcome);
                }
                GuestMessage::Finished if outcomes.len() == req.steps.len() => return Ok(()),
                GuestMessage::Finished => {
                    return Err(SessionError::Protocol(format!(
                        "finished after {} of {} steps",
                        outcomes.len(),
                        req.steps.len()
                    )))
                }
                GuestMessage::Error { message } => return Err(SessionError::Guest(message)),
            }
        }
    };
    let (sent, received) = tokio::join!(send, recv);
    // The guest's answer explains more than a broken pipe on our side.
    received?;
    sent?;
    Ok(())
}

/// The only place the fabric logs a step. For sealed requests nothing but the
/// step index is logged: no output, exit code or timing may reach any log.
pub(crate) fn log_outcome(req: &ExecutionRequest, o: &StepOutcome) {
    if req.sealed {
        tracing::debug!(request = %req.id, step = o.step_index, "sealed step finished");
        return;
    }
    tracing::debug!(
        request = %req.id,
        step = o.step_index,
        exit_code = ?o.exit_code,
        timed_out = o.timed_out,
        duration_ms = o.duration_ms,
        stdout_bytes = o.stdout.len(),
        stderr_bytes = o.stderr.len(),
        "step finished"
    );
    if !o.success() {
        let tail = &o.stderr[o.stderr.len().saturating_sub(2048)..];
        tracing::trace!(request = %req.id, step = o.step_index,
            stderr_tail = %String::from_utf8_lossy(tail), "failed step stderr");
    }
}

/// Outcome recorded for steps that never ran because the VM was killed at
/// the hard deadline.
pub(crate) fn fill_timed_out(req: &ExecutionRequest, outcomes: &mut Vec<StepOutcome>) {
    for step_index in outcomes.len()..req.steps.len() {
        outcomes.push(StepOutcome {
            step_index,
            exit_code: None,
            timed_out: true,
            stdout: Vec::new(),
            stderr: Vec::new(),
            duration_ms: 0,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use verifier_core::{CommitSha, Step};

    fn req(steps: usize) -> ExecutionRequest {
        ExecutionRequest {
            id: uuid::Uuid::nil(),
            repo_url: "local".into(),
            commit: CommitSha::new("b".repeat(40)).unwrap(),
            steps: vec![Step::Test { filters: vec![] }; steps],
            timeout_secs: 5,
            vcpus: 1,
            memory_mib: 128,
            sealed: false,
            env: BTreeMap::new(),
        }
    }

    fn outcome(i: usize) -> StepOutcome {
        StepOutcome {
            step_index: i,
            exit_code: Some(0),
            timed_out: false,
            stdout: vec![],
            stderr: vec![],
            duration_ms: 1,
        }
    }

    /// Fake guest: drains the host's frames, then replies with `replies`.
    async fn fake_guest(
        replies: Vec<GuestMessage>,
        r: &ExecutionRequest,
    ) -> (Vec<StepOutcome>, Result<(), SessionError>) {
        let (host, guest) = tokio::io::duplex(1 << 20);
        let g = tokio::spawn(async move {
            let (mut gr, mut gw) = tokio::io::split(guest);
            loop {
                let m: HostMessage = read_frame(&mut gr).await.unwrap().unwrap();
                if m == HostMessage::SourceEnd {
                    break;
                }
            }
            for m in replies {
                write_frame(&mut gw, &m).await.unwrap();
            }
        });
        let mut outcomes = vec![];
        let res = run_session(host, r, &[7u8; 10_000], &mut outcomes).await;
        g.await.unwrap();
        (outcomes, res)
    }

    #[tokio::test]
    async fn collects_outcomes_in_order() {
        let r = req(2);
        let (out, res) = fake_guest(
            vec![
                GuestMessage::StepDone {
                    outcome: outcome(0),
                },
                GuestMessage::StepDone {
                    outcome: outcome(1),
                },
                GuestMessage::Finished,
            ],
            &r,
        )
        .await;
        res.unwrap();
        assert_eq!(out, vec![outcome(0), outcome(1)]);
    }

    #[tokio::test]
    async fn rejects_out_of_order_and_early_finish() {
        let r = req(2);
        let (_, res) = fake_guest(
            vec![GuestMessage::StepDone {
                outcome: outcome(1),
            }],
            &r,
        )
        .await;
        assert!(matches!(res, Err(SessionError::Protocol(_))));

        let (out, res) = fake_guest(
            vec![
                GuestMessage::StepDone {
                    outcome: outcome(0),
                },
                GuestMessage::Finished,
            ],
            &r,
        )
        .await;
        assert!(matches!(res, Err(SessionError::Protocol(_))));
        assert_eq!(out.len(), 1);
    }

    #[tokio::test]
    async fn guest_error_is_surfaced() {
        let r = req(1);
        let (_, res) = fake_guest(
            vec![GuestMessage::Error {
                message: "nope".into(),
            }],
            &r,
        )
        .await;
        assert!(matches!(res, Err(SessionError::Guest(m)) if m == "nope"));
    }

    #[test]
    fn fill_marks_missing_steps_timed_out() {
        let r = req(3);
        let mut out = vec![outcome(0)];
        fill_timed_out(&r, &mut out);
        assert_eq!(out.len(), 3);
        assert!(out[1].timed_out && out[2].timed_out);
        assert_eq!(out[2].step_index, 2);
    }
}
