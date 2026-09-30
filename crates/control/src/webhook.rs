//! `POST /webhooks/github`: signature check, then enqueue.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use verifier_core::{CommitSha, PullRequest, RepoId};

use crate::api::AppState;
use crate::queue::Enqueued;

/// Verify `X-Hub-Signature-256: sha256=<hex>` over the raw body, in constant time.
pub fn verify_signature(secret: &[u8], body: &[u8], header: Option<&str>) -> bool {
    let Some(sig) = header
        .and_then(|h| h.strip_prefix("sha256="))
        .and_then(|h| hex::decode(h).ok())
    else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    mac.verify_slice(&sig).is_ok()
}

#[derive(Deserialize)]
struct PullRequestEvent {
    action: String,
    pull_request: PrPayload,
    repository: RepoPayload,
}

#[derive(Deserialize)]
struct PrPayload {
    number: u64,
    #[serde(default)]
    body: Option<String>,
    user: UserPayload,
    head: RefPayload,
    base: RefPayload,
}

#[derive(Deserialize)]
struct RefPayload {
    sha: String,
    /// Null when the fork was deleted.
    repo: Option<RefRepo>,
}

#[derive(Deserialize)]
struct RefRepo {
    clone_url: String,
}

#[derive(Deserialize)]
struct RepoPayload {
    name: String,
    owner: UserPayload,
    clone_url: String,
}

#[derive(Deserialize)]
struct UserPayload {
    login: String,
}

/// Parse a `pull_request` event. `Ok(None)` for actions that need no run.
pub fn parse_pull_request(body: &[u8]) -> anyhow::Result<Option<PullRequest>> {
    let ev: PullRequestEvent = serde_json::from_slice(body)?;
    if !matches!(ev.action.as_str(), "opened" | "synchronize" | "reopened") {
        return Ok(None);
    }
    let pr = ev.pull_request;
    let base_clone_url = pr
        .base
        .repo
        .map(|r| r.clone_url)
        .unwrap_or(ev.repository.clone_url);
    Ok(Some(PullRequest {
        repo: RepoId {
            owner: ev.repository.owner.login,
            name: ev.repository.name,
        },
        number: pr.number,
        base_sha: CommitSha::new(pr.base.sha).map_err(anyhow::Error::msg)?,
        head_sha: CommitSha::new(pr.head.sha).map_err(anyhow::Error::msg)?,
        // A deleted fork's head is still reachable as refs/pull/N/head on base.
        head_clone_url: pr
            .head
            .repo
            .map(|r| r.clone_url)
            .unwrap_or_else(|| base_clone_url.clone()),
        base_clone_url,
        author: pr.user.login,
        body: pr.body.unwrap_or_default(),
    }))
}

pub async fn github(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if !verify_signature(&state.webhook_secret, &body, header("x-hub-signature-256")) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if header("x-github-event") != Some("pull_request") {
        return StatusCode::NO_CONTENT.into_response();
    }
    let pr = match parse_pull_request(&body) {
        Ok(Some(pr)) => pr,
        Ok(None) => return StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "malformed pull_request payload");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    match state.queue.enqueue(pr).await {
        Ok(outcome) => {
            let duplicate = matches!(outcome, Enqueued::Duplicate(_));
            tracing::info!(job = %outcome.id(), duplicate, "pull request enqueued");
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({ "job_id": outcome.id(), "duplicate": duplicate })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "enqueue failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}
