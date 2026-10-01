//! HTTP surface: webhooks, receipts, contributor reports, log entries, and a
//! maintainer-only verdict endpoint.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rebut_core::RepoId;
use rebut_receipts::TransparencyLog;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::queue::JobQueue;
use crate::store::Store;

#[derive(Clone)]
pub struct AppState {
    pub queue: Arc<dyn JobQueue>,
    pub store: Arc<dyn Store>,
    pub log: Arc<dyn TransparencyLog>,
    pub webhook_secret: Arc<[u8]>,
    /// Bearer token for the full-verdict endpoint; `None` disables it.
    pub maintainer_token: Option<Arc<str>>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/webhooks/github", post(crate::webhook::github))
        .route("/v1/receipts/:id", get(receipt))
        .route("/v1/prs/:owner/:repo/:number/report", get(report))
        .route("/v1/prs/:owner/:repo/:number/verdict", get(verdict))
        .route("/v1/log/:index", get(log_entry))
        .with_state(state)
}

/// Internal errors are logged, not echoed to the client.
struct ApiError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(e.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        tracing::error!(error = %format!("{:#}", self.0), "request failed");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

type ApiResult = Result<Response, ApiError>;

fn found<T: serde::Serialize>(v: Option<T>) -> Response {
    match v {
        Some(v) => Json(v).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn receipt(State(s): State<AppState>, Path(id): Path<Uuid>) -> ApiResult {
    Ok(found(s.store.receipt(id).await?))
}

/// Contributor view only: never the full verdict.
async fn report(
    State(s): State<AppState>,
    Path((owner, name, number)): Path<(String, String, u64)>,
) -> ApiResult {
    let run = s.store.latest_run(&RepoId { owner, name }, number).await?;
    Ok(found(run.map(|r| r.verdict.for_contributor())))
}

/// Full verdict, sealed reproductions included.
///
/// Sketch: a single operator-wide bearer token. A real deployment should
/// check that the caller is a maintainer of *this* repository on the forge.
async fn verdict(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path((owner, name, number)): Path<(String, String, u64)>,
) -> ApiResult {
    if !maintainer_authorized(s.maintainer_token.as_deref(), &headers) {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    let run = s.store.latest_run(&RepoId { owner, name }, number).await?;
    Ok(found(run.map(|r| r.verdict)))
}

fn maintainer_authorized(expected: Option<&str>, headers: &HeaderMap) -> bool {
    let (Some(expected), Some(given)) = (
        expected,
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer ")),
    ) else {
        return false;
    };
    !expected.is_empty() && bool::from(expected.as_bytes().ct_eq(given.as_bytes()))
}

async fn log_entry(State(s): State<AppState>, Path(index): Path<u64>) -> ApiResult {
    Ok(found(s.log.get(index).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::InMemoryQueue;
    use crate::store::{InMemoryStore, RunRecord};
    use crate::webhook::verify_signature;
    use axum::body::Body;
    use axum::http::Request;
    use hmac::{Hmac, Mac};
    use rebut_core::*;
    use rebut_receipts::{Ed25519Signer, InMemoryLog};
    use tower::ServiceExt;

    const SECRET: &[u8] = b"It's a Secret to Everybody";

    fn state() -> (AppState, Arc<InMemoryQueue>, Arc<InMemoryStore>) {
        let queue = Arc::new(InMemoryQueue::default());
        let store = Arc::new(InMemoryStore::default());
        let st = AppState {
            queue: queue.clone(),
            store: store.clone(),
            log: Arc::new(InMemoryLog::new(Arc::new(Ed25519Signer::generate()))),
            webhook_secret: SECRET.into(),
            maintainer_token: Some("maint".into()),
        };
        (st, queue, store)
    }

    fn sign(body: &[u8]) -> String {
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    fn payload(action: &str) -> Vec<u8> {
        serde_json::json!({
            "action": action,
            "number": 5,
            "pull_request": {
                "number": 5,
                "body": "```rebut-intent\nkind = \"refactor\"\n```",
                "user": { "login": "contributor" },
                "head": { "sha": "b".repeat(40), "repo": { "clone_url": "https://github.com/fork/lib.git" } },
                "base": { "sha": "a".repeat(40), "repo": { "clone_url": "https://github.com/acme/lib.git" } }
            },
            "repository": {
                "name": "lib", "owner": { "login": "acme" },
                "clone_url": "https://github.com/acme/lib.git"
            },
            "installation": { "id": 1 }
        })
        .to_string()
        .into_bytes()
    }

    async fn post(app: &Router, event: &str, body: Vec<u8>, sig: Option<String>) -> StatusCode {
        let mut req = Request::post("/webhooks/github").header("x-github-event", event);
        if let Some(sig) = sig {
            req = req.header("x-hub-signature-256", sig);
        }
        app.clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[test]
    fn signature_known_answer() {
        // Example from GitHub's "Validating webhook deliveries" documentation.
        assert!(verify_signature(
            SECRET,
            b"Hello, World!",
            Some("sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17")
        ));
        assert!(!verify_signature(
            SECRET,
            b"Hello, World!",
            Some("sha256=00")
        ));
        assert!(!verify_signature(SECRET, b"Hello, World!", Some("zzz")));
        assert!(!verify_signature(SECRET, b"Hello, World!", None));
    }

    #[tokio::test]
    async fn webhook_accepts_valid_and_rejects_invalid() {
        let (st, queue, _) = state();
        let app = router(st);
        let body = payload("opened");

        assert_eq!(
            post(&app, "pull_request", body.clone(), None).await,
            StatusCode::UNAUTHORIZED
        );
        let mut tampered = body.clone();
        tampered[10] ^= 1;
        assert_eq!(
            post(&app, "pull_request", tampered, Some(sign(&body))).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(queue.counts().0, 0);

        assert_eq!(
            post(&app, "pull_request", body.clone(), Some(sign(&body))).await,
            StatusCode::ACCEPTED
        );
        // Re-delivery of the same webhook does not create a second job.
        assert_eq!(
            post(&app, "pull_request", body.clone(), Some(sign(&body))).await,
            StatusCode::ACCEPTED
        );
        assert_eq!(queue.counts().0, 1);

        let closed = payload("closed");
        assert_eq!(
            post(&app, "pull_request", closed.clone(), Some(sign(&closed))).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            post(&app, "issues", body.clone(), Some(sign(&body))).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(queue.counts().0, 1);
    }

    #[tokio::test]
    async fn parsed_pull_request_fields() {
        let pr = crate::webhook::parse_pull_request(&payload("synchronize"))
            .unwrap()
            .unwrap();
        assert_eq!(pr.repo.to_string(), "acme/lib");
        assert_eq!(pr.number, 5);
        assert_eq!(pr.head_sha.as_str(), "b".repeat(40));
        assert_eq!(pr.head_clone_url, "https://github.com/fork/lib.git");
        assert!(IntentManifest::from_pr_body(&pr.body).is_some());
    }

    #[tokio::test]
    async fn report_hides_sealed_and_verdict_needs_token() {
        let (st, _, store) = state();
        let pr = crate::queue::tests::pr(9, 'b');
        let verdict = Verdict {
            pr,
            seed: None,
            engines_run: vec![EngineKind::Challenges],
            findings: vec![crate::forge::tests::finding(
                Visibility::Sealed,
                b"SEALED-SECRET",
                false,
            )],
            inconclusive_reason: None,
            mode: EnforcementMode::Mark,
        };
        let signer = Ed25519Signer::generate();
        let envelope = rebut_receipts::Envelope::sign("t", b"{}", &signer)
            .await
            .unwrap();
        let id = Uuid::new_v4();
        store
            .save_run(&RunRecord {
                id,
                job_id: Uuid::new_v4(),
                verdict,
                envelope,
                log_index: 0,
                created_at: time::OffsetDateTime::now_utc(),
            })
            .await
            .unwrap();
        let app = router(st);
        let get = |uri: String, auth: Option<&'static str>| {
            let app = app.clone();
            async move {
                let mut req = Request::get(uri);
                if let Some(a) = auth {
                    req = req.header("authorization", a);
                }
                let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap();
                (status, String::from_utf8(bytes.to_vec()).unwrap())
            }
        };

        let (status, body) = get("/v1/prs/acme/lib/9/report".into(), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body.contains("SEALED-SECRET"));
        assert!(body.contains("integer-overflow"));

        let uri = "/v1/prs/acme/lib/9/verdict".to_string();
        assert_eq!(get(uri.clone(), None).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(
            get(uri.clone(), Some("Bearer wrong")).await.0,
            StatusCode::UNAUTHORIZED
        );
        let (status, body) = get(uri, Some("Bearer maint")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("integer-overflow"));

        assert_eq!(
            get(format!("/v1/receipts/{id}"), None).await.0,
            StatusCode::OK
        );
        assert_eq!(
            get(format!("/v1/receipts/{}", Uuid::new_v4()), None)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(get("/v1/log/0".into(), None).await.0, StatusCode::NOT_FOUND);
        assert_eq!(get("/healthz".into(), None).await.0, StatusCode::OK);
    }
}
