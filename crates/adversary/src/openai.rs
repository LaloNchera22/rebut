//! [`HypothesisGenerator`] for any OpenAI-compatible chat completions
//! endpoint: Ollama (`http://localhost:11434/v1`), llama.cpp's `llama-server`,
//! LM Studio, vLLM. This is how the rival agent runs on a local model, free.
//!
//! Local models are weaker and sloppier than a hosted frontier model, so the
//! answer goes through [`parse_hypotheses_lenient`] and any failure (server
//! down, HTTP error, unparsable answer) yields zero hypotheses at worst. ADR-6
//! is what makes that trade acceptable: a weaker model proposes fewer inputs
//! that reproduce; it cannot produce a finding that doesn't.

use std::time::Duration;

use rebut_core::{EngineContext, Hypothesis};
use serde::Deserialize;
use serde_json::json;

use crate::prompt::{self, parse_hypotheses_lenient};
use crate::HypothesisGenerator;

pub const OLLAMA_URL: &str = "http://localhost:11434/v1";
pub const DEFAULT_LOCAL_MODEL: &str = "qwen2.5-coder:7b";

pub struct OpenAiCompatGenerator {
    client: reqwest::Client,
    /// Base URL including the version segment, e.g. `http://localhost:11434/v1`.
    pub base_url: String,
    pub model: String,
    /// Sent as a bearer token when set (vLLM `--api-key`, hosted gateways).
    api_key: Option<String>,
    pub max_tokens: u32,
    pub max_hypotheses: usize,
    pub max_input_bytes: usize,
}

impl std::fmt::Debug for OpenAiCompatGenerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiCompatGenerator")
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// Local generation on a laptop CPU is slow; this bounds a whole answer.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// A loopback server must not be sent through `HTTP(S)_PROXY`.
fn client_for(base_url: &str) -> reqwest::Client {
    let loopback = reqwest::Url::parse(base_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .is_some_and(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]");
    let mut b = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT);
    if loopback {
        b = b.no_proxy();
    }
    b.build().unwrap_or_default()
}

impl OpenAiCompatGenerator {
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        let base_url = base_url.into();
        Self::with_client(client_for(&base_url), base_url, model)
    }

    pub fn with_client(
        client: reqwest::Client,
        base_url: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        OpenAiCompatGenerator {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            model: model.into(),
            api_key: None,
            max_tokens: 4096,
            max_hypotheses: 8,
            max_input_bytes: 64 * 1024,
        }
    }

    /// Ollama on its default port.
    pub fn ollama(model: impl Into<String>) -> Self {
        Self::new(OLLAMA_URL, model)
    }

    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// The request body (exposed for tests and audit logs). `json_mode` asks
    /// for `response_format: json_object`, which not every server accepts.
    pub fn request_body(&self, ctx: &EngineContext, json_mode: bool) -> serde_json::Value {
        let mut body = json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0.2,
            "stream": false,
            "messages": [
                { "role": "system", "content": prompt::SYSTEM_PROMPT },
                { "role": "user", "content": prompt::user_prompt(ctx, &prompt::untrusted_tag(), true) }
            ]
        });
        if json_mode {
            body["response_format"] = json!({ "type": "json_object" });
        }
        body
    }

    fn post(&self, url: &str, body: &serde_json::Value) -> reqwest::RequestBuilder {
        let req = self.client.post(url).json(body);
        match &self.api_key {
            Some(k) => req.bearer_auth(k),
            None => req,
        }
    }
}

#[derive(Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChatMessage,
}

#[derive(Deserialize)]
struct ChatMessage {
    #[serde(default)]
    content: Option<String>,
}

#[async_trait::async_trait]
impl HypothesisGenerator for OpenAiCompatGenerator {
    async fn ready(&self) -> anyhow::Result<()> {
        let mut req = self
            .client
            .get(format!("{}/models", self.base_url))
            .timeout(Duration::from_secs(5));
        if let Some(k) = &self.api_key {
            req = req.bearer_auth(k);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{} is not reachable: {e}", self.base_url))?;
        if !resp.status().is_success() {
            anyhow::bail!("{}/models returned {}", self.base_url, resp.status());
        }
        Ok(())
    }

    async fn propose(&self, ctx: &EngineContext) -> anyhow::Result<Vec<Hypothesis>> {
        if ctx.plan.changed_functions.is_empty() {
            return Ok(vec![]);
        }
        let url = format!("{}/chat/completions", self.base_url);
        let mut resp = self
            .post(&url, &self.request_body(ctx, true))
            .send()
            .await?;
        // Some servers (LM Studio, older llama.cpp) reject `json_object`; the
        // prompt spells out the format anyway, so retry without it.
        if resp.status().is_client_error() && resp.status() != reqwest::StatusCode::NOT_FOUND {
            tracing::debug!(status = %resp.status(), "retrying without response_format");
            resp = self
                .post(&url, &self.request_body(ctx, false))
                .send()
                .await?;
        }
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "{url} returned {status}: {}",
                body.chars().take(500).collect::<String>()
            );
        }
        let api: ChatResponse = resp.json().await?;
        let text = api
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .unwrap_or_default();
        Ok(parse_hypotheses_lenient(
            &text,
            &prompt::allowed_targets(ctx),
            self.max_hypotheses,
            self.max_input_bytes,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rebut_core::Engine as _;
    use std::sync::{Arc, Mutex};

    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::{get, post},
        Json, Router,
    };

    type Seen = Arc<Mutex<Vec<(HeaderMap, serde_json::Value)>>>;

    #[derive(Clone)]
    struct Mock {
        seen: Seen,
        /// Assistant message content to answer with.
        answer: String,
        /// Reject requests carrying `response_format` (LM Studio style).
        reject_json_mode: bool,
    }

    async fn chat(
        State(m): State<Mock>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let json_mode = body.get("response_format").is_some();
        m.seen.lock().unwrap().push((headers, body));
        if m.reject_json_mode && json_mode {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "'response_format.type' must be 'json_schema'"})),
            );
        }
        (
            StatusCode::OK,
            Json(json!({
                "id": "chatcmpl-1", "object": "chat.completion", "model": "qwen2.5-coder:7b",
                "choices": [{
                    "index": 0, "finish_reason": "stop",
                    "message": {"role": "assistant", "content": m.answer}
                }],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20}
            })),
        )
    }

    async fn serve(answer: &str, reject_json_mode: bool) -> (String, Seen) {
        let seen: Seen = Default::default();
        let app = Router::new()
            .route("/v1/chat/completions", post(chat))
            .route("/v1/models", get(|| async { Json(json!({"data": []})) }))
            .with_state(Mock {
                seen: seen.clone(),
                answer: answer.to_string(),
                reject_json_mode,
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}/v1"), seen)
    }

    fn ctx() -> EngineContext {
        crate::tests::ctx(Arc::new(NoExec))
    }

    #[tokio::test]
    async fn calls_chat_completions_and_parses_a_sloppy_answer() {
        let answer = "Here you go:\n```json\n{\"hypotheses\": [{\"target\": \"mylib::parse::header\", \"claim\": \"magic byte\", \"input_encoding\": \"hex\", \"input\": \"ff\"},]}\n```";
        let (url, seen) = serve(answer, false).await;
        let g = OpenAiCompatGenerator::new(&url, DEFAULT_LOCAL_MODEL).with_api_key("k");
        g.ready().await.unwrap();
        let hs = g.propose(&ctx()).await.unwrap();
        assert_eq!(hs.len(), 1);
        assert_eq!(hs[0].candidate_input.as_deref(), Some(&[0xFF][..]));

        let seen = seen.lock().unwrap();
        let (headers, body) = &seen[0];
        assert_eq!(headers["authorization"], "Bearer k");
        assert_eq!(body["model"], "qwen2.5-coder:7b");
        assert_eq!(body["stream"], false);
        assert_eq!(body["response_format"]["type"], "json_object");
        assert_eq!(body["messages"][0]["role"], "system");
        let prompt = body["messages"][1]["content"].as_str().unwrap();
        assert!(prompt.contains("mylib::parse::header(&[u8]) -> usize"));
        assert!(prompt.contains("untrusted data"));
        assert!(prompt.contains("Answer with a single JSON object"));
    }

    #[tokio::test]
    async fn retries_without_json_mode_when_rejected() {
        let answer = r#"{"hypotheses":[{"target":"mylib::parse::header","claim":"c","input_encoding":"utf8","input":"x"}]}"#;
        let (url, seen) = serve(answer, true).await;
        let hs = OpenAiCompatGenerator::new(&url, "m")
            .propose(&ctx())
            .await
            .unwrap();
        assert_eq!(hs.len(), 1);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen[1].1.get("response_format").is_none());
        assert!(seen[0].0.get("authorization").is_none());
    }

    #[tokio::test]
    async fn garbage_answer_is_zero_hypotheses() {
        let (url, _) = serve("I'm sorry, I can't analyze this code.", false).await;
        let hs = OpenAiCompatGenerator::new(&url, "m")
            .propose(&ctx())
            .await
            .unwrap();
        assert!(hs.is_empty());
    }

    #[tokio::test]
    async fn unreachable_server_is_reported_by_ready() {
        // Bind then drop: nothing listens on this port any more.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let g = OpenAiCompatGenerator::new(format!("http://127.0.0.1:{port}/v1"), "m");
        let e = g.ready().await.unwrap_err();
        assert!(e.to_string().contains("not reachable"), "{e}");
        // And a run with it degrades to an empty report, not an error.
        let r = crate::AdversaryEngine::new(Arc::new(g))
            .run(&ctx())
            .await
            .unwrap();
        assert!(r.inconclusive.is_none());
        assert!(r.findings.is_empty() && r.unreproduced.is_empty());
    }

    struct NoExec;
    #[async_trait::async_trait]
    impl rebut_core::Executor for NoExec {
        async fn execute(
            &self,
            _: rebut_core::ExecutionRequest,
        ) -> anyhow::Result<rebut_core::ExecutionResult> {
            anyhow::bail!("unused")
        }
    }
}
