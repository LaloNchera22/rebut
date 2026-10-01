//! GitHub App implementation of [`Forge`].
//!
//! Auth: an RS256 JWT signed with the App's private key is exchanged for a
//! per-installation access token (cached until shortly before it expires).

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{bail, Context};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use verifier_core::{CommitSha, RepoId};

use crate::forge::{CheckRun, Forge};

pub const DEFAULT_API: &str = "https://api.github.com";

pub struct GitHubForge {
    app_id: u64,
    key: EncodingKey,
    api: String,
    http: reqwest::Client,
    tokens: Mutex<HashMap<RepoId, (String, OffsetDateTime)>>,
}

#[derive(Serialize)]
struct Claims {
    iat: i64,
    exp: i64,
    iss: String,
}

#[derive(Deserialize)]
struct Installation {
    id: u64,
}

#[derive(Deserialize)]
struct AccessToken {
    token: String,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

impl GitHubForge {
    pub fn new(
        app_id: u64,
        private_key_pem: &[u8],
        api: impl Into<String>,
    ) -> anyhow::Result<Self> {
        Ok(GitHubForge {
            app_id,
            key: EncodingKey::from_rsa_pem(private_key_pem).context("invalid GitHub App key")?,
            api: api.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .user_agent("rebut-verifier")
                .build()?,
            tokens: Mutex::new(HashMap::new()),
        })
    }

    fn app_jwt(&self) -> anyhow::Result<String> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        // Backdated to tolerate clock drift; GitHub caps lifetime at 10 minutes.
        let claims = Claims {
            iat: now - 60,
            exp: now + 540,
            iss: self.app_id.to_string(),
        };
        Ok(jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &self.key,
        )?)
    }

    fn request(&self, req: RequestBuilder, bearer: &str) -> RequestBuilder {
        req.bearer_auth(bearer)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
    }

    async fn installation_token(&self, repo: &RepoId) -> anyhow::Result<String> {
        let fresh_until = OffsetDateTime::now_utc() + time::Duration::minutes(5);
        if let Some((token, exp)) = self.tokens.lock().expect("token lock").get(repo) {
            if *exp > fresh_until {
                return Ok(token.clone());
            }
        }
        let jwt = self.app_jwt()?;
        let url = format!(
            "{}/repos/{}/{}/installation",
            self.api, repo.owner, repo.name
        );
        let inst: Installation = self
            .request(self.http.get(url), &jwt)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let url = format!("{}/app/installations/{}/access_tokens", self.api, inst.id);
        let tok: AccessToken = self
            .request(self.http.post(url), &jwt)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        self.tokens
            .lock()
            .expect("token lock")
            .insert(repo.clone(), (tok.token.clone(), tok.expires_at));
        Ok(tok.token)
    }
}

#[async_trait::async_trait]
impl Forge for GitHubForge {
    async fn file_at(
        &self,
        repo: &RepoId,
        commit: &CommitSha,
        path: &str,
    ) -> anyhow::Result<Option<String>> {
        let token = self.installation_token(repo).await?;
        let url = format!(
            "{}/repos/{}/{}/contents/{}",
            self.api, repo.owner, repo.name, path
        );
        let resp = self
            .request(self.http.get(url), &token)
            .header("Accept", "application/vnd.github.raw+json")
            .query(&[("ref", commit.as_str())])
            .send()
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(resp.error_for_status()?.text().await?))
    }

    async fn publish_check_run(&self, repo: &RepoId, run: &CheckRun) -> anyhow::Result<()> {
        let token = self.installation_token(repo).await?;
        let url = format!("{}/repos/{}/{}/check-runs", self.api, repo.owner, repo.name);
        let mut body = serde_json::json!({
            "name": run.name,
            "head_sha": run.head_sha.as_str(),
            "status": "completed",
            "conclusion": run.conclusion,
            "output": { "title": run.title, "summary": run.summary },
        });
        if let Some(u) = &run.details_url {
            body["details_url"] = u.clone().into();
        }
        let resp = self
            .request(self.http.post(url), &token)
            .json(&body)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            bail!(
                "check run rejected ({status}): {}",
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_rsa_key() {
        assert!(GitHubForge::new(1, b"not a key", DEFAULT_API).is_err());
    }

    #[test]
    fn conclusion_serializes_like_github() {
        assert_eq!(
            serde_json::to_value(crate::forge::Conclusion::Neutral).unwrap(),
            "neutral"
        );
    }
}
