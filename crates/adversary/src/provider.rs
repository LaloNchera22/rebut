//! Choosing a hypothesis generator from a CLI flag or environment variable.
//!
//! The rival agent is off unless asked for (ADR-9). When it is on, a local
//! model is the expected choice: `ollama[:model]`, or any OpenAI-compatible
//! server with `openai-compat`. `anthropic` uses the hosted API and needs
//! `ANTHROPIC_API_KEY`.

use std::sync::Arc;

use crate::openai::{DEFAULT_LOCAL_MODEL, OLLAMA_URL};
use crate::{AnthropicGenerator, HypothesisGenerator, OpenAiCompatGenerator};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Ollama,
    OpenAiCompat,
    Anthropic,
}

/// A parsed `--adversary` choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdversaryConfig {
    pub provider: Provider,
    pub url: Option<String>,
    pub model: Option<String>,
}

impl AdversaryConfig {
    /// Parse `spec` (`ollama[:model]`, `openai-compat[:model]`,
    /// `anthropic[:model]`, or `off`/`none`). A model in `spec` wins over
    /// `model`. `Ok(None)` means the rival agent stays off.
    pub fn parse(
        spec: &str,
        url: Option<String>,
        model: Option<String>,
    ) -> anyhow::Result<Option<Self>> {
        let spec = spec.trim();
        let (name, inline_model) = match spec.split_once(':') {
            Some((n, m)) if !m.is_empty() => (n, Some(m.to_string())),
            Some((n, _)) => (n, None),
            None => (spec, None),
        };
        let provider = match name.to_ascii_lowercase().as_str() {
            "" | "off" | "none" | "false" | "0" => return Ok(None),
            "ollama" => Provider::Ollama,
            "openai-compat" | "openai-compatible" | "openai" => Provider::OpenAiCompat,
            "anthropic" => Provider::Anthropic,
            other => anyhow::bail!(
                "unknown adversary provider {other:?} (expected ollama[:model], openai-compat or anthropic)"
            ),
        };
        let model = inline_model.or(model).filter(|m| !m.trim().is_empty());
        let url = url.filter(|u| !u.trim().is_empty());
        if provider == Provider::OpenAiCompat {
            anyhow::ensure!(
                url.is_some(),
                "--adversary openai-compat needs --adversary-url (e.g. http://localhost:8080/v1)"
            );
            anyhow::ensure!(
                model.is_some(),
                "--adversary openai-compat needs --adversary-model"
            );
        }
        Ok(Some(AdversaryConfig {
            provider,
            url,
            model,
        }))
    }

    /// One line for logs: provider, model and endpoint.
    pub fn describe(&self) -> String {
        match self.provider {
            Provider::Ollama => format!(
                "ollama {} at {}",
                self.model.as_deref().unwrap_or(DEFAULT_LOCAL_MODEL),
                self.url.as_deref().unwrap_or(OLLAMA_URL)
            ),
            Provider::OpenAiCompat => format!(
                "openai-compat {} at {}",
                self.model.as_deref().unwrap_or_default(),
                self.url.as_deref().unwrap_or_default()
            ),
            Provider::Anthropic => format!(
                "anthropic {}",
                self.model.as_deref().unwrap_or(crate::DEFAULT_MODEL)
            ),
        }
    }

    /// Build the generator. Only configuration errors fail here (a missing
    /// API key); an unreachable server is found by
    /// [`HypothesisGenerator::ready`].
    pub fn build(&self) -> anyhow::Result<Arc<dyn HypothesisGenerator>> {
        Ok(match self.provider {
            Provider::Ollama | Provider::OpenAiCompat => {
                let mut g = OpenAiCompatGenerator::new(
                    self.url.as_deref().unwrap_or(OLLAMA_URL),
                    self.model.as_deref().unwrap_or(DEFAULT_LOCAL_MODEL),
                );
                if let Ok(k) = std::env::var("REBUT_ADVERSARY_API_KEY") {
                    g = g.with_api_key(k);
                }
                Arc::new(g)
            }
            Provider::Anthropic => {
                let mut g = AnthropicGenerator::from_env()?;
                if let Some(m) = &self.model {
                    g.model = m.clone();
                }
                if let Some(u) = &self.url {
                    g.base_url = u.clone();
                }
                Arc::new(g)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(spec: &str, url: Option<&str>, model: Option<&str>) -> Option<AdversaryConfig> {
        AdversaryConfig::parse(spec, url.map(Into::into), model.map(Into::into)).unwrap()
    }

    #[test]
    fn parses_provider_specs() {
        for off in ["", "off", "none", "OFF"] {
            assert_eq!(parse(off, None, None), None);
        }
        let c = parse("ollama", None, None).unwrap();
        assert_eq!(c.provider, Provider::Ollama);
        assert_eq!(
            c.describe(),
            "ollama qwen2.5-coder:7b at http://localhost:11434/v1"
        );
        // Ollama tags contain ':' themselves.
        let c = parse("ollama:llama3.1:8b", None, Some("ignored")).unwrap();
        assert_eq!(c.model.as_deref(), Some("llama3.1:8b"));
        let c = parse(
            "openai-compat",
            Some("http://127.0.0.1:8080/v1"),
            Some("qwen"),
        )
        .unwrap();
        assert_eq!(c.provider, Provider::OpenAiCompat);
        assert_eq!(
            c.describe(),
            "openai-compat qwen at http://127.0.0.1:8080/v1"
        );
        assert_eq!(
            parse("anthropic", None, None).unwrap().provider,
            Provider::Anthropic
        );

        assert!(AdversaryConfig::parse("openai-compat", None, Some("m".into())).is_err());
        assert!(AdversaryConfig::parse("openai-compat", Some("http://x/v1".into()), None).is_err());
        assert!(AdversaryConfig::parse("gpt", None, None).is_err());
    }

    #[test]
    fn local_providers_build_without_keys() {
        let g = parse("ollama", None, None).unwrap().build();
        assert!(g.is_ok());
    }
}
