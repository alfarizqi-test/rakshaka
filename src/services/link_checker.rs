use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize)]
struct ExternalCheckRequest {
    url: String,
}

#[derive(Debug, Deserialize)]
pub struct ExternalCheckResponse {
    pub status: Option<String>,
    pub score: Option<i64>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

pub struct LinkCheckerService {
    client: Client,
    api_key: String,
    api_url: String,
}

impl LinkCheckerService {
    pub fn new(api_key: String, api_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("Failed to build HTTP client");

        Self { client, api_key, api_url }
    }

    pub async fn check_url(&self, url: &str) -> Result<serde_json::Value, LinkCheckerError> {
        if self.api_url.is_empty() {
            return Err(LinkCheckerError::NotConfigured);
        }

        let response = self
            .client
            .post(&self.api_url)
            .header("X-API-Key", &self.api_key)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&ExternalCheckRequest { url: url.to_string() })
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    LinkCheckerError::Timeout
                } else {
                    LinkCheckerError::RequestFailed(e.to_string())
                }
            })?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            return Err(LinkCheckerError::ApiError(format!("API returned status {}", status)));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| LinkCheckerError::ParseError(e.to_string()))?;

        Ok(body)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LinkCheckerError {
    #[error("Link checker API is not configured")]
    NotConfigured,

    #[error("Request timed out")]
    Timeout,

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("Failed to parse response: {0}")]
    ParseError(String),
}
