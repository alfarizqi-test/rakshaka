use std::time::Duration;
use reqwest::Client;
use serde_json::Value;

pub struct LinkCheckerService {
    client: Client,
    api_key: String,
    api_url: String,
}

impl LinkCheckerService {
    pub fn new(api_key: String, api_url: String) -> Self {
        // PERBAIKAN 1: Menyamar sebagai Browser Google Chrome agar tidak diblokir oleh website
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .build()
            .expect("Failed to build HTTP client");

        Self { client, api_key, api_url }
    }

    async fn fetch_website_content(&self, url: &str) -> String {
        match self.client.get(url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.text().await {
                        Ok(text) => {
                            let max_len = std::cmp::min(text.len(), 5000);
                            text[..max_len].to_string()
                        },
                        Err(_) => "Error: Failed to read website body.".to_string()
                    }
                } else {
                    format!("Error: Website returned HTTP status code {}", response.status())
                }
            },
            Err(e) => format!("Error: Failed to fetch website. Reason: {}", e)
        }
    }

    pub async fn check_url(&self, url: &str) -> Result<Value, LinkCheckerError> {
        if self.api_url.is_empty() || self.api_key.is_empty() {
            return Err(LinkCheckerError::NotConfigured);
        }

        let website_content = self.fetch_website_content(url).await;

        let prompt = format!(
            "You are a cybersecurity URL analysis engine. \
            Analyze the following URL and its website HTML content for threats such as phishing, scam, malware, judol (illegal gambling), or other malicious activity. \
            \n\n\
            URL TO ANALYZE: {}\n\n\
            WEBSITE CONTENT PREVIEW (First 5000 chars):\n\
            {}\n\n\
            CRITICAL RULES:\n\
            1. 'status' MUST be exactly one of these values: \"safe\", \"suspicious\", \"malicious\", or \"judol\".\n\
            2. 'score' MUST be an integer between 0 and 100. DO NOT use null. Give 0 ONLY if you are absolutely sure it is safe based on the content.\n\
            3. 'reason' MUST be a brief string explaining the judgment based on BOTH the URL name and the website content provided.\n\
            4. Output ONLY valid JSON without any markdown formatting or backticks. Start your response directly with {{ and end with }}.\n",
            url, website_content
        );

        let endpoint = format!("{}?key={}", self.api_url, self.api_key);

        let response = self
            .client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "contents": [{
                    "parts": [{ "text": prompt }]
                }],
                "generationConfig": {
                    "temperature": 0.0,
                    "maxOutputTokens": 1024, // PERBAIKAN 2: Dinaikkan agar balasan JSON tidak terpotong
                    "responseMimeType": "application/json"
                }
            }))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    LinkCheckerError::Timeout
                } else {
                    LinkCheckerError::RequestFailed(e.to_string())
                }
            })?;

        let http_status = response.status();
        if !http_status.is_success() {
            let body = response.text().await.unwrap_or_default();
            tracing::error!("Gemini API error {}: {}", http_status, body);
            return Err(LinkCheckerError::ApiError(format!(
                "AI API returned status {}",
                http_status.as_u16()
            )));
        }

        let raw: Value = response
            .json()
            .await
            .map_err(|e| LinkCheckerError::ParseError(e.to_string()))?;

        let mut text = raw
            .pointer("/candidates/0/content/parts/0/text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();

        // PERBAIKAN 3: Ekstraksi JSON yang jauh lebih aman (Mencari tanda kurung kurawal pertama { dan terakhir })
        if let Some(start_idx) = text.find('{') {
            if let Some(end_idx) = text.rfind('}') {
                if start_idx <= end_idx {
                    text = text[start_idx..=end_idx].to_string();
                }
            }
        }

        let parsed: Value = serde_json::from_str(&text).unwrap_or_else(|_| {
            tracing::warn!("Gemini returned non-JSON text unexpectedly: {}", text);
            serde_json::json!({
                "status": "unknown",
                "score": 0,
                "reason": text
            })
        });

        Ok(parsed)
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
