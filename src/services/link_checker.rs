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
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("Failed to build HTTP client");

        Self { client, api_key, api_url }
    }

    /// Fungsi bantuan untuk mengambil konten website terlebih dahulu
    async fn fetch_website_content(&self, url: &str) -> String {
        match self.client.get(url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.text().await {
                        Ok(text) => {
                            // Ambil maksimal 5000 karakter pertama agar tidak memberatkan request ke Gemini
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

    /// Call the Gemini API and parse its response into a flat analysis object.
    /// Returns a JSON value with at minimum: { status, score, reason }.
    pub async fn check_url(&self, url: &str) -> Result<Value, LinkCheckerError> {
        if self.api_url.is_empty() || self.api_key.is_empty() {
            return Err(LinkCheckerError::NotConfigured);
        }

        // 1. Ambil konten website terlebih dahulu dari URL (Scraping dasar)
        let website_content = self.fetch_website_content(url).await;

        // 2. Gabungkan URL dan konten web ke dalam prompt untuk Gemini
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
            4. Output ONLY valid JSON without any markdown formatting or backticks.\n",
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
                    "maxOutputTokens": 256,
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

        let text = raw
            .pointer("/candidates/0/content/parts/0/text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();

        // 3. Membersihkan markdown format ```json ... ``` dan teks awalan (Anti Error)
        let mut json_str = text;
        if let Some(start) = json_str.find("```json") {
            json_str = &json_str[start + 7..];
            if let Some(end) = json_str.rfind("```") {
                json_str = &json_str[..end];
            }
        } else if let Some(start) = json_str.find("```") {
            json_str = &json_str[start + 3..];
            if let Some(end) = json_str.rfind("```") {
                json_str = &json_str[..end];
            }
        }
        
        let cleaned_json_str = json_str.trim();

        let parsed: Value = serde_json::from_str(cleaned_json_str).unwrap_or_else(|_| {
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
