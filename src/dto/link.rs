use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct LinkCheckRequest {
    #[validate(url(message = "Invalid URL format"))]
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkCheckData {
    pub url: String,
    pub status: String,
    pub score: Option<i64>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct LinkCheckResponse {
    pub url: String,
    pub status: String,
    pub score: Option<i64>,
}
