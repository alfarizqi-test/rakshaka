use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateReportRequest {
    #[validate(length(min = 3, max = 200, message = "Title must be 3-200 characters"))]
    pub title: String,

    #[validate(length(min = 10, message = "Description must be at least 10 characters"))]
    pub description: String,

    #[validate(custom(function = "validate_category"))]
    pub category: String,

    #[validate(custom(function = "validate_images"))]
    pub images: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateReportRequest {
    #[validate(length(min = 3, max = 200, message = "Title must be 3-200 characters"))]
    pub title: Option<String>,

    #[validate(length(min = 10, message = "Description must be at least 10 characters"))]
    pub description: Option<String>,

    #[validate(custom(function = "validate_category_opt"))]
    pub category: Option<String>,

    #[validate(custom(function = "validate_images"))]
    pub images: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page: Option<u64>,
    pub per_page: Option<u64>,
}

fn validate_category(value: &str) -> Result<(), validator::ValidationError> {
    match value {
        "scam" | "phishing" | "judol" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_category")),
    }
}

fn validate_category_opt(value: &str) -> Result<(), validator::ValidationError> {
    validate_category(value)
}

fn validate_images(value: &Vec<String>) -> Result<(), validator::ValidationError> {
    if value.len() > 3 {
        return Err(validator::ValidationError::new("max_3_images"));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct ReportResponse {
    pub id: String,
    pub user_id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub images: Vec<ImageResponse>,
}

#[derive(Debug, Serialize)]
pub struct ImageResponse {
    pub id: String,
    pub image_url: String,
}

#[derive(Debug, Serialize)]
pub struct PaginatedReports {
    pub data: Vec<ReportResponse>,
    pub page: u64,
    pub per_page: u64,
    pub total: u64,
    pub total_pages: u64,
}
