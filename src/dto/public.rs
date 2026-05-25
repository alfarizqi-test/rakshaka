use serde::{Deserialize, Serialize};

/// Query parameters for public report pagination.
#[derive(Debug, Deserialize)]
pub struct PublicPaginationParams {
    pub page: Option<u64>,
    pub per_page: Option<u64>,
}

/// A single image entry safe for public consumption.
#[derive(Debug, Serialize)]
pub struct PublicImageResponse {
    pub id: String,
    pub image_url: String,
}

/// Public-safe report response — no user_id, email, or any sensitive field.
#[derive(Debug, Serialize)]
pub struct PublicReportResponse {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub created_at: Option<String>,
    pub images: Vec<PublicImageResponse>,
}

/// Paginated wrapper for public reports.
#[derive(Debug, Serialize)]
pub struct PaginatedPublicReports {
    pub data: Vec<PublicReportResponse>,
    pub page: u64,
    pub per_page: u64,
    pub total: u64,
    pub total_pages: u64,
}
