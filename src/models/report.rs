use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Report {
    pub id: String,
    pub user_id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ReportImage {
    pub id: String,
    pub report_id: String,
    pub image_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportWithImages {
    pub id: String,
    pub user_id: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub images: Vec<ReportImage>,
}
