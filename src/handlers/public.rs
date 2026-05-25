use axum::{extract::{Path, Query, State}, response::IntoResponse};

use crate::{
    dto::public::{
        PaginatedPublicReports, PublicImageResponse, PublicPaginationParams,
        PublicReportDetailResponse, PublicReportResponse,
    },
    models::report::{Report, ReportImage},
    state::AppState,
    utils::response::{not_found, success},
};

pub async fn list_public_reports(
    State(state): State<AppState>,
    Query(params): Query<PublicPaginationParams>,
) -> impl IntoResponse {
    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(10).min(50);
    let offset = (page - 1) * per_page;

    // Total count
    let total: u64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0u64);

    // Fetch page of reports ordered newest-first
    let reports: Vec<Report> = sqlx::query_as(
        "SELECT id, user_id, title, description, category, created_at, updated_at \
         FROM reports \
         ORDER BY created_at DESC \
         LIMIT ? OFFSET ?",
    )
    .bind(per_page as i64)
    .bind(offset as i64)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    // Build public responses, fetching images per report
    let mut data: Vec<PublicReportResponse> = Vec::with_capacity(reports.len());

    for report in reports {
        let images = fetch_images(&state, &report.id).await;

        data.push(PublicReportResponse {
            id: report.id,
            title: report.title,
            description: report.description,
            category: report.category,
            created_at: report.created_at.map(|dt| dt.to_string()),
            images: map_images(images),
        });
    }

    let total_pages = if per_page == 0 { 1 } else { (total + per_page - 1) / per_page };

    success(
        "Public reports retrieved",
        PaginatedPublicReports {
            data,
            page,
            per_page,
            total,
            total_pages,
        },
    )
}

/// Helper: convert a Vec<ReportImage> into Vec<PublicImageResponse>.
fn map_images(images: Vec<ReportImage>) -> Vec<PublicImageResponse> {
    images
        .into_iter()
        .map(|img| PublicImageResponse {
            id: img.id,
            image_url: img.image_url,
        })
        .collect()
}

/// Fetch images for a given report_id, capped at 3.
async fn fetch_images(state: &AppState, report_id: &str) -> Vec<ReportImage> {
    sqlx::query_as(
        "SELECT id, report_id, image_url \
         FROM report_images \
         WHERE report_id = ? \
         LIMIT 3",
    )
    .bind(report_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default()
}

/// GET /reports/public/:id
///
/// Returns a single report's public detail. No authentication required.
/// Omits user_id and all private/internal data.
pub async fn get_public_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let report: Option<Report> = sqlx::query_as(
        "SELECT id, user_id, title, description, category, created_at, updated_at \
         FROM reports \
         WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let report = match report {
        Some(r) => r,
        None => return not_found("Report not found").into_response(),
    };

    let images = fetch_images(&state, &report.id).await;

    success(
        "Public report retrieved",
        PublicReportDetailResponse {
            id: report.id,
            title: report.title,
            description: report.description,
            category: report.category,
            created_at: report.created_at.map(|dt| dt.to_string()),
            updated_at: report.updated_at.map(|dt| dt.to_string()),
            images: map_images(images),
        },
    )
    .into_response()
}
