use axum::{extract::{Query, State}, response::IntoResponse};

use crate::{
    dto::public::{
        PaginatedPublicReports, PublicImageResponse, PublicPaginationParams, PublicReportResponse,
    },
    models::report::{Report, ReportImage},
    state::AppState,
    utils::response::success,
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
        let images: Vec<ReportImage> = sqlx::query_as(
            "SELECT id, report_id, image_url \
             FROM report_images \
             WHERE report_id = ? \
             LIMIT 3",
        )
        .bind(&report.id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        data.push(PublicReportResponse {
            id: report.id,
            title: report.title,
            description: report.description,
            category: report.category,
            created_at: report.created_at.map(|dt| dt.to_string()),
            images: images
                .into_iter()
                .map(|img| PublicImageResponse {
                    id: img.id,
                    image_url: img.image_url,
                })
                .collect(),
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
