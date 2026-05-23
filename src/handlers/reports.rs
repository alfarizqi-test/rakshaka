use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use validator::Validate;

use crate::{
    dto::report::{
        CreateReportRequest, ImageResponse, PaginatedReports, PaginationParams, ReportResponse,
        UpdateReportRequest,
    },
    models::report::{Report, ReportImage},
    state::AppState,
    utils::{
        jwt::Claims,
        response::{error, forbidden, not_found, success, success_created},
    },
};

fn to_report_response(report: Report, images: Vec<ReportImage>) -> ReportResponse {
    ReportResponse {
        id: report.id,
        user_id: report.user_id,
        title: report.title,
        description: report.description,
        category: report.category,
        created_at: report.created_at.map(|dt| dt.to_string()),
        updated_at: report.updated_at.map(|dt| dt.to_string()),
        images: images
            .into_iter()
            .map(|img| ImageResponse {
                id: img.id,
                image_url: img.image_url,
            })
            .collect(),
    }
}

pub async fn list_reports(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let page = params.page.unwrap_or(1).max(1);
    let per_page = params.per_page.unwrap_or(10).min(100);
    let offset = (page - 1) * per_page;

    let (reports, total): (Vec<Report>, u64) = if claims.role == "admin" {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM reports")
            .fetch_one(&state.db)
            .await
            .unwrap_or((0,));

        let reports: Vec<Report> = sqlx::query_as(
            "SELECT id, user_id, title, description, category, created_at, updated_at FROM reports ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(per_page as i64)
        .bind(offset as i64)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        (reports, total.0 as u64)
    } else {
        let total: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM reports WHERE user_id = ?")
                .bind(&claims.sub)
                .fetch_one(&state.db)
                .await
                .unwrap_or((0,));

        let reports: Vec<Report> = sqlx::query_as(
            "SELECT id, user_id, title, description, category, created_at, updated_at FROM reports WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        )
        .bind(&claims.sub)
        .bind(per_page as i64)
        .bind(offset as i64)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        (reports, total.0 as u64)
    };

    let mut responses = Vec::new();
    for report in reports {
        let images: Vec<ReportImage> = sqlx::query_as(
            "SELECT id, report_id, image_url FROM report_images WHERE report_id = ?",
        )
        .bind(&report.id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
        responses.push(to_report_response(report, images));
    }

    let total_pages = (total + per_page - 1) / per_page;
    let paginated = PaginatedReports {
        data: responses,
        page,
        per_page,
        total,
        total_pages,
    };

    success("Reports retrieved", paginated).into_response()
}

pub async fn get_report(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let report: Option<Report> = sqlx::query_as(
        "SELECT id, user_id, title, description, category, created_at, updated_at FROM reports WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let report = match report {
        Some(r) => r,
        None => return not_found("Report not found").into_response(),
    };

    // Only owner or admin can view
    if claims.role != "admin" && report.user_id != claims.sub {
        return forbidden("You are not authorized to view this report").into_response();
    }

    let images: Vec<ReportImage> = sqlx::query_as(
        "SELECT id, report_id, image_url FROM report_images WHERE report_id = ?",
    )
    .bind(&report.id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    success("Report retrieved", to_report_response(report, images)).into_response()
}

pub async fn create_report(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(payload): Json<CreateReportRequest>,
) -> impl IntoResponse {
    if let Err(e) = payload.validate() {
        let msg = e
            .field_errors()
            .values()
            .flat_map(|errs| errs.iter())
            .filter_map(|e| e.message.as_ref())
            .map(|m| m.as_ref())
            .collect::<Vec<&str>>()
            .join(", ");
        return error(StatusCode::UNPROCESSABLE_ENTITY, &msg).into_response();
    }

    let images = payload.images.clone().unwrap_or_default();
    if images.len() > 3 {
        return error(StatusCode::UNPROCESSABLE_ENTITY, "Maximum 3 images allowed").into_response();
    }

    let report_id = uuid::Uuid::new_v4().to_string();

    let result = sqlx::query(
        "INSERT INTO reports (id, user_id, title, description, category) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&report_id)
    .bind(&claims.sub)
    .bind(&payload.title)
    .bind(&payload.description)
    .bind(&payload.category)
    .execute(&state.db)
    .await;

    if let Err(e) = result {
        tracing::error!("Failed to create report: {}", e);
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create report").into_response();
    }

    // Insert images
    let mut inserted_images = Vec::new();
    for image_url in &images {
        let image_id = uuid::Uuid::new_v4().to_string();
        let img_result = sqlx::query(
            "INSERT INTO report_images (id, report_id, image_url) VALUES (?, ?, ?)",
        )
        .bind(&image_id)
        .bind(&report_id)
        .bind(image_url)
        .execute(&state.db)
        .await;

        if img_result.is_ok() {
            inserted_images.push(ReportImage {
                id: image_id,
                report_id: report_id.clone(),
                image_url: image_url.clone(),
            });
        }
    }

    let report: Report = sqlx::query_as(
        "SELECT id, user_id, title, description, category, created_at, updated_at FROM reports WHERE id = ?",
    )
    .bind(&report_id)
    .fetch_one(&state.db)
    .await
    .expect("Newly inserted report not found");

    success_created("Report created successfully", to_report_response(report, inserted_images)).into_response()
}

pub async fn update_report(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateReportRequest>,
) -> impl IntoResponse {
    if let Err(e) = payload.validate() {
        let msg = e
            .field_errors()
            .values()
            .flat_map(|errs| errs.iter())
            .filter_map(|e| e.message.as_ref())
            .map(|m| m.as_ref())
            .collect::<Vec<&str>>()
            .join(", ");
        return error(StatusCode::UNPROCESSABLE_ENTITY, &msg).into_response();
    }

    let report: Option<Report> = sqlx::query_as(
        "SELECT id, user_id, title, description, category, created_at, updated_at FROM reports WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let report = match report {
        Some(r) => r,
        None => return not_found("Report not found").into_response(),
    };

    // Only owner can update (admin can too)
    if claims.role != "admin" && report.user_id != claims.sub {
        return forbidden("You are not authorized to update this report").into_response();
    }

    let new_title = payload.title.as_deref().unwrap_or(&report.title);
    let new_desc = payload.description.as_deref().unwrap_or(&report.description);
    let new_category = payload.category.as_deref().unwrap_or(&report.category);

    let update_result = sqlx::query(
        "UPDATE reports SET title = ?, description = ?, category = ?, updated_at = NOW() WHERE id = ?",
    )
    .bind(new_title)
    .bind(new_desc)
    .bind(new_category)
    .bind(&id)
    .execute(&state.db)
    .await;

    if let Err(e) = update_result {
        tracing::error!("Failed to update report: {}", e);
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to update report").into_response();
    }

    // Update images if provided
    if let Some(images) = &payload.images {
        if images.len() > 3 {
            return error(StatusCode::UNPROCESSABLE_ENTITY, "Maximum 3 images allowed").into_response();
        }
        // Delete old images
        let _ = sqlx::query("DELETE FROM report_images WHERE report_id = ?")
            .bind(&id)
            .execute(&state.db)
            .await;

        // Insert new images
        for image_url in images {
            let image_id = uuid::Uuid::new_v4().to_string();
            let _ = sqlx::query(
                "INSERT INTO report_images (id, report_id, image_url) VALUES (?, ?, ?)",
            )
            .bind(&image_id)
            .bind(&id)
            .bind(image_url)
            .execute(&state.db)
            .await;
        }
    }

    let updated_report: Report = sqlx::query_as(
        "SELECT id, user_id, title, description, category, created_at, updated_at FROM reports WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&state.db)
    .await
    .expect("Updated report not found");

    let images: Vec<ReportImage> = sqlx::query_as(
        "SELECT id, report_id, image_url FROM report_images WHERE report_id = ?",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    success("Report updated successfully", to_report_response(updated_report, images)).into_response()
}

pub async fn delete_report(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let report: Option<Report> = sqlx::query_as(
        "SELECT id, user_id, title, description, category, created_at, updated_at FROM reports WHERE id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let report = match report {
        Some(r) => r,
        None => return not_found("Report not found").into_response(),
    };

    // Only owner or admin can delete
    if claims.role != "admin" && report.user_id != claims.sub {
        return forbidden("You are not authorized to delete this report").into_response();
    }

    // Delete images first
    let _ = sqlx::query("DELETE FROM report_images WHERE report_id = ?")
        .bind(&id)
        .execute(&state.db)
        .await;

    let _ = sqlx::query("DELETE FROM reports WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await;

    success("Report deleted successfully", serde_json::json!(null)).into_response()
}
