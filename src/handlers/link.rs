use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use validator::Validate;

use crate::{
    dto::link::LinkCheckRequest,
    services::link_checker::{LinkCheckerError, LinkCheckerService},
    state::AppState,
    utils::{
        jwt::Claims,
        response::{error, success},
        url::{extract_host, is_blocked_host},
    },
};

/// Community intelligence: counts how many reports exist for this domain/URL.
struct CommunityData {
    report_count: i64,
    categories: Vec<String>,
}

async fn query_community_data(state: &AppState, url: &str) -> CommunityData {
    // Extract bare domain for matching (e.g. "evil.com" matches "https://evil.com/path")
    let domain = extract_host(url).unwrap_or_default();

    // Count reports whose title or description mentions the URL or domain
    let pattern = format!("%{}%", if domain.is_empty() { url } else { &domain });

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reports \
         WHERE title LIKE ? OR description LIKE ?",
    )
    .bind(&pattern)
    .bind(&pattern)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    // Collect distinct categories from those matching reports
    let categories: Vec<String> = if count > 0 {
        sqlx::query_scalar(
            "SELECT DISTINCT category FROM reports \
             WHERE title LIKE ? OR description LIKE ?",
        )
        .bind(&pattern)
        .bind(&pattern)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default()
    } else {
        vec![]
    };

    CommunityData { report_count: count, categories }
}

pub async fn check_link(
    State(state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Json(payload): Json<LinkCheckRequest>,
) -> impl IntoResponse {
    // ── 1. Basic format validation ──────────────────────────────────────────
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

    // ── 2. SSRF protection ──────────────────────────────────────────────────
    let host = match extract_host(&payload.url) {
        Some(h) => h,
        None => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid URL: cannot extract host",
            )
            .into_response()
        }
    };

    if is_blocked_host(&host) {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "URL targets a private, internal, or reserved address and cannot be analyzed",
        )
        .into_response();
    }

    // ── 3. Community intelligence (local DB) ────────────────────────────────
    let community = query_community_data(&state, &payload.url).await;

    // ── 4. AI / external analysis ───────────────────────────────────────────
    let service = LinkCheckerService::new(
        state.link_checker_api_key.clone(),
        state.link_checker_api_url.clone(),
    );

    let ai_result = service.check_url(&payload.url).await;

    let (ai_status, ai_score, ai_reason) = match &ai_result {
        Ok(v) => {
            let status = v
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string();
            let score = v.get("score").and_then(|s| s.as_i64());
            let reason = v
                .get("reason")
                .and_then(|r| r.as_str())
                .unwrap_or("")
                .to_string();
            (status, score, reason)
        }
        Err(LinkCheckerError::NotConfigured) => {
            tracing::warn!("AI link checker not configured");
            ("unknown".to_string(), None, "AI analysis not available".to_string())
        }
        Err(LinkCheckerError::Timeout) => {
            tracing::warn!("AI link checker timed out for {}", payload.url);
            ("unknown".to_string(), None, "AI analysis timed out".to_string())
        }
        Err(e) => {
            tracing::error!("AI link checker error for {}: {}", payload.url, e);
            ("unknown".to_string(), None, "AI analysis failed".to_string())
        }
    };

    // ── 5. Merge community signal into final verdict ─────────────────────────
    // If community has reports, escalate status unless AI already flagged it.
    let final_status = if community.report_count > 0
        && (ai_status == "unknown" || ai_status == "safe")
    {
        // Infer status from most common category in reports
        if community.categories.iter().any(|c| c == "phishing") {
            "suspicious".to_string()
        } else if community.categories.iter().any(|c| c == "scam" || c == "judol") {
            "suspicious".to_string()
        } else {
            "suspicious".to_string()
        }
    } else {
        ai_status.clone()
    };

    // ── 6. Build response ────────────────────────────────────────────────────
    success(
        "Link analyzed successfully",
        serde_json::json!({
            "url": payload.url,
            "status": final_status,
            "score": ai_score,
            "reason": ai_reason,
            "community": {
                "report_count": community.report_count,
                "categories": community.categories,
            }
        }),
    )
    .into_response()
}
