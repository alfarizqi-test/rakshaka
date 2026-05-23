use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use validator::Validate;

use crate::{
    dto::link::LinkCheckRequest,
    services::link_checker::LinkCheckerService,
    state::AppState,
    utils::{
        jwt::Claims,
        response::{error, success},
    },
};

pub async fn check_link(
    State(state): State<AppState>,
    Extension(_claims): Extension<Claims>,
    Json(payload): Json<LinkCheckRequest>,
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

    let service = LinkCheckerService::new(
        state.link_checker_api_key.clone(),
        state.link_checker_api_url.clone(),
    );

    match service.check_url(&payload.url).await {
        Ok(result) => {
            let status = result
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let score = result.get("score").and_then(|v| v.as_i64());

            success(
                "Link analyzed successfully",
                serde_json::json!({
                    "url": payload.url,
                    "status": status,
                    "score": score,
                }),
            )
            .into_response()
        }
        Err(crate::services::link_checker::LinkCheckerError::NotConfigured) => {
            error(StatusCode::SERVICE_UNAVAILABLE, "Link checker service is not configured").into_response()
        }
        Err(crate::services::link_checker::LinkCheckerError::Timeout) => {
            error(StatusCode::GATEWAY_TIMEOUT, "Link checker request timed out").into_response()
        }
        Err(e) => {
            tracing::error!("Link checker error: {}", e);
            error(StatusCode::BAD_GATEWAY, "Failed to analyze link").into_response()
        }
    }
}
