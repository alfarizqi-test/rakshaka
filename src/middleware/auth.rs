use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
    Json,
};
use serde_json::json;

#[allow(unused_imports)]
use crate::{state::AppState, utils::jwt::verify_token, utils::jwt::Claims};


pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => h[7..].to_owned(),
        _ => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"success": false, "message": "Missing or invalid Authorization header"})),
            ))
        }
    };

    match verify_token(&token, &state.jwt_secret) {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            Ok(next.run(req).await)
        }
        Err(_) => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"success": false, "message": "Invalid or expired token"})),
        )),
    }
}
