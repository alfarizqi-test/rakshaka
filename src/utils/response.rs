use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use serde_json::json;

pub fn success<T: Serialize>(message: &str, data: T) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "message": message,
            "data": data,
        })),
    )
}

pub fn success_created<T: Serialize>(message: &str, data: T) -> impl IntoResponse {
    (
        StatusCode::CREATED,
        Json(json!({
            "success": true,
            "message": message,
            "data": data,
        })),
    )
}

pub fn error(status: StatusCode, message: &str) -> impl IntoResponse {
    (
        status,
        Json(json!({
            "success": false,
            "message": message,
        })),
    )
}

pub fn validation_error(message: &str) -> impl IntoResponse {
    error(StatusCode::UNPROCESSABLE_ENTITY, message)
}

pub fn unauthorized(message: &str) -> impl IntoResponse {
    error(StatusCode::UNAUTHORIZED, message)
}

pub fn forbidden(message: &str) -> impl IntoResponse {
    error(StatusCode::FORBIDDEN, message)
}

pub fn not_found(message: &str) -> impl IntoResponse {
    error(StatusCode::NOT_FOUND, message)
}

pub fn internal_error(message: &str) -> impl IntoResponse {
    error(StatusCode::INTERNAL_SERVER_ERROR, message)
}
