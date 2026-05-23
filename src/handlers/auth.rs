use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use validator::Validate;

use crate::{
    dto::auth::{LoginRequest, RegisterRequest, UserResponse},
    models::user::User,
    state::AppState,
    utils::{
        hash::{hash_password, verify_password},
        jwt::{generate_token, Claims},
        response::{error, success, success_created, unauthorized},
    },
};

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    // Validate input
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

    // Check username uniqueness
    let existing_username: Option<User> = sqlx::query_as(
        "SELECT id, username, email, password_hash, role, created_at FROM users WHERE username = ?",
    )
    .bind(&payload.username)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    if existing_username.is_some() {
        return error(StatusCode::CONFLICT, "Username already taken").into_response();
    }

    // Check email uniqueness
    let existing_email: Option<User> = sqlx::query_as(
        "SELECT id, username, email, password_hash, role, created_at FROM users WHERE email = ?",
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    if existing_email.is_some() {
        return error(StatusCode::CONFLICT, "Email already registered").into_response();
    }

    // Hash password
    let password_hash = match hash_password(&payload.password) {
        Ok(h) => h,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password").into_response(),
    };

    let user_id = uuid::Uuid::new_v4().to_string();

    // Insert user
    let result = sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, role) VALUES (?, ?, ?, ?, 'user')",
    )
    .bind(&user_id)
    .bind(&payload.username)
    .bind(&payload.email)
    .bind(&password_hash)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            let user_resp = UserResponse {
                id: user_id,
                username: payload.username,
                email: payload.email,
                role: "user".to_string(),
                created_at: Some(chrono::Utc::now().to_rfc3339()),
            };
            success_created("User registered successfully", user_resp).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to insert user: {}", e);
            error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to register user").into_response()
        }
    }
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
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

    let user: Option<User> = sqlx::query_as(
        "SELECT id, username, email, password_hash, role, created_at FROM users WHERE email = ?",
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let user = match user {
        Some(u) => u,
        None => return unauthorized("Invalid email or password").into_response(),
    };

    match verify_password(&payload.password, &user.password_hash) {
        Ok(true) => {}
        _ => return unauthorized("Invalid email or password").into_response(),
    }

    let token = match generate_token(&user.id, &user.role, &state.jwt_secret) {
        Ok(t) => t,
        Err(_) => return error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate token").into_response(),
    };

    let user_resp = UserResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        created_at: user.created_at.map(|dt| dt.to_string()),
    };

    success(
        "Login successful",
        serde_json::json!({
            "token": token,
            "user": user_resp,
        }),
    )
    .into_response()
}

pub async fn me(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    let user: Option<User> = sqlx::query_as(
        "SELECT id, username, email, password_hash, role, created_at FROM users WHERE id = ?",
    )
    .bind(&claims.sub)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    match user {
        Some(u) => {
            let resp = UserResponse {
                id: u.id,
                username: u.username,
                email: u.email,
                role: u.role,
                created_at: u.created_at.map(|dt| dt.to_string()),
            };
            success("User retrieved", resp).into_response()
        }
        None => error(StatusCode::NOT_FOUND, "User not found").into_response(),
    }
}
