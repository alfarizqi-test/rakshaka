use axum::{
    routing::{get, post},
    Router,
};

use crate::{
    handlers::auth::{login, me, register},
    state::AppState,
};

/// Returns routes that need JWT protection (to be wrapped by middleware in main.rs)
pub fn protected_routes() -> Router<AppState> {
    Router::new().route("/auth/me", get(me))
}

/// Returns public auth routes (no middleware)
pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
}
