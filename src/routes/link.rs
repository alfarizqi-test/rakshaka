use axum::{routing::post, Router};

use crate::{handlers::link::check_link, state::AppState};

pub fn protected_routes() -> Router<AppState> {
    Router::new().route("/link/check", post(check_link))
}
