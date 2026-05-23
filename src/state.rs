use sqlx::MySqlPool;

#[derive(Clone)]
pub struct AppState {
    pub db: MySqlPool,
    pub jwt_secret: String,
    pub link_checker_api_key: String,
    pub link_checker_api_url: String,
}
