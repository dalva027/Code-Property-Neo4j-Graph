//! A small axum service: for each injection rule one handler that passes request data to a
//! dangerous call, and one that does the same thing safely. See ../expected.json.
mod handlers;

use axum::routing::get;
use axum::Router;
use sqlx::SqlitePool;

#[tokio::main]
async fn main() {
    let pool = SqlitePool::connect_lazy("sqlite::memory:").expect("valid database url");
    let app = Router::new()
        .route("/ping", get(handlers::ping))
        .route("/ping-count", get(handlers::ping_count))
        .route("/users", get(handlers::find_user))
        .route("/users-bound", get(handlers::find_user_bound))
        .route("/files/:name", get(handlers::read_file))
        .route("/files-checked/:name", get(handlers::read_file_checked))
        .route("/proxy", get(handlers::proxy))
        .route("/proxy-allowed", get(handlers::proxy_allowed))
        .route("/peek", get(handlers::peek))
        .route("/peek-clamped", get(handlers::peek_clamped))
        .route("/login-done", get(handlers::login_done))
        .route("/login-done-checked", get(handlers::login_done_checked))
        .route("/language", get(handlers::set_language))
        .route("/language-checked", get(handlers::set_language_checked))
        .with_state(pool);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.expect("free port");
    axum::serve(listener, app).await.expect("server runs");
}
