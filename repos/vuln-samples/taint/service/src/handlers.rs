use std::collections::HashMap;
use std::process::Command;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Redirect;
use sqlx::SqlitePool;

fn describe(ok: bool) -> String {
    if ok { "ok".to_string() } else { "failed".to_string() }
}

// -- T1 command injection ------------------------------------------------------------------
pub async fn ping(Query(params): Query<HashMap<String, String>>) -> String {
    let host = params.get("host").cloned().unwrap_or_default();
    let command = format!("ping -c 1 {host}");
    let output = Command::new("sh").arg("-c").arg(&command).output(); // EXPECT command-injection
    describe(output.is_ok())
}

/// Safe: the value is parsed into a number before it reaches the command line.
pub async fn ping_count(Query(params): Query<HashMap<String, String>>) -> String {
    let count: u32 = params.get("count").and_then(|value| value.parse().ok()).unwrap_or(1);
    let output = Command::new("ping").arg("-c").arg(count.to_string()).arg("localhost").output();
    describe(output.is_ok())
}

// -- T2 SQL injection ------------------------------------------------------------------------
pub async fn find_user(
    State(pool): State<SqlitePool>,
    Query(params): Query<HashMap<String, String>>,
) -> String {
    let name = params.get("name").cloned().unwrap_or_default();
    let sql = format!("SELECT id FROM users WHERE name = '{name}'");
    let rows = sqlx::query(&sql).fetch_all(&pool).await; // EXPECT sql-injection
    describe(rows.is_ok())
}

/// Safe: the value is a bind parameter, the query text is constant.
pub async fn find_user_bound(
    State(pool): State<SqlitePool>,
    Query(params): Query<HashMap<String, String>>,
) -> String {
    let name = params.get("name").cloned().unwrap_or_default();
    let rows = sqlx::query("SELECT id FROM users WHERE name = ?").bind(name).fetch_all(&pool).await;
    describe(rows.is_ok())
}

// -- T3 path traversal -----------------------------------------------------------------------
pub async fn read_file(Path(name): Path<String>) -> String {
    let path = format!("/srv/files/{name}");
    std::fs::read_to_string(&path).unwrap_or_default() // EXPECT path-traversal
}

/// Safe: the path is canonicalized and must stay under the base directory.
pub async fn read_file_checked(Path(name): Path<String>) -> String {
    let base = std::path::Path::new("/srv/files");
    let Ok(full) = base.join(&name).canonicalize() else {
        return String::new();
    };
    if !full.starts_with(base) {
        return String::new();
    }
    std::fs::read_to_string(&full).unwrap_or_default()
}

// -- T4 server-side request forgery -----------------------------------------------------------
pub async fn proxy(Query(params): Query<HashMap<String, String>>) -> String {
    let url = params.get("url").cloned().unwrap_or_default();
    let response = reqwest::get(&url).await; // EXPECT ssrf
    describe(response.is_ok())
}

/// Safe: only one host is allowed.
pub async fn proxy_allowed(Query(params): Query<HashMap<String, String>>) -> String {
    let url = params.get("url").cloned().unwrap_or_default();
    let Ok(target) = reqwest::Url::parse(&url) else {
        return String::new();
    };
    if target.host_str() != Some("api.example.com") {
        return String::new();
    }
    let response = reqwest::get(target).await;
    describe(response.is_ok())
}

// -- T5 length from input reaching unsafe memory APIs -------------------------------------------
pub async fn peek(Query(params): Query<HashMap<String, String>>) -> String {
    let len: usize = params.get("len").and_then(|value| value.parse().ok()).unwrap_or(0);
    let buffer = vec![0u8; 16];
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr(), len) }; // EXPECT unsafe-length-from-input
    format!("{bytes:?}")
}

/// Safe: the length is clamped to the buffer.
pub async fn peek_clamped(Query(params): Query<HashMap<String, String>>) -> String {
    let wanted: usize = params.get("len").and_then(|value| value.parse().ok()).unwrap_or(0);
    let buffer = vec![0u8; 16];
    let len = wanted.min(buffer.len());
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr(), len) };
    format!("{bytes:?}")
}

// -- T6 open redirect --------------------------------------------------------------------------
pub async fn login_done(Query(params): Query<HashMap<String, String>>) -> Redirect {
    let next = params.get("next").cloned().unwrap_or_default();
    Redirect::to(&next) // EXPECT open-redirect
}

/// Safe: only site-relative targets are followed.
pub async fn login_done_checked(Query(params): Query<HashMap<String, String>>) -> Redirect {
    let next = params.get("next").cloned().unwrap_or_default();
    if !next.starts_with('/') || next.starts_with("//") {
        return Redirect::to("/");
    }
    Redirect::to(&next)
}

// -- T7 header injection -------------------------------------------------------------------------
pub async fn set_language(Query(params): Query<HashMap<String, String>>) -> HeaderMap {
    let language = params.get("lang").cloned().unwrap_or_default();
    let mut headers = HeaderMap::new();
    let value = unsafe { HeaderValue::from_maybe_shared_unchecked(language.into_bytes()) }; // EXPECT header-injection
    headers.insert("content-language", value);
    headers
}

/// Safe: HeaderValue::from_str rejects CR and LF.
pub async fn set_language_checked(Query(params): Query<HashMap<String, String>>) -> HeaderMap {
    let language = params.get("lang").cloned().unwrap_or_default();
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&language) {
        headers.insert("content-language", value);
    }
    headers
}
