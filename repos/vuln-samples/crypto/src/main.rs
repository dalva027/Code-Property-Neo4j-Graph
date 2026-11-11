//! Class C sample: weak hashes, insecure randomness, hard-coded secrets, disabled TLS
//! verification, an insecure cipher and weak KDF parameters.
mod auth;
mod tls;
mod tokens;

const API_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

fn main() {
    let digest = auth::legacy_digest(b"data");
    let token = tokens::session_token();
    let client = tls::insecure_client();
    println!("{:?} {} {:?} {}", digest, token, client, API_KEY);
    let _ = auth::derive_key("hunter2");
    let _ = auth::check_admin("guess");
}
