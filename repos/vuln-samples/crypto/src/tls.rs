use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::symm::Cipher;
use reqwest::blocking::Client;

pub fn insecure_client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client")
}

pub fn legacy_connector() -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls()).expect("connector");
    builder.set_verify(SslVerifyMode::NONE);
    builder.build()
}

pub fn legacy_cipher() -> Cipher {
    Cipher::des_ede3_cbc()
}
