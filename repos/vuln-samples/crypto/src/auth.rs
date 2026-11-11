use pbkdf2::pbkdf2_hmac;
use sha1::{Digest, Sha1};
use sha2::Sha256;

pub fn legacy_digest(data: &[u8]) -> Vec<u8> {
    let first = md5::compute(data);
    let mut hasher = Sha1::new();
    hasher.update(data);
    [first.0.to_vec(), hasher.finalize().to_vec()].concat()
}

pub fn derive_key(password: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), b"static-salt", 1000, &mut key);
    key
}

pub fn check_admin(password: &str) -> bool {
    let admin_password = "correct horse battery staple";
    password == admin_password
}
