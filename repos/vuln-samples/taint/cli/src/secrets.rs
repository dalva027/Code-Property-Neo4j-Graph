//! The flow forms of the crypto rules: what is hashed, what a nonce is made of, where RNG output goes.
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use sha1::Sha1;
use sha2::{Digest, Sha256};

// -- C2 a password hashed with a general-purpose digest ---------------------------------------------
pub fn store_password(password: &str) -> Vec<u8> {
    Sha256::digest(password.as_bytes()).to_vec() // EXPECT weak-password-hashing
}

/// SHA-1 is weak whatever it hashes (C1), and it is hashing a password (C2).
pub fn legacy_password_hash(password: &str) -> Vec<u8> {
    Sha1::digest(password.as_bytes()).to_vec() // EXPECT weak-hash-algorithm weak-password-hashing
}

/// Safe: SHA-256 of data that is not a password.
pub fn checksum(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

// -- C6 a constant nonce -------------------------------------------------------------------------
pub fn seal(key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = [0u8; 12];
    cipher.encrypt(Nonce::from_slice(&nonce), message).unwrap_or_default() // EXPECT insecure-cipher-or-mode
}

/// Safe: the caller supplies a fresh nonce.
pub fn seal_fresh(key: &[u8; 32], message: &[u8], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), message).unwrap_or_default()
}

// -- C3 a non-cryptographic RNG whose output becomes a token -----------------------------------------
pub fn session_token() -> u64 {
    let mut rng = SmallRng::seed_from_u64(7); // EXPECT insecure-randomness
    let token: u64 = rng.gen();
    token
}
