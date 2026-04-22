//! argon2id password hashing and verification.

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

/// Hash a plaintext password with argon2id + random salt.
pub fn hash(plaintext: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?
        .to_string();
    Ok(hash)
}

/// Constant-time verify that a plaintext matches a stored hash.
///
/// `argon2::password_hash::Error` does not implement `std::error::Error`, so
/// `anyhow::Context` can't wrap it directly. Convert via `map_err` instead.
pub fn verify(plaintext: &str, stored_hash: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| anyhow::anyhow!("failed to parse stored hash: {e}"))?;
    let ok = Argon2::default()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok();
    Ok(ok)
}
