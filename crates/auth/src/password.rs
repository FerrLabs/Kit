//! argon2id password hashing and verification.

use anyhow::Context;
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
pub fn verify(plaintext: &str, stored_hash: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(stored_hash).context("failed to parse stored hash")?;
    let ok = Argon2::default()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok();
    Ok(ok)
}
