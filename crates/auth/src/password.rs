//! argon2id password hashing and verification.

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

/// Hash a plaintext password with argon2id + random salt.
pub fn hash(plaintext: &str) -> anyhow::Result<String> {
    let hash = Argon2::default()
        .hash_password(plaintext.as_bytes())
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

#[cfg(test)]
mod tests {
    use super::{hash, verify};

    const ARGON2_0_5_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$UyZgCDbJ9chhcULuP/EIXA$whpdo+qkf7pjy+J/mJfX7nZQgqM3fRRRhauyLxAOJW0";
    const ARGON2_0_5_PLAINTEXT: &str = "correct horse battery staple";

    #[test]
    fn a_hash_verifies_against_its_own_plaintext() {
        let stored = hash("hunter2").unwrap();
        assert!(verify("hunter2", &stored).unwrap());
    }

    #[test]
    fn a_different_password_does_not_verify() {
        let stored = hash("hunter2").unwrap();
        assert!(!verify("hunter3", &stored).unwrap());
    }

    #[test]
    fn two_hashes_of_one_password_differ() {
        assert_ne!(hash("hunter2").unwrap(), hash("hunter2").unwrap());
    }

    #[test]
    fn a_hash_written_by_argon2_0_5_still_verifies() {
        assert!(verify(ARGON2_0_5_PLAINTEXT, ARGON2_0_5_HASH).unwrap());
        assert!(!verify("something else", ARGON2_0_5_HASH).unwrap());
    }

    #[test]
    fn a_malformed_stored_hash_is_an_error() {
        assert!(verify("hunter2", "not-a-phc-string").is_err());
    }
}
