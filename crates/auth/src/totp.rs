//! TOTP 2FA.
//!
//! Seeds are stored **envelope-encrypted** via `ferrlabs-crypto` — never in
//! cleartext. Recovery codes are hashed.

// TODO: totp-rs wrapper + seed encryption via ferrlabs-crypto
