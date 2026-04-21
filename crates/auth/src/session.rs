//! Refresh sessions stored in Postgres.
//!
//! Issued when the user logs in, exchanged for short-lived JWT access tokens.
//! Rotated on use to make token replay harder to pull off.

// TODO: session CRUD against the sessions table
