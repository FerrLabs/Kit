//! Per-principal rate limiting (user ID or API token).
//!
//! Backed by Redis or in-memory sliding-window. Limits configurable per
//! plan tier.

// TODO: sliding-window rate limiter, plan-aware
