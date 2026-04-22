//! Stripe integration for `FerrLabs` billing.
//!
//! One Stripe customer per `FerrLabs` organization. One subscription item per
//! (org, product) pair — so an org can subscribe to `FerrFlow` Premium and
//! `FerrVault` Team independently, all on one invoice.
//!
//! ## Products
//!
//! - `ferrflow` — Free, Premium
//! - `ferrvault` — Free, Team, Business, Enterprise

// TODO: stripe client setup, subscription CRUD, webhook verification

pub mod webhooks;
