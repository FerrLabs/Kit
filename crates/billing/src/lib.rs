//! Stripe integration for `FerrLabs` billing.
//!
//! One Stripe customer per `FerrLabs` organization. One subscription per
//! (org, product) pair — so an org can subscribe to `FerrVault` Team and
//! `FerrTrack` Pro independently, all on one customer / one invoice.
//!
//! ## Layout
//!
//! - [`client`] — [`BillingClient`], the authenticated Stripe handle and the
//!   customer/subscription operations the per-product model needs.
//! - [`webhooks`] — [`verify_signature`](webhooks::verify_signature), the
//!   security-critical `Stripe-Signature` HMAC verification with replay
//!   protection.
//! - [`events`] — [`parse_event`](events::parse_event), which turns a verified
//!   webhook body into a typed [`WebhookEvent`](events::WebhookEvent).
//!
//! ## Tiers
//!
//! Each paid product is `Free → Pro → Team → Enterprise`
//! ([`ferrlabs_types::Plan`]). Stripe price IDs per (product, tier) are
//! resolved by the consumer and passed in via [`client::PlanPrice`]; this crate
//! holds no hard-coded Stripe object IDs.

pub mod client;
pub mod error;
pub mod events;
pub mod webhooks;

pub use client::{BillingClient, PlanPrice};
pub use error::{BillingError, SignatureError};
pub use events::{SubscriptionChange, WebhookEvent, parse_event};
pub use webhooks::{DEFAULT_TOLERANCE_SECS, verify_optional_signature, verify_signature};
