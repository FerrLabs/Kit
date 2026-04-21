//! Stripe webhook handling.
//!
//! Verifies the signature and dispatches to per-event handlers that update
//! the `subscriptions` table in Postgres.

// TODO: webhook handler for invoice.paid, customer.subscription.updated, etc.
