//! Typed parsing of the Stripe webhook events FerrLabs billing reacts to.
//!
//! We only model the handful of events that drive the `subscriptions` table.
//! Everything else parses to [`WebhookEvent::Other`] so an unrecognised event
//! is acknowledged (HTTP 200) rather than erroring — Stripe retries on non-2xx
//! and we don't want to retry-loop on events we simply ignore.

use ferrlabs_types::{Plan, Product, SubscriptionStatus};
use serde::Deserialize;

use crate::error::BillingError;

/// The subset of Stripe webhook events that change FerrLabs billing state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookEvent {
    /// `invoice.paid` — the org paid; the subscription period was extended.
    InvoicePaid(SubscriptionChange),
    /// `customer.subscription.updated` — tier swap, status change, renewal.
    SubscriptionUpdated(SubscriptionChange),
    /// `customer.subscription.deleted` — the subscription was fully canceled.
    SubscriptionDeleted(SubscriptionChange),
    /// Any event type we don't act on. Carries the raw type string for logging.
    Other(String),
}

/// The normalized billing state carried by a subscription-affecting event.
///
/// `org` and `product` are read from the metadata FerrLabs stamps onto every
/// Stripe customer/subscription at creation time; `tier`/`status` reflect the
/// event's current view of the subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionChange {
    pub stripe_subscription_id: String,
    pub stripe_customer_id: String,
    pub org_id: String,
    pub product: Product,
    pub tier: Plan,
    pub status: SubscriptionStatus,
}

#[derive(Deserialize)]
struct RawEvent {
    #[serde(rename = "type")]
    event_type: String,
    data: RawData,
}

#[derive(Deserialize)]
struct RawData {
    object: serde_json::Value,
}

#[derive(Deserialize)]
struct RawSubscriptionObject {
    id: String,
    customer: String,
    status: String,
    #[serde(default)]
    metadata: Metadata,
}

#[derive(Deserialize)]
struct RawInvoiceObject {
    subscription: Option<String>,
    customer: String,
    #[serde(default)]
    metadata: Metadata,
    #[serde(default)]
    lines: InvoiceLines,
}

#[derive(Deserialize, Default)]
struct InvoiceLines {
    #[serde(default)]
    data: Vec<InvoiceLine>,
}

#[derive(Deserialize)]
struct InvoiceLine {
    #[serde(default)]
    metadata: Metadata,
    #[serde(default)]
    subscription: Option<String>,
}

#[derive(Deserialize, Default)]
struct Metadata {
    org_id: Option<String>,
    product: Option<String>,
    tier: Option<String>,
}

fn product_from_slug(slug: &str) -> Option<Product> {
    Product::all().iter().copied().find(|p| p.slug() == slug)
}

fn tier_from_str(value: &str) -> Plan {
    match value {
        "pro" => Plan::Pro,
        "team" => Plan::Team,
        "enterprise" => Plan::Enterprise,
        _ => Plan::Free,
    }
}

fn status_from_stripe(value: &str) -> SubscriptionStatus {
    match value {
        "trialing" => SubscriptionStatus::Trialing,
        "active" => SubscriptionStatus::Active,
        "past_due" | "unpaid" => SubscriptionStatus::PastDue,
        "canceled" => SubscriptionStatus::Canceled,
        _ => SubscriptionStatus::Incomplete,
    }
}

fn change_from_subscription(
    raw: RawSubscriptionObject,
    status_override: Option<SubscriptionStatus>,
) -> Result<SubscriptionChange, BillingError> {
    let org_id = raw
        .metadata
        .org_id
        .ok_or(BillingError::MissingField("metadata.org_id"))?;
    let product_slug = raw
        .metadata
        .product
        .ok_or(BillingError::MissingField("metadata.product"))?;
    let product = product_from_slug(&product_slug).ok_or(BillingError::MissingField(
        "metadata.product (unknown slug)",
    ))?;
    let tier = raw
        .metadata
        .tier
        .as_deref()
        .map_or(Plan::Free, tier_from_str);

    Ok(SubscriptionChange {
        stripe_subscription_id: raw.id,
        stripe_customer_id: raw.customer,
        org_id,
        product,
        tier,
        status: status_override.unwrap_or_else(|| status_from_stripe(&raw.status)),
    })
}

fn change_from_invoice(raw: RawInvoiceObject) -> Result<SubscriptionChange, BillingError> {
    let line_meta = raw.lines.data.first();
    let metadata = if raw.metadata.org_id.is_some() {
        &raw.metadata
    } else {
        line_meta.map_or(&raw.metadata, |l| &l.metadata)
    };

    let org_id = metadata
        .org_id
        .clone()
        .ok_or(BillingError::MissingField("metadata.org_id"))?;
    let product_slug = metadata
        .product
        .clone()
        .ok_or(BillingError::MissingField("metadata.product"))?;
    let product = product_from_slug(&product_slug).ok_or(BillingError::MissingField(
        "metadata.product (unknown slug)",
    ))?;
    let tier = metadata.tier.as_deref().map_or(Plan::Free, tier_from_str);

    let subscription_id = raw
        .subscription
        .or_else(|| line_meta.and_then(|l| l.subscription.clone()))
        .ok_or(BillingError::MissingField("subscription"))?;

    Ok(SubscriptionChange {
        stripe_subscription_id: subscription_id,
        stripe_customer_id: raw.customer,
        org_id,
        product,
        tier,
        status: SubscriptionStatus::Active,
    })
}

/// Parse a verified webhook body into a [`WebhookEvent`].
///
/// Call this **only after** [`crate::webhooks::verify_signature`] has accepted
/// the body — this function trusts the payload's authenticity.
///
/// # Errors
/// - [`BillingError::MalformedPayload`] — the body is not a Stripe event.
/// - [`BillingError::MissingField`] — a subscription-affecting event lacked the
///   `org_id`/`product` metadata FerrLabs requires.
pub fn parse_event(payload: &[u8]) -> Result<WebhookEvent, BillingError> {
    let raw: RawEvent = serde_json::from_slice(payload)
        .map_err(|e| BillingError::MalformedPayload(e.to_string()))?;

    match raw.event_type.as_str() {
        "invoice.paid" => {
            let invoice: RawInvoiceObject = serde_json::from_value(raw.data.object)
                .map_err(|e| BillingError::MalformedPayload(e.to_string()))?;
            Ok(WebhookEvent::InvoicePaid(change_from_invoice(invoice)?))
        }
        "customer.subscription.updated" => {
            let sub: RawSubscriptionObject = serde_json::from_value(raw.data.object)
                .map_err(|e| BillingError::MalformedPayload(e.to_string()))?;
            Ok(WebhookEvent::SubscriptionUpdated(change_from_subscription(
                sub, None,
            )?))
        }
        "customer.subscription.deleted" => {
            let sub: RawSubscriptionObject = serde_json::from_value(raw.data.object)
                .map_err(|e| BillingError::MalformedPayload(e.to_string()))?;
            Ok(WebhookEvent::SubscriptionDeleted(change_from_subscription(
                sub,
                Some(SubscriptionStatus::Canceled),
            )?))
        }
        other => Ok(WebhookEvent::Other(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription_event(event_type: &str, status: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": "evt_123",
            "type": event_type,
            "data": {
                "object": {
                    "id": "sub_abc",
                    "customer": "cus_xyz",
                    "status": status,
                    "metadata": {
                        "org_id": "org-42",
                        "product": "ferrvault",
                        "tier": "team"
                    }
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn parses_subscription_updated() {
        let body = subscription_event("customer.subscription.updated", "active");
        let event = parse_event(&body).unwrap();
        let WebhookEvent::SubscriptionUpdated(change) = event else {
            panic!("expected SubscriptionUpdated, got {event:?}");
        };
        assert_eq!(change.org_id, "org-42");
        assert_eq!(change.product, Product::FerrVault);
        assert_eq!(change.tier, Plan::Team);
        assert_eq!(change.status, SubscriptionStatus::Active);
        assert_eq!(change.stripe_subscription_id, "sub_abc");
        assert_eq!(change.stripe_customer_id, "cus_xyz");
    }

    #[test]
    fn subscription_deleted_forces_canceled_status() {
        let body = subscription_event("customer.subscription.deleted", "active");
        let event = parse_event(&body).unwrap();
        let WebhookEvent::SubscriptionDeleted(change) = event else {
            panic!("expected SubscriptionDeleted");
        };
        assert_eq!(change.status, SubscriptionStatus::Canceled);
    }

    #[test]
    fn parses_invoice_paid_with_line_metadata() {
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_1",
            "type": "invoice.paid",
            "data": {
                "object": {
                    "customer": "cus_1",
                    "subscription": "sub_1",
                    "metadata": {},
                    "lines": {
                        "data": [{
                            "subscription": "sub_1",
                            "metadata": {
                                "org_id": "org-7",
                                "product": "ferrtrack",
                                "tier": "pro"
                            }
                        }]
                    }
                }
            }
        }))
        .unwrap();

        let event = parse_event(&body).unwrap();
        let WebhookEvent::InvoicePaid(change) = event else {
            panic!("expected InvoicePaid");
        };
        assert_eq!(change.org_id, "org-7");
        assert_eq!(change.product, Product::FerrTrack);
        assert_eq!(change.tier, Plan::Pro);
        assert_eq!(change.status, SubscriptionStatus::Active);
        assert_eq!(change.stripe_subscription_id, "sub_1");
    }

    #[test]
    fn unknown_event_type_is_other() {
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_9",
            "type": "payment_intent.succeeded",
            "data": { "object": {} }
        }))
        .unwrap();
        let event = parse_event(&body).unwrap();
        assert_eq!(
            event,
            WebhookEvent::Other("payment_intent.succeeded".to_string())
        );
    }

    #[test]
    fn missing_org_metadata_is_an_error() {
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_2",
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_x",
                    "customer": "cus_x",
                    "status": "active",
                    "metadata": { "product": "ferrvault", "tier": "pro" }
                }
            }
        }))
        .unwrap();
        let err = parse_event(&body).unwrap_err();
        assert!(matches!(err, BillingError::MissingField("metadata.org_id")));
    }

    #[test]
    fn unknown_product_slug_is_an_error() {
        let body = subscription_event("customer.subscription.updated", "active");
        let body = String::from_utf8(body)
            .unwrap()
            .replace("ferrvault", "ferrnope");
        let err = parse_event(body.as_bytes()).unwrap_err();
        assert!(matches!(
            err,
            BillingError::MissingField("metadata.product (unknown slug)")
        ));
    }

    #[test]
    fn missing_tier_defaults_to_free() {
        let body = serde_json::to_vec(&serde_json::json!({
            "id": "evt_3",
            "type": "customer.subscription.updated",
            "data": {
                "object": {
                    "id": "sub_y",
                    "customer": "cus_y",
                    "status": "trialing",
                    "metadata": { "org_id": "org-1", "product": "ferrfleet" }
                }
            }
        }))
        .unwrap();
        let WebhookEvent::SubscriptionUpdated(change) = parse_event(&body).unwrap() else {
            panic!("expected SubscriptionUpdated");
        };
        assert_eq!(change.tier, Plan::Free);
        assert_eq!(change.status, SubscriptionStatus::Trialing);
    }

    #[test]
    fn malformed_json_is_an_error() {
        let err = parse_event(b"not json").unwrap_err();
        assert!(matches!(err, BillingError::MalformedPayload(_)));
    }
}
