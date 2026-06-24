//! Thin wrapper over the Stripe API for the FerrLabs per-product subscription
//! model: one [`Customer`](stripe::Customer) per org, one
//! [`Subscription`](stripe::Subscription) per (org, product) pair.
//!
//! The secret key is supplied by the consumer (read from Vault / env at API
//! startup) and never sourced from a process-global here.

use ferrlabs_types::{Plan, Product};
use stripe::{
    CancelSubscription, Client, CreateCustomer, CreateSubscription, CreateSubscriptionItems,
    Customer, CustomerId, Subscription, SubscriptionId, UpdateSubscription,
    UpdateSubscriptionItems,
};

use crate::error::BillingError;

/// Authenticated handle to the Stripe API.
#[derive(Clone)]
pub struct BillingClient {
    client: Client,
}

/// The Stripe price to attach for a given (product, tier). The price IDs live
/// in product config (one per tier), so the caller resolves them and hands the
/// ID in — this crate stays free of any hard-coded Stripe object IDs.
#[derive(Debug, Clone)]
pub struct PlanPrice {
    pub product: Product,
    pub tier: Plan,
    pub price_id: String,
}

impl BillingClient {
    /// Build a client from a Stripe secret key (`sk_live_…` / `sk_test_…`).
    #[must_use]
    pub fn new(secret_key: &str) -> Self {
        Self {
            client: Client::new(secret_key),
        }
    }

    /// Find the Stripe customer already linked to an org, or create one.
    ///
    /// `existing_customer_id` is whatever we have persisted for the org (the
    /// `stripe_customer_id` column); pass `None` for an org that has never been
    /// billed. The org id and email are stamped into metadata so webhook events
    /// can be routed back to the org without a DB lookup.
    ///
    /// # Errors
    /// Returns [`BillingError::Stripe`] if the API call fails.
    pub async fn ensure_customer(
        &self,
        org_id: &str,
        email: &str,
        existing_customer_id: Option<&str>,
    ) -> Result<Customer, BillingError> {
        if let Some(id) = existing_customer_id {
            let customer_id: CustomerId = id
                .parse()
                .map_err(|_| BillingError::MissingField("stripe_customer_id"))?;
            return Ok(Customer::retrieve(&self.client, &customer_id, &[]).await?);
        }

        let mut params = CreateCustomer::new();
        params.email = Some(email);
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("org_id".to_string(), org_id.to_string());
        params.metadata = Some(metadata);

        Ok(Customer::create(&self.client, params).await?)
    }

    /// Create a subscription for a (customer, product price). Stamps org and
    /// product metadata onto the subscription so webhooks resolve cleanly.
    ///
    /// # Errors
    /// Returns [`BillingError::Stripe`] if the API call fails.
    pub async fn create_subscription(
        &self,
        customer_id: &str,
        org_id: &str,
        plan: &PlanPrice,
    ) -> Result<Subscription, BillingError> {
        let customer: CustomerId = customer_id
            .parse()
            .map_err(|_| BillingError::MissingField("stripe_customer_id"))?;

        let mut params = CreateSubscription::new(customer);
        params.items = Some(vec![CreateSubscriptionItems {
            price: Some(plan.price_id.clone()),
            ..Default::default()
        }]);
        params.metadata = Some(subscription_metadata(org_id, plan));

        Ok(Subscription::create(&self.client, params).await?)
    }

    /// Swap a subscription onto a new price (tier change). Stripe prorates the
    /// difference by default. The single existing item is replaced.
    ///
    /// # Errors
    /// - [`BillingError::Stripe`] on API failure.
    /// - [`BillingError::MissingField`] if the subscription has no items to swap.
    pub async fn update_tier(
        &self,
        subscription_id: &str,
        org_id: &str,
        plan: &PlanPrice,
    ) -> Result<Subscription, BillingError> {
        let sub_id: SubscriptionId = subscription_id
            .parse()
            .map_err(|_| BillingError::MissingField("stripe_subscription_id"))?;

        let current = Subscription::retrieve(&self.client, &sub_id, &[]).await?;
        let item_id = current
            .items
            .data
            .first()
            .map(|item| item.id.to_string())
            .ok_or(BillingError::MissingField("subscription has no items"))?;

        let mut params = UpdateSubscription::new();
        params.items = Some(vec![UpdateSubscriptionItems {
            id: Some(item_id),
            price: Some(plan.price_id.clone()),
            ..Default::default()
        }]);
        params.metadata = Some(subscription_metadata(org_id, plan));

        Ok(Subscription::update(&self.client, &sub_id, params).await?)
    }

    /// Cancel a subscription immediately.
    ///
    /// # Errors
    /// Returns [`BillingError::Stripe`] if the API call fails.
    pub async fn cancel_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<Subscription, BillingError> {
        let sub_id: SubscriptionId = subscription_id
            .parse()
            .map_err(|_| BillingError::MissingField("stripe_subscription_id"))?;
        Ok(Subscription::cancel(&self.client, &sub_id, CancelSubscription::default()).await?)
    }

    /// Fetch the current state of a subscription.
    ///
    /// # Errors
    /// Returns [`BillingError::Stripe`] if the API call fails.
    pub async fn get_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<Subscription, BillingError> {
        let sub_id: SubscriptionId = subscription_id
            .parse()
            .map_err(|_| BillingError::MissingField("stripe_subscription_id"))?;
        Ok(Subscription::retrieve(&self.client, &sub_id, &[]).await?)
    }
}

fn subscription_metadata(
    org_id: &str,
    plan: &PlanPrice,
) -> std::collections::HashMap<String, String> {
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("org_id".to_string(), org_id.to_string());
    metadata.insert("product".to_string(), plan.product.slug().to_string());
    metadata.insert("tier".to_string(), tier_slug(plan.tier).to_string());
    metadata
}

fn tier_slug(plan: Plan) -> &'static str {
    match plan {
        Plan::Free => "free",
        Plan::Pro => "pro",
        Plan::Team => "team",
        Plan::Enterprise => "enterprise",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_carries_org_product_and_tier() {
        let plan = PlanPrice {
            product: Product::FerrVault,
            tier: Plan::Team,
            price_id: "price_123".to_string(),
        };
        let meta = subscription_metadata("org-9", &plan);
        assert_eq!(meta.get("org_id").map(String::as_str), Some("org-9"));
        assert_eq!(meta.get("product").map(String::as_str), Some("ferrvault"));
        assert_eq!(meta.get("tier").map(String::as_str), Some("team"));
    }

    #[test]
    fn tier_slug_round_trips_every_plan() {
        assert_eq!(tier_slug(Plan::Free), "free");
        assert_eq!(tier_slug(Plan::Pro), "pro");
        assert_eq!(tier_slug(Plan::Team), "team");
        assert_eq!(tier_slug(Plan::Enterprise), "enterprise");
    }
}
