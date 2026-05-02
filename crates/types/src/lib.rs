//! Shared domain types for the `FerrLabs` platform.
//!
//! Every Cloud repo (FerrFlow-Cloud, FerrVault-Cloud, FerrLabs-Cloud) consumes
//! these types via the Kit workspace dependency, so `User`, `Organization`,
//! and friends are guaranteed byte-compatible across products.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A user of the `FerrLabs` platform — unified across all products.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub email_verified_at: Option<DateTime<Utc>>,
}

/// An organization owns projects, billing, and memberships.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// A user's membership in an organization, including per-product roles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    pub user_id: Uuid,
    pub organization_id: Uuid,
    pub role: Role,
    pub ferrflow_role: Option<Role>,
    pub ferrvault_role: Option<Role>,
    pub ferrtrack_role: Option<Role>,
    pub ferrgrowth_role: Option<Role>,
    pub ferrfleet_role: Option<Role>,
    pub joined_at: DateTime<Utc>,
}

/// Coarse role. Product-specific permissions are derived from this in each API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Member,
    Viewer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Plan {
    Free,
    Pro,
    Team,
    Enterprise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Product {
    FerrFlow,
    FerrVault,
    FerrTrack,
    FerrGrowth,
    FerrFleet,
}

impl Product {
    pub fn slug(&self) -> &'static str {
        match self {
            Product::FerrFlow => "ferrflow",
            Product::FerrVault => "ferrvault",
            Product::FerrTrack => "ferrtrack",
            Product::FerrGrowth => "ferrgrowth",
            Product::FerrFleet => "ferrfleet",
        }
    }

    pub fn all() -> &'static [Product] {
        &[
            Product::FerrFlow,
            Product::FerrVault,
            Product::FerrTrack,
            Product::FerrGrowth,
            Product::FerrFleet,
        ]
    }

    pub fn paid() -> &'static [Product] {
        &[
            Product::FerrVault,
            Product::FerrTrack,
            Product::FerrGrowth,
            Product::FerrFleet,
        ]
    }

    pub fn is_paid(&self) -> bool {
        !matches!(self, Product::FerrFlow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Trialing,
    Active,
    PastDue,
    Canceled,
    Incomplete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: Uuid,
    pub org_id: Uuid,
    pub product: Product,
    pub tier: Plan,
    pub status: SubscriptionStatus,
    pub trial_ends_at: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub stripe_subscription_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
