//! Shared domain types for the FerrLabs platform.
//!
//! Every Cloud repo (FerrFlow-Cloud, FerrVault-Cloud, FerrLabs-Cloud) consumes
//! these types via the Kit workspace dependency, so `User`, `Organization`,
//! and friends are guaranteed byte-compatible across products.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A user of the FerrLabs platform — unified across all products.
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
    /// Per-product authorization — an admin of Flow may be a viewer of Vault.
    pub ferrflow_role: Option<Role>,
    pub ferrvault_role: Option<Role>,
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

/// Subscription plan — one per (organization, product).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plan {
    Free,
    Team,
    Business,
    Enterprise,
}

/// Which FerrLabs product a subscription or permission applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Product {
    FerrFlow,
    FerrVault,
}
