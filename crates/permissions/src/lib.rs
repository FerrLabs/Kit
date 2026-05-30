//! Typed scope + capability system for the FerrLabs platform.
//!
//! Every authorisation decision in a FerrLabs API — beyond "is the
//! caller logged in" — should resolve to a [`Scope`]. Free-form scope
//! strings (`"secrets:read"`, `"agents:run"`, …) are forbidden in new
//! code: they're typo-prone, can't be enumerated at compile time, and
//! make grep-for-callers a guessing game. Adding a new scope is an
//! explicit edit to this enum, surfaced in code review.
//!
//! # Wiring overview
//!
//! ```text
//!   Login                        API token created
//!     │                            │
//!     ▼                            ▼
//!   Session  ────► AuthSource ◄──── ApiToken
//!     │              │                │
//!     │              │ (carries scopes: Vec<String> in DB,
//!     │              │  parsed via Scope::parse_or_unknown)
//!     │              ▼
//!     │           ScopeSet ──► .require(Scope::SecretsWrite)
//!     │                            │
//!     │                            ▼
//!     │                        Ok / AccessDenied
//!     ▼
//!   ScopeSet::full_session()  // sessions get every scope implicitly
//! ```
//!
//! # Migration from free-form strings
//!
//! Existing code calls `AuthUser::require_scope("secrets:read")`. The
//! migration is mechanical: add `use ferrlabs_permissions::Scope;` and
//! replace the call with `auth.require(Scope::SecretsRead)`. The string
//! representation (`Scope::SecretsRead.as_str() == "secrets:read"`) is
//! kept stable so existing DB rows in `api_tokens.scope text[]` keep
//! working without a data migration.

#![forbid(unsafe_code)]

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::collections::HashSet;
use std::marker::PhantomData;

/// Closed set of scopes recognised across the FerrLabs platform.
///
/// String form is the **stable on-the-wire identifier** — used in:
/// - `api_tokens.scope text[]` column (Postgres)
/// - `Authorization: Bearer …` JWT claims (`scope` space-separated, OIDC §3.1.2)
/// - `/v1/userinfo` claim filtering
///
/// **Do not reorder** the variants — `serde` defaults preserve order,
/// but the `as_str` / `parse` mapping is what the wire sees and that
/// must not break across releases.
///
/// **Adding a new variant**: if a product needs a new scope, add it
/// here and bump the `ferrlabs-permissions` minor. Don't fork or
/// extend with a sidecar enum — the closed enum is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    // -----------------------------------------------------------------
    // Cross-product platform scopes
    // -----------------------------------------------------------------
    /// FerrLabs staff access — gates `/api/v1/admin/*` endpoints.
    /// Granted only to users with `users.is_staff = true`. Does NOT
    /// imply any product or org scopes — staff still need explicit
    /// org membership to act on org data, except through dedicated
    /// admin endpoints that document the override.
    StaffAccess,

    /// Org owner — full control of an org including delete + transfer
    /// ownership. Granted by `org_members.role = 'owner'`.
    OrgOwner,
    /// Org admin — manage members, roles, settings. Cannot delete the
    /// org or transfer ownership.
    OrgAdmin,
    /// Org member — read everything in the org, write what their
    /// per-product roles allow. Default for invited users.
    OrgMember,
    /// Org billing — view invoices, manage payment methods, change
    /// subscription tier. Decoupled from admin so finance roles can
    /// do their job without org-wide write access.
    OrgBilling,
    /// Org auditor — read-only access to audit log + member list +
    /// security settings. For compliance review, doesn't grant any
    /// data-plane scope.
    OrgAuditor,

    // -----------------------------------------------------------------
    // FerrVault — secrets management
    // -----------------------------------------------------------------
    SecretsRead,
    SecretsWrite,
    SecretsAdmin,

    // -----------------------------------------------------------------
    // FerrTrack — issue tracker
    // -----------------------------------------------------------------
    IssuesRead,
    IssuesWrite,
    IssuesAdmin,

    // -----------------------------------------------------------------
    // FerrGrowth — sites
    // -----------------------------------------------------------------
    SitesRead,
    SitesWrite,
    SitesAdmin,

    // -----------------------------------------------------------------
    // FerrFleet — agents
    // -----------------------------------------------------------------
    /// Read agent catalog, run history, transcripts.
    AgentsRead,
    /// Trigger an agent run. Combined with read for "use the platform".
    AgentsRun,
    /// Mutate agents, schedules, skills. Org-admin equivalent.
    AgentsAdmin,

    // -----------------------------------------------------------------
    // API tokens — meta-scope for managing tokens themselves
    // -----------------------------------------------------------------
    /// Create / rotate / delete API tokens. Held by users (not by the
    /// tokens themselves — a token can't grant or revoke another).
    TokensManage,
}

impl Scope {
    /// Stable on-the-wire identifier. Stored verbatim in
    /// `api_tokens.scope text[]` and emitted in JWT `scope` claims.
    /// Reorder-safe — `match` on the variant, not the index.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaffAccess => "staff:access",
            Self::OrgOwner => "org:owner",
            Self::OrgAdmin => "org:admin",
            Self::OrgMember => "org:member",
            Self::OrgBilling => "org:billing",
            Self::OrgAuditor => "org:auditor",
            Self::SecretsRead => "secrets:read",
            Self::SecretsWrite => "secrets:write",
            Self::SecretsAdmin => "secrets:admin",
            Self::IssuesRead => "issues:read",
            Self::IssuesWrite => "issues:write",
            Self::IssuesAdmin => "issues:admin",
            Self::SitesRead => "sites:read",
            Self::SitesWrite => "sites:write",
            Self::SitesAdmin => "sites:admin",
            Self::AgentsRead => "agents:read",
            Self::AgentsRun => "agents:run",
            Self::AgentsAdmin => "agents:admin",
            Self::TokensManage => "tokens:manage",
        }
    }

    /// Parse a scope string into the typed enum. Returns `None` for
    /// unknown strings — callers decide whether to log + skip
    /// (tolerant: a future deploy added a scope this binary doesn't
    /// know about) or refuse the whole token (strict: stale string in
    /// the DB shouldn't silently grant nothing).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "staff:access" => Self::StaffAccess,
            "org:owner" => Self::OrgOwner,
            "org:admin" => Self::OrgAdmin,
            "org:member" => Self::OrgMember,
            "org:billing" => Self::OrgBilling,
            "org:auditor" => Self::OrgAuditor,
            "secrets:read" => Self::SecretsRead,
            "secrets:write" => Self::SecretsWrite,
            "secrets:admin" => Self::SecretsAdmin,
            "issues:read" => Self::IssuesRead,
            "issues:write" => Self::IssuesWrite,
            "issues:admin" => Self::IssuesAdmin,
            "sites:read" => Self::SitesRead,
            "sites:write" => Self::SitesWrite,
            "sites:admin" => Self::SitesAdmin,
            "agents:read" => Self::AgentsRead,
            "agents:run" => Self::AgentsRun,
            "agents:admin" => Self::AgentsAdmin,
            "tokens:manage" => Self::TokensManage,
            _ => return None,
        })
    }

    /// Every scope this enum knows about. Used by sessions
    /// (`ScopeSet::full_session`) — a logged-in human gets the full
    /// set implicitly; only programmatic API tokens are scope-restricted.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::StaffAccess,
            Self::OrgOwner,
            Self::OrgAdmin,
            Self::OrgMember,
            Self::OrgBilling,
            Self::OrgAuditor,
            Self::SecretsRead,
            Self::SecretsWrite,
            Self::SecretsAdmin,
            Self::IssuesRead,
            Self::IssuesWrite,
            Self::IssuesAdmin,
            Self::SitesRead,
            Self::SitesWrite,
            Self::SitesAdmin,
            Self::AgentsRead,
            Self::AgentsRun,
            Self::AgentsAdmin,
            Self::TokensManage,
        ]
    }

    /// Read-implies relationship — `SecretsAdmin` grants
    /// `SecretsWrite` which grants `SecretsRead`, etc. Used by
    /// `ScopeSet::has` to keep callers from listing every level.
    #[must_use]
    pub fn implies(self, other: Self) -> bool {
        if self == other {
            return true;
        }
        matches!(
            (self, other),
            (Self::SecretsAdmin, Self::SecretsWrite | Self::SecretsRead)
                | (Self::SecretsWrite, Self::SecretsRead)
                | (Self::IssuesAdmin, Self::IssuesWrite | Self::IssuesRead)
                | (Self::IssuesWrite, Self::IssuesRead)
                | (Self::SitesAdmin, Self::SitesWrite | Self::SitesRead)
                | (Self::SitesWrite, Self::SitesRead)
                | (Self::AgentsAdmin, Self::AgentsRun | Self::AgentsRead)
                | (Self::AgentsRun, Self::AgentsRead)
                | (
                    Self::OrgOwner,
                    Self::OrgAdmin | Self::OrgMember | Self::OrgBilling | Self::OrgAuditor,
                )
                | (Self::OrgAdmin, Self::OrgMember | Self::OrgAuditor)
        )
    }
}

impl Serialize for Scope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        Self::parse(s).ok_or_else(|| de::Error::unknown_variant(s, &["<see Scope::as_str>"]))
    }
}

/// Resource-scoped authorization primitives.
///
/// API handlers across the FerrLabs platform repeatedly hand-write
/// `WHERE id = $1 AND project_id = $2` to enforce tenant isolation —
/// load a row, check its parent matches the caller's parent, return 404
/// if not. The [`Resource`] trait centralises that contract so a future
/// DB-backed extractor can do it once and hand back a [`ScopedResource`]
/// that's already proven to belong to the caller's parent scope.
///
/// v0.1 ships the trait and the wrapper type only. The extractor lands
/// in a follow-up alongside the FerrLabs-Cloud wire-up
/// (`FerrLabs/FerrLabs-Cloud#362`).
///
/// # Defining a resource
///
/// ```text
/// struct Vault;
/// impl Resource for Vault {
///     type Id = Uuid;
///     type ParentId = Uuid;
///     const TABLE: &'static str = "vaults";
///     const PARENT_ID_COL: &'static str = "org_id";
/// }
/// ```
pub trait Resource {
    type Id: Copy + Send + Sync + 'static;
    type ParentId: Copy + Send + Sync + 'static;

    const TABLE: &'static str;
    const ID_COL: &'static str = "id";
    const PARENT_ID_COL: &'static str;
}

/// A reference to a [`Resource`] bound to its verified parent.
///
/// Built by the future DB-backed extractor; until that ships, consumers
/// construct one via [`ScopedResource::new`] after running their own
/// parent check. The wrapper exists so handler signatures can already
/// adopt the final API and migrate to the extractor without churn.
#[derive(Debug)]
pub struct ScopedResource<R: Resource> {
    pub parent_id: R::ParentId,
    pub id: R::Id,
    _phantom: PhantomData<fn() -> R>,
}

impl<R: Resource> ScopedResource<R> {
    #[must_use]
    pub fn new(parent_id: R::ParentId, id: R::Id) -> Self {
        Self {
            parent_id,
            id,
            _phantom: PhantomData,
        }
    }

    #[must_use]
    pub fn id(&self) -> R::Id {
        self.id
    }

    #[must_use]
    pub fn parent_id(&self) -> R::ParentId {
        self.parent_id
    }
}

impl<R: Resource> Clone for ScopedResource<R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R: Resource> Copy for ScopedResource<R> {}

/// A set of scopes attached to a session or API token. O(1) lookup
/// with implication-aware `has`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeSet {
    inner: HashSet<Scope>,
}

impl ScopeSet {
    /// Empty set — used by tokens that explicitly granted nothing
    /// (probably a misconfigured token; the caller will get
    /// `AccessDenied` on every check, which is correct).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Full set — every known scope. Used by interactive user
    /// sessions: a logged-in human is trusted with everything they
    /// can do via the UI (which is necessarily scoped by the UI's
    /// own permission checks anyway). API tokens are the only
    /// principals that need narrow scopes.
    #[must_use]
    pub fn full_session() -> Self {
        Self {
            inner: Scope::all().iter().copied().collect(),
        }
    }

    /// Build from a list of scope strings (typical: `api_tokens.scope`
    /// column). Unknown strings are ignored — the caller's binary
    /// might predate the scope's introduction.
    #[must_use]
    pub fn from_strings<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            inner: scopes
                .into_iter()
                .filter_map(|s| Scope::parse(s.as_ref()))
                .collect(),
        }
    }

    /// Wildcard `"*"` is recognised as full session — historical
    /// behaviour for staff-issued super-tokens. Use sparingly.
    #[must_use]
    pub fn from_strings_with_wildcard<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut wildcard = false;
        let parsed: HashSet<Scope> = scopes
            .into_iter()
            .filter_map(|s| {
                let s = s.as_ref();
                if s == "*" {
                    wildcard = true;
                    None
                } else {
                    Scope::parse(s)
                }
            })
            .collect();
        if wildcard {
            Self::full_session()
        } else {
            Self { inner: parsed }
        }
    }

    /// True if this set grants `scope` either directly or via an
    /// implication (e.g. `SecretsAdmin` → `SecretsRead`).
    #[must_use]
    pub fn has(&self, scope: Scope) -> bool {
        self.inner.iter().any(|granted| granted.implies(scope))
    }

    /// `Ok` if the set has the scope, `Err(AccessDenied)` otherwise.
    /// Idiomatic in handlers: `auth.scopes().require(Scope::SecretsWrite)?;`
    pub fn require(&self, scope: Scope) -> Result<(), AccessDenied> {
        if self.has(scope) {
            Ok(())
        } else {
            Err(AccessDenied { missing: scope })
        }
    }

    /// Add a scope (returns true if newly inserted). Useful when
    /// building a set programmatically (e.g. tests, or layering scopes
    /// from multiple sources).
    pub fn insert(&mut self, scope: Scope) -> bool {
        self.inner.insert(scope)
    }

    /// Iterator over the granted scopes, sorted for deterministic
    /// output in JWT claims and audit logs.
    pub fn iter(&self) -> impl Iterator<Item = Scope> + '_ {
        let mut v: Vec<Scope> = self.inner.iter().copied().collect();
        v.sort_by_key(|s| s.as_str());
        v.into_iter()
    }

    /// Render as a space-separated list of stable strings — the
    /// OIDC §3.1.2 wire format for the `scope` claim.
    #[must_use]
    pub fn to_oidc_scope_string(&self) -> String {
        let mut parts: Vec<&'static str> = self.inner.iter().map(|s| s.as_str()).collect();
        parts.sort_unstable();
        parts.join(" ")
    }
}

/// Returned by [`ScopeSet::require`] when the set is missing a scope.
/// Convert to your API's error type at the boundary; this crate stays
/// transport-agnostic so it's reusable across axum, lambda, gRPC, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("missing required scope: {missing:?}")]
pub struct AccessDenied {
    pub missing: Scope,
}

impl AccessDenied {
    /// The scope the caller was missing — useful for log lines and
    /// error code mapping.
    #[must_use]
    pub fn missing(self) -> Scope {
        self.missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_every_variant() {
        for scope in Scope::all() {
            assert_eq!(Scope::parse(scope.as_str()), Some(*scope), "{scope:?}");
        }
    }

    #[test]
    fn unknown_scope_string_returns_none() {
        assert!(Scope::parse("not:a:real:scope").is_none());
        assert!(Scope::parse("").is_none());
    }

    #[test]
    fn full_session_grants_everything() {
        let s = ScopeSet::full_session();
        for scope in Scope::all() {
            assert!(s.has(*scope), "full session missing {scope:?}");
        }
    }

    #[test]
    fn empty_grants_nothing() {
        let s = ScopeSet::empty();
        for scope in Scope::all() {
            assert!(!s.has(*scope));
        }
    }

    #[test]
    fn admin_implies_write_implies_read() {
        let mut s = ScopeSet::empty();
        s.insert(Scope::SecretsAdmin);
        assert!(s.has(Scope::SecretsAdmin));
        assert!(s.has(Scope::SecretsWrite));
        assert!(s.has(Scope::SecretsRead));
        assert!(!s.has(Scope::IssuesRead));
    }

    #[test]
    fn org_owner_implies_lower_roles() {
        let mut s = ScopeSet::empty();
        s.insert(Scope::OrgOwner);
        assert!(s.has(Scope::OrgAdmin));
        assert!(s.has(Scope::OrgMember));
        assert!(s.has(Scope::OrgAuditor));
        assert!(s.has(Scope::OrgBilling));
    }

    #[test]
    fn org_admin_does_not_imply_billing() {
        let mut s = ScopeSet::empty();
        s.insert(Scope::OrgAdmin);
        assert!(s.has(Scope::OrgMember));
        assert!(s.has(Scope::OrgAuditor));
        // Billing is intentionally a separate axis — admins shouldn't
        // automatically be able to change payment methods.
        assert!(!s.has(Scope::OrgBilling));
        assert!(!s.has(Scope::OrgOwner));
    }

    #[test]
    fn require_returns_access_denied_with_missing_scope() {
        let s = ScopeSet::empty();
        let err = s.require(Scope::SecretsWrite).unwrap_err();
        assert_eq!(err.missing(), Scope::SecretsWrite);
    }

    #[test]
    fn from_strings_drops_unknown_silently() {
        let s = ScopeSet::from_strings(["secrets:read", "made:up", "agents:run"]);
        assert!(s.has(Scope::SecretsRead));
        assert!(s.has(Scope::AgentsRun));
    }

    #[test]
    fn wildcard_in_strings_grants_full_session() {
        let s = ScopeSet::from_strings_with_wildcard(["*"]);
        assert!(s.has(Scope::StaffAccess));
        assert!(s.has(Scope::AgentsAdmin));
    }

    #[test]
    fn wildcard_with_other_entries_still_grants_full_session() {
        let s = ScopeSet::from_strings_with_wildcard(["secrets:read", "*", "garbage"]);
        for scope in Scope::all() {
            assert!(s.has(*scope));
        }
    }

    #[test]
    fn oidc_scope_string_is_sorted_space_separated() {
        let mut s = ScopeSet::empty();
        s.insert(Scope::SecretsRead);
        s.insert(Scope::AgentsRun);
        s.insert(Scope::OrgMember);
        let out = s.to_oidc_scope_string();
        assert_eq!(out, "agents:run org:member secrets:read");
    }

    #[test]
    fn serde_uses_colon_wire_form_for_known_variants() {
        assert_eq!(
            serde_json::to_string(&Scope::SecretsRead).unwrap(),
            r#""secrets:read""#
        );
        assert_eq!(
            serde_json::to_string(&Scope::SecretsAdmin).unwrap(),
            r#""secrets:admin""#
        );
        assert_eq!(
            serde_json::to_string(&Scope::AgentsRun).unwrap(),
            r#""agents:run""#
        );
        assert_eq!(
            serde_json::to_string(&Scope::StaffAccess).unwrap(),
            r#""staff:access""#
        );
        assert_eq!(
            serde_json::to_string(&Scope::TokensManage).unwrap(),
            r#""tokens:manage""#
        );
    }

    #[test]
    fn serde_round_trip_matches_as_str_for_every_variant() {
        for scope in Scope::all() {
            let json = serde_json::to_string(scope).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", scope.as_str()),
                "serde diverged from as_str for {scope:?}",
            );
            let parsed: Scope = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *scope, "round-trip lost {scope:?}");
        }
    }

    #[test]
    fn serde_rejects_legacy_snake_case_wire_form() {
        assert!(serde_json::from_str::<Scope>(r#""secrets_read""#).is_err());
        assert!(serde_json::from_str::<Scope>(r#""secrets_admin""#).is_err());
        assert!(serde_json::from_str::<Scope>(r#""agents_run""#).is_err());
        assert!(serde_json::from_str::<Scope>(r#""tokens_manage""#).is_err());
    }

    #[test]
    fn serde_rejects_unknown_scope_string() {
        assert!(serde_json::from_str::<Scope>(r#""not:a:scope""#).is_err());
    }

    struct FakeVault;
    impl Resource for FakeVault {
        type Id = u64;
        type ParentId = u64;
        const TABLE: &'static str = "vaults";
        const PARENT_ID_COL: &'static str = "org_id";
    }

    #[test]
    fn scoped_resource_round_trips_ids() {
        let r: ScopedResource<FakeVault> = ScopedResource::new(42, 7);
        assert_eq!(r.parent_id(), 42);
        assert_eq!(r.id(), 7);
        assert_eq!(FakeVault::TABLE, "vaults");
        assert_eq!(FakeVault::ID_COL, "id");
        assert_eq!(FakeVault::PARENT_ID_COL, "org_id");
        let copied = r;
        assert_eq!(copied.id(), 7);
    }
}
