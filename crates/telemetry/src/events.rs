use chrono::{DateTime, Utc};
use ferrlabs_types::Product;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Ferrlabs,
    Ferrflow,
    Ferrvault,
    Ferrtrack,
    Ferrgrowth,
    Ferrfleet,
}

impl Surface {
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::Ferrlabs => "ferrlabs",
            Self::Ferrflow => "ferrflow",
            Self::Ferrvault => "ferrvault",
            Self::Ferrtrack => "ferrtrack",
            Self::Ferrgrowth => "ferrgrowth",
            Self::Ferrfleet => "ferrfleet",
        }
    }

    #[must_use]
    pub fn all() -> &'static [Surface] {
        &[
            Self::Ferrlabs,
            Self::Ferrflow,
            Self::Ferrvault,
            Self::Ferrtrack,
            Self::Ferrgrowth,
            Self::Ferrfleet,
        ]
    }
}

impl From<Product> for Surface {
    fn from(p: Product) -> Self {
        match p {
            Product::FerrFlow => Self::Ferrflow,
            Product::FerrVault => Self::Ferrvault,
            Product::FerrTrack => Self::Ferrtrack,
            Product::FerrGrowth => Self::Ferrgrowth,
            Product::FerrFleet => Self::Ferrfleet,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    OrgCreated,
    OrgMemberAdded,
    ProductActivated,
    ProductTierChanged,
    ProductCanceled,
    AuthLogin,
    AuthSignup,

    CliRun,
    CliError,

    VaultSecretInjected,
    TrackIssueCreated,
    GrowthSitePublished,
    FleetAgentRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Hash,
    Enum,
    Int,
    String,
    Bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Field {
    pub name: &'static str,
    pub kind: FieldType,
    pub doc: &'static str,
}

impl Field {
    #[must_use]
    pub const fn new(name: &'static str, kind: FieldType, doc: &'static str) -> Self {
        Self { name, kind, doc }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct EventMeta {
    pub event: Event,
    pub when_it_fires: &'static str,
    pub fields: &'static [Field],
}

const FIELDS_ORG_CREATED: &[Field] = &[
    Field::new("org_hash", FieldType::Hash, "BLAKE3-keyed(org_id)."),
    Field::new(
        "user_hash",
        FieldType::Hash,
        "BLAKE3-keyed(user_id) of the creator.",
    ),
];

const FIELDS_ORG_MEMBER_ADDED: &[Field] = &[
    Field::new("org_hash", FieldType::Hash, "BLAKE3-keyed(org_id)."),
    Field::new(
        "actor_hash",
        FieldType::Hash,
        "BLAKE3-keyed(user_id) of the actor that added the member.",
    ),
    Field::new(
        "role",
        FieldType::Enum,
        "owner | admin | member | billing | auditor",
    ),
];

const FIELDS_PRODUCT_ACTIVATED: &[Field] = &[
    Field::new("org_hash", FieldType::Hash, "BLAKE3-keyed(org_id)."),
    Field::new(
        "product",
        FieldType::Enum,
        "ferrflow | ferrvault | ferrtrack | ferrgrowth | ferrfleet",
    ),
    Field::new("tier", FieldType::Enum, "free | pro | team | enterprise"),
];

const FIELDS_PRODUCT_TIER_CHANGED: &[Field] = &[
    Field::new("org_hash", FieldType::Hash, "BLAKE3-keyed(org_id)."),
    Field::new("product", FieldType::Enum, "Product slug."),
    Field::new("tier_from", FieldType::Enum, "Previous tier."),
    Field::new("tier_to", FieldType::Enum, "New tier."),
];

const FIELDS_PRODUCT_CANCELED: &[Field] = &[
    Field::new("org_hash", FieldType::Hash, "BLAKE3-keyed(org_id)."),
    Field::new("product", FieldType::Enum, "Product slug."),
];

const FIELDS_AUTH_LOGIN: &[Field] = &[
    Field::new("user_hash", FieldType::Hash, "BLAKE3-keyed(user_id)."),
    Field::new(
        "method",
        FieldType::Enum,
        "password | oauth-google | oauth-github | sso",
    ),
];

const FIELDS_AUTH_SIGNUP: &[Field] = &[
    Field::new("user_hash", FieldType::Hash, "BLAKE3-keyed(user_id)."),
    Field::new("method", FieldType::Enum, "Auth method used."),
];

const FIELDS_CLI_RUN: &[Field] = &[
    Field::new("command", FieldType::Enum, "bump | release | changelog | …"),
    Field::new("exit_code", FieldType::Int, "Process exit code."),
    Field::new("duration_ms", FieldType::Int, "Wall-clock duration."),
    Field::new("cli_version", FieldType::String, "semver."),
    Field::new("os", FieldType::Enum, "linux | macos | windows"),
    Field::new("arch", FieldType::Enum, "x86_64 | aarch64"),
];

const FIELDS_CLI_ERROR: &[Field] = &[
    Field::new("command", FieldType::Enum, "Command that errored."),
    Field::new(
        "error_code",
        FieldType::String,
        "FFXXXX code. The error body is NOT sent.",
    ),
    Field::new("cli_version", FieldType::String, "semver."),
];

const FIELDS_VAULT_SECRET_INJECTED: &[Field] = &[
    Field::new("org_hash", FieldType::Hash, "BLAKE3-keyed(org_id)."),
    Field::new(
        "kind",
        FieldType::Enum,
        "Backend kind: native | external_helm | external_other.",
    ),
];

const FIELDS_TRACK_ISSUE_CREATED: &[Field] = &[
    Field::new("org_hash", FieldType::Hash, "BLAKE3-keyed(org_id)."),
    Field::new(
        "source",
        FieldType::Enum,
        "ui | api | git_link | automation",
    ),
];

const FIELDS_GROWTH_SITE_PUBLISHED: &[Field] = &[
    Field::new("org_hash", FieldType::Hash, "BLAKE3-keyed(org_id)."),
    Field::new(
        "custom_domain",
        FieldType::Bool,
        "True if a custom domain is bound.",
    ),
];

const FIELDS_FLEET_AGENT_RUN: &[Field] = &[
    Field::new("org_hash", FieldType::Hash, "BLAKE3-keyed(org_id)."),
    Field::new("agent_kind", FieldType::Enum, "first_party | custom"),
    Field::new(
        "first_party_slug",
        FieldType::String,
        "Set when agent_kind=first_party.",
    ),
    Field::new("exit_code", FieldType::Int, "0 on success."),
    Field::new("duration_ms", FieldType::Int, "Wall-clock duration."),
];

const ALL_EVENTS: &[Event] = &[
    Event::OrgCreated,
    Event::OrgMemberAdded,
    Event::ProductActivated,
    Event::ProductTierChanged,
    Event::ProductCanceled,
    Event::AuthLogin,
    Event::AuthSignup,
    Event::CliRun,
    Event::CliError,
    Event::VaultSecretInjected,
    Event::TrackIssueCreated,
    Event::GrowthSitePublished,
    Event::FleetAgentRun,
];

impl Event {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::OrgCreated => "org.created",
            Self::OrgMemberAdded => "org.member.added",
            Self::ProductActivated => "product.activated",
            Self::ProductTierChanged => "product.tier_changed",
            Self::ProductCanceled => "product.canceled",
            Self::AuthLogin => "auth.login",
            Self::AuthSignup => "auth.signup",
            Self::CliRun => "cli.run",
            Self::CliError => "cli.error",
            Self::VaultSecretInjected => "vault.secret.injected",
            Self::TrackIssueCreated => "track.issue.created",
            Self::GrowthSitePublished => "growth.site.published",
            Self::FleetAgentRun => "fleet.agent.run",
        }
    }

    #[must_use]
    pub fn surface(self) -> Surface {
        match self {
            Self::OrgCreated
            | Self::OrgMemberAdded
            | Self::ProductActivated
            | Self::ProductTierChanged
            | Self::ProductCanceled
            | Self::AuthLogin
            | Self::AuthSignup => Surface::Ferrlabs,
            Self::CliRun | Self::CliError => Surface::Ferrflow,
            Self::VaultSecretInjected => Surface::Ferrvault,
            Self::TrackIssueCreated => Surface::Ferrtrack,
            Self::GrowthSitePublished => Surface::Ferrgrowth,
            Self::FleetAgentRun => Surface::Ferrfleet,
        }
    }

    #[must_use]
    pub fn fields(self) -> &'static [Field] {
        match self {
            Self::OrgCreated => FIELDS_ORG_CREATED,
            Self::OrgMemberAdded => FIELDS_ORG_MEMBER_ADDED,
            Self::ProductActivated => FIELDS_PRODUCT_ACTIVATED,
            Self::ProductTierChanged => FIELDS_PRODUCT_TIER_CHANGED,
            Self::ProductCanceled => FIELDS_PRODUCT_CANCELED,
            Self::AuthLogin => FIELDS_AUTH_LOGIN,
            Self::AuthSignup => FIELDS_AUTH_SIGNUP,
            Self::CliRun => FIELDS_CLI_RUN,
            Self::CliError => FIELDS_CLI_ERROR,
            Self::VaultSecretInjected => FIELDS_VAULT_SECRET_INJECTED,
            Self::TrackIssueCreated => FIELDS_TRACK_ISSUE_CREATED,
            Self::GrowthSitePublished => FIELDS_GROWTH_SITE_PUBLISHED,
            Self::FleetAgentRun => FIELDS_FLEET_AGENT_RUN,
        }
    }

    #[must_use]
    pub fn when_it_fires(self) -> &'static str {
        match self {
            Self::OrgCreated => "A new organization is created.",
            Self::OrgMemberAdded => "A user is added to an organization.",
            Self::ProductActivated => "An org activates a product subscription.",
            Self::ProductTierChanged => "An active subscription is upgraded or downgraded.",
            Self::ProductCanceled => "A subscription is canceled.",
            Self::AuthLogin => "Successful login.",
            Self::AuthSignup => "A new account is created.",
            Self::CliRun => "Once per CLI invocation, after the command finishes.",
            Self::CliError => "On unhandled error, instead of cli.run.",
            Self::VaultSecretInjected => "FerrVault operator injects a secret into a workload.",
            Self::TrackIssueCreated => "A new issue is created in FerrTrack.",
            Self::GrowthSitePublished => "A FerrGrowth site is (re)published.",
            Self::FleetAgentRun => "A FerrFleet agent run finishes (success or error).",
        }
    }

    #[must_use]
    pub fn meta(self) -> EventMeta {
        EventMeta {
            event: self,
            when_it_fires: self.when_it_fires(),
            fields: self.fields(),
        }
    }

    #[must_use]
    pub fn all() -> &'static [Event] {
        ALL_EVENTS
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub surface: Surface,
    pub event: Event,
    pub org_hash: Option<String>,
    pub user_hash: Option<String>,
    pub properties: BTreeMap<String, serde_json::Value>,
    pub schema_version: u32,
    pub occurred_at: DateTime<Utc>,
}

impl Envelope {
    #[must_use]
    pub fn new(event: Event) -> Self {
        Self {
            surface: event.surface(),
            event,
            org_hash: None,
            user_hash: None,
            properties: BTreeMap::new(),
            schema_version: SCHEMA_VERSION,
            occurred_at: Utc::now(),
        }
    }

    #[must_use]
    pub fn with_org(mut self, hash: String) -> Self {
        self.org_hash = Some(hash);
        self
    }

    #[must_use]
    pub fn with_user(mut self, hash: String) -> Self {
        self.user_hash = Some(hash);
        self
    }

    #[must_use]
    pub fn with_property(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone)]
pub struct Hasher {
    key: [u8; 32],
}

impl std::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hasher")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Hasher {
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn from_hex(hex_key: &str) -> anyhow::Result<Self> {
        let bytes = hex::decode(hex_key)?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("expected 32-byte key, got {} bytes", v.len()))?;
        Ok(Self::new(key))
    }

    #[must_use]
    pub fn hash_uuid(&self, id: Uuid) -> String {
        let mac = blake3::keyed_hash(&self.key, id.as_bytes());
        hex::encode(&mac.as_bytes()[..16])
    }

    #[must_use]
    pub fn hash_bytes(&self, bytes: &[u8]) -> String {
        let mac = blake3::keyed_hash(&self.key, bytes);
        hex::encode(&mac.as_bytes()[..16])
    }
}

#[must_use]
pub fn manifest() -> Vec<EventMeta> {
    Event::all().iter().copied().map(Event::meta).collect()
}

#[must_use]
pub fn manifest_json() -> serde_json::Value {
    serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "events": manifest()
            .iter()
            .map(|m| {
                serde_json::json!({
                    "event": m.event.name(),
                    "surface": m.event.surface().slug(),
                    "when_it_fires": m.when_it_fires,
                    "fields": m.fields.iter().map(|f| serde_json::json!({
                        "name": f.name,
                        "kind": f.kind,
                        "doc": f.doc,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_names_are_unique() {
        let mut names: Vec<&str> = Event::all().iter().map(|e| e.name()).collect();
        names.sort_unstable();
        let len = names.len();
        names.dedup();
        assert_eq!(names.len(), len, "duplicate event names");
    }

    #[test]
    fn meta_covers_every_event() {
        for ev in Event::all() {
            let meta = ev.meta();
            assert_eq!(meta.event.name(), ev.name());
            assert!(
                !meta.when_it_fires.is_empty(),
                "{} missing description",
                ev.name()
            );
        }
    }

    #[test]
    fn surface_slug_matches_serde() {
        for s in Surface::all() {
            let json = serde_json::to_string(s).unwrap();
            assert_eq!(json.trim_matches('"'), s.slug());
        }
    }

    #[test]
    fn envelope_round_trips() {
        let env = Envelope::new(Event::OrgCreated)
            .with_org("abc123".into())
            .with_user("def456".into())
            .with_property("seat_count", 3);
        let json = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event, Event::OrgCreated);
        assert_eq!(back.org_hash.as_deref(), Some("abc123"));
        assert_eq!(back.user_hash.as_deref(), Some("def456"));
        assert_eq!(
            back.properties.get("seat_count"),
            Some(&serde_json::json!(3))
        );
        assert_eq!(back.surface, Surface::Ferrlabs);
    }

    #[test]
    fn hasher_is_deterministic_with_same_key() {
        let key = [42u8; 32];
        let h1 = Hasher::new(key);
        let h2 = Hasher::new(key);
        let id = Uuid::nil();
        assert_eq!(h1.hash_uuid(id), h2.hash_uuid(id));
    }

    #[test]
    fn hasher_changes_when_key_rotates() {
        let id = Uuid::from_u128(0xdead_beef_cafe_babe_0000_0000_0000_0001);
        let a = Hasher::new([1u8; 32]).hash_uuid(id);
        let b = Hasher::new([2u8; 32]).hash_uuid(id);
        assert_ne!(a, b);
    }

    #[test]
    fn hasher_hex_round_trip() {
        let key_hex = "0".repeat(64);
        let h = Hasher::from_hex(&key_hex).unwrap();
        let id = Uuid::from_u128(1);
        let out = h.hash_uuid(id);
        assert_eq!(out.len(), 32);
        assert!(out.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hasher_rejects_wrong_length_hex() {
        assert!(Hasher::from_hex("deadbeef").is_err());
    }

    #[test]
    fn manifest_covers_every_event() {
        let m = manifest();
        assert_eq!(m.len(), Event::all().len());
    }

    #[test]
    fn manifest_json_has_schema_version() {
        let v = manifest_json();
        assert_eq!(v["schema_version"], SCHEMA_VERSION);
        assert!(v["events"].as_array().unwrap().len() >= Event::all().len());
    }

    #[test]
    fn product_maps_to_surface() {
        assert_eq!(Surface::from(Product::FerrFlow), Surface::Ferrflow);
        assert_eq!(Surface::from(Product::FerrVault), Surface::Ferrvault);
        assert_eq!(Surface::from(Product::FerrFleet), Surface::Ferrfleet);
    }
}
