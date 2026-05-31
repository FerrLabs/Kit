#![forbid(unsafe_code)]
//! Append-only audit logging.
//!
//! An [`AuditEntry`] records who ([`Actor`]) did what ([`Action`]) to which
//! resource, when. Entries are written through an [`AuditSink`]; an in-memory
//! sink is provided for tests. A Postgres-backed sink is a deliberate
//! follow-up — see the `sqlx` TODO below.

use chrono::{DateTime, Utc};
use ferrlabs_id::UserId;
use serde::{Deserialize, Serialize};

/// What happened. Closed set, marked non-exhaustive so new variants are an
/// additive (non-breaking) change for downstream matchers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Action {
    Created,
    Read,
    Updated,
    Deleted,
    Rotated,
    TokenMinted,
    TokenRevoked,
    LoginSucceeded,
    LoginFailed,
    PermissionDenied,
}

/// Who performed the action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Actor {
    /// An authenticated human or service user.
    User { id: UserId },
    /// An in-cluster workload identified by a stable name (e.g. operator).
    Cluster { name: String },
    /// The platform itself (background jobs, scheduled tasks).
    System,
}

impl Actor {
    /// Convenience constructor for a [`Actor::User`].
    #[must_use]
    pub fn user(id: UserId) -> Self {
        Self::User { id }
    }
}

/// A single append-only audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: DateTime<Utc>,
    pub actor: Actor,
    pub action: Action,
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
}

impl AuditEntry {
    /// Build an entry stamped with the current time.
    #[must_use]
    pub fn now(actor: Actor, action: Action, resource: impl Into<String>) -> Self {
        Self {
            at: Utc::now(),
            actor,
            action,
            resource: resource.into(),
            detail: None,
        }
    }

    /// Build an entry with an explicit timestamp (deterministic for tests).
    #[must_use]
    pub fn at(
        at: DateTime<Utc>,
        actor: Actor,
        action: Action,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            at,
            actor,
            action,
            resource: resource.into(),
            detail: None,
        }
    }

    /// Attach a free-form detail string.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Errors a sink may return when writing.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuditError {
    /// The underlying backend rejected the write.
    Backend(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(e) => write!(f, "audit backend error: {e}"),
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Backend(e) => Some(e.as_ref()),
        }
    }
}

/// Destination for audit entries. Append-only by contract.
pub trait AuditSink: Send + Sync {
    /// Append a single entry.
    ///
    /// # Errors
    /// Returns [`AuditError`] if the backend fails to persist the entry.
    fn append(&self, entry: AuditEntry) -> Result<(), AuditError>;
}

/// In-memory [`AuditSink`] that preserves insertion order. For tests.
#[derive(Default)]
pub struct InMemoryAuditSink {
    entries: std::sync::Mutex<Vec<AuditEntry>>,
}

impl InMemoryAuditSink {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of recorded entries, in append order.
    #[must_use]
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().expect("audit lock poisoned").clone()
    }

    /// Number of recorded entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().expect("audit lock poisoned").len()
    }

    /// Whether no entries have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AuditSink for InMemoryAuditSink {
    fn append(&self, entry: AuditEntry) -> Result<(), AuditError> {
        self.entries
            .lock()
            .expect("audit lock poisoned")
            .push(entry);
        Ok(())
    }
}

// TODO(Kit): add a feature-gated sqlx-backed AuditSink once the audit_log
// table schema is agreed across product APIs.

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    #[test]
    fn entries_append_in_order() {
        let sink = InMemoryAuditSink::new();
        sink.append(AuditEntry::at(
            ts(1),
            Actor::System,
            Action::Created,
            "vault/a",
        ))
        .unwrap();
        sink.append(AuditEntry::at(
            ts(2),
            Actor::user(UserId::nil()),
            Action::Read,
            "vault/a",
        ))
        .unwrap();

        let got = sink.entries();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].action, Action::Created);
        assert_eq!(got[1].action, Action::Read);
        assert_eq!(got[0].at, ts(1));
        assert_eq!(got[1].at, ts(2));
    }

    #[test]
    fn entry_serialization_is_stable() {
        let entry = AuditEntry::at(
            ts(1_700_000_000),
            Actor::System,
            Action::Rotated,
            "secret/x",
        )
        .with_detail("scheduled");
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains(r#""actor":{"kind":"system"}"#));
        assert!(json.contains(r#""action":"rotated""#));
        assert!(json.contains(r#""resource":"secret/x""#));
        assert!(json.contains(r#""detail":"scheduled""#));

        let back: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entry);
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }

    #[test]
    fn detail_omitted_when_absent() {
        let entry = AuditEntry::at(ts(0), Actor::System, Action::LoginFailed, "auth");
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("detail"));
    }

    #[test]
    fn user_actor_round_trips() {
        let uid = UserId::new_v7();
        let entry = AuditEntry::at(ts(5), Actor::user(uid), Action::TokenMinted, "token/1");
        let json = serde_json::to_string(&entry).unwrap();
        let back: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.actor, Actor::user(uid));
    }

    #[test]
    fn cluster_actor_round_trips() {
        let entry = AuditEntry::at(
            ts(5),
            Actor::Cluster {
                name: "vault-operator".into(),
            },
            Action::Read,
            "secret/y",
        );
        let json = serde_json::to_string(&entry).unwrap();
        let back: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entry);
    }
}
