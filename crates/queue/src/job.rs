use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Strongly-typed wrapper around a job's `id` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JobId(pub Uuid);

impl JobId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Uuid> for JobId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<JobId> for Uuid {
    fn from(value: JobId) -> Self {
        value.0
    }
}

/// Lifecycle of a job row.
///
/// Transitions: `queued -> running -> done | failed | dead`. A failed job
/// returns to `queued` semantics via `run_at` once the worker reschedules
/// it (the actual status flips to `failed` so the row is still selectable
/// by the poll query but stays distinguishable for observability).
/// `cancelled` and `dead` are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Failed,
    Cancelled,
    Dead,
}

impl JobStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Dead => "dead",
        }
    }

    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Cancelled | Self::Dead)
    }
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when a status string from the database doesn't match
/// any known [`JobStatus`] variant.
#[derive(Debug, thiserror::Error)]
#[error("unknown job status: {0}")]
pub struct UnknownJobStatus(pub String);

impl std::str::FromStr for JobStatus {
    type Err = UnknownJobStatus;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "done" => Ok(Self::Done),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "dead" => Ok(Self::Dead),
            other => Err(UnknownJobStatus(other.to_owned())),
        }
    }
}

/// A claimed job handed to [`Worker::handle`](crate::worker::Worker::handle).
///
/// The `payload` has already been deserialized into the type associated
/// with the worker's queue.
#[derive(Debug, Clone)]
pub struct Job<P> {
    pub id: JobId,
    pub payload: P,
    pub attempt: u32,
    pub max_attempts: u32,
    pub queue: String,
    pub org_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub run_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Untyped row used by [`Queue::list`](crate::queue::Queue::list) for
/// admin / debugging surfaces that need to inspect jobs across queues
/// without knowing the payload type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobMeta {
    pub id: JobId,
    pub queue: String,
    pub status: JobStatus,
    pub priority: i32,
    pub attempts: u32,
    pub max_attempts: u32,
    pub run_at: DateTime<Utc>,
    pub locked_at: Option<DateTime<Utc>>,
    pub locked_by: Option<String>,
    pub last_error: Option<String>,
    pub idempotency_key: Option<String>,
    pub org_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub payload: serde_json::Value,
}

/// Compute the retry delay in seconds for a given attempt number.
///
/// Exponential — `2^attempt` — capped at one hour. `attempt` is the
/// 1-indexed attempt that just failed (i.e. the value already
/// incremented by the claim query).
#[must_use]
pub fn backoff_seconds(attempt: u32) -> u64 {
    let raw = 2_u64.saturating_pow(attempt);
    raw.min(3600)
}
