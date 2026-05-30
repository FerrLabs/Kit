use thiserror::Error;

/// Errors returned by the queue API surface (`Queue::enqueue`,
/// `Queue::cancel`, `Queue::list`, `Queue::migrate`).
#[derive(Debug, Error)]
pub enum QueueError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("payload serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("job not found: {0}")]
    JobNotFound(uuid::Uuid),

    #[error("worker channel closed")]
    WorkerChannelClosed,
}

/// Convenience alias for results returned by the queue API.
pub type QueueResult<T> = Result<T, QueueError>;

/// Error returned by a [`Worker::handle`](crate::worker::Worker::handle)
/// implementation.
///
/// The variant decides whether the job will be rescheduled (`Retriable`)
/// or buried as `dead` immediately without further attempts (`Permanent`).
/// A `Retriable` error that has exhausted `max_attempts` is also moved to
/// `dead`.
#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("retriable: {0}")]
    Retriable(#[source] anyhow::Error),

    #[error("permanent: {0}")]
    Permanent(#[source] anyhow::Error),
}

impl WorkerError {
    /// Wrap any error as a [`WorkerError::Retriable`] — the worker loop
    /// will reschedule the job with exponential backoff until
    /// `max_attempts` is reached.
    pub fn retriable<E: Into<anyhow::Error>>(err: E) -> Self {
        Self::Retriable(err.into())
    }

    /// Wrap any error as a [`WorkerError::Permanent`] — the worker loop
    /// will mark the job as `dead` immediately and stop retrying.
    pub fn permanent<E: Into<anyhow::Error>>(err: E) -> Self {
        Self::Permanent(err.into())
    }
}
