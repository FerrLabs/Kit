//! Postgres-backed durable job queue for `FerrLabs` services.
//!
//! The crate exposes a small typed API on top of a single `jobs` table.
//! Every product API already ships a `PgPool` via
//! [`ferrlabs-db`](https://github.com/FerrLabs/Kit) — `ferrlabs-queue`
//! borrows that pool and uses `FOR UPDATE SKIP LOCKED` to coordinate
//! multiple workers without any extra infrastructure. `LISTEN / NOTIFY`
//! provides sub-second wake-up on enqueue.
//!
//! ## Quick start
//!
//! ```ignore
//! use ferrlabs_queue::{Queue, Payload, Worker, WorkerError, EnqueueOptions, WorkerConfig, Job};
//! use std::sync::Arc;
//! use uuid::Uuid;
//!
//! #[derive(serde::Serialize, serde::Deserialize)]
//! struct SendWelcomeEmail { user_id: Uuid, template: String }
//!
//! impl Payload for SendWelcomeEmail {
//!     const QUEUE: &'static str = "email.send";
//! }
//!
//! struct EmailWorker;
//!
//! #[async_trait::async_trait]
//! impl Worker<SendWelcomeEmail> for EmailWorker {
//!     async fn handle(&self, job: Job<SendWelcomeEmail>) -> Result<(), WorkerError> {
//!         println!("sending {} to {}", job.payload.template, job.payload.user_id);
//!         Ok(())
//!     }
//! }
//!
//! # async fn boot(pool: sqlx::PgPool) -> anyhow::Result<()> {
//! Queue::<SendWelcomeEmail>::migrate(&pool).await?;
//! let q = Queue::<SendWelcomeEmail>::new(pool.clone());
//! let _handle = q.spawn_worker(EmailWorker, WorkerConfig::default()).await;
//! q.enqueue(
//!     SendWelcomeEmail { user_id: Uuid::nil(), template: "welcome".into() },
//!     EnqueueOptions::default(),
//! ).await?;
//! # Ok(()) }
//! ```
//!
//! ## Semantics
//!
//! - At-least-once delivery. Use `EnqueueOptions::idempotency_key` to
//!   make enqueues safe to retry; use idempotent handlers (or your own
//!   dedup table) inside `Worker::handle`.
//! - Retries are exponential (`2^attempt` seconds, capped at one hour)
//!   on `WorkerError::Retriable`. `Permanent` errors bury immediately.
//! - A `running` job whose `locked_at` is older than
//!   `WorkerConfig::stale_after` is reclaimed by the sweeper — protects
//!   against pod kills, OOMs, and network partitions.
//! - `Queue::migrate` is idempotent. Call it once during API startup,
//!   before spawning workers; safe to ship on every deploy.

pub mod error;
pub mod job;
pub mod queue;
mod schema;
pub mod worker;

pub use error::{QueueError, QueueResult, WorkerError};
pub use job::{Job, JobId, JobMeta, JobStatus, backoff_seconds};
pub use queue::{EnqueueOptions, JobFilter, Queue};
pub use worker::{Worker, WorkerConfig, WorkerHandle};

/// Marker trait that pairs a serializable payload type with its queue
/// name.
///
/// `QUEUE` is the logical channel name — every producer and consumer
/// for the same kind of job must use the same constant.
pub trait Payload: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static {
    const QUEUE: &'static str;
}
