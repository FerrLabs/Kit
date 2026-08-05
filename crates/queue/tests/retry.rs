//! Integration test: worker retry / dead-letter semantics against a real
//! Postgres.
//!
//! Requires Docker (or `TEST_DATABASE_URL`) via `ferrlabs-testkit`, so this
//! whole file is gated behind the `integration` feature and each test is
//! `#[ignore]`d:
//!
//! ```bash
//! cargo test -p ferrlabs-queue --features integration -- --ignored
//! ```
#![cfg(feature = "integration")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use ferrlabs_queue::{EnqueueOptions, Job, Payload, Queue, Worker, WorkerConfig, WorkerError};
use ferrlabs_testkit::TestDb;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct AlwaysFails {
    marker: u32,
}

impl Payload for AlwaysFails {
    const QUEUE: &'static str = "test.retry.always_fails";
}

struct FailingWorker {
    attempts_seen: Arc<AtomicUsize>,
}

#[async_trait]
impl Worker<AlwaysFails> for FailingWorker {
    async fn handle(&self, _job: Job<AlwaysFails>) -> Result<(), WorkerError> {
        self.attempts_seen.fetch_add(1, Ordering::SeqCst);
        Err(WorkerError::retriable(anyhow::anyhow!("simulated failure")))
    }
}

fn fast_worker_config() -> WorkerConfig {
    WorkerConfig {
        name: "retry-test-worker".to_owned(),
        poll_interval: Duration::from_millis(50),
        sweep_interval: Duration::from_secs(60),
        stale_after: Duration::from_secs(300),
    }
}

/// A job that fails on every attempt must land in `dead` after exactly
/// `max_attempts` tries, and must never be picked up again afterwards.
#[tokio::test]
#[ignore = "requires docker (or TEST_DATABASE_URL); run with --features integration -- --ignored"]
async fn job_reaches_dead_after_max_attempts_and_is_not_retried_again() {
    let db = TestDb::fresh().await.expect("spin up test db");
    Queue::<AlwaysFails>::migrate(&db.pool)
        .await
        .expect("migrate jobs table");
    let queue = Queue::<AlwaysFails>::new(db.pool.clone());

    let max_attempts = 2;
    let id = queue
        .enqueue(
            AlwaysFails { marker: 1 },
            EnqueueOptions {
                max_attempts: Some(max_attempts),
                ..Default::default()
            },
        )
        .await
        .expect("enqueue job");

    let attempts_seen = Arc::new(AtomicUsize::new(0));
    let worker = FailingWorker {
        attempts_seen: attempts_seen.clone(),
    };

    // Backoff after attempt N is `backoff_seconds(N)` seconds
    // (2s after attempt 1, 4s after attempt 2), so give the loop enough
    // wall-clock time to observe both attempts and land on `dead`.
    let handle = queue.spawn_worker(worker, fast_worker_config());
    tokio::time::sleep(Duration::from_secs(6)).await;
    handle.shutdown().await;

    let job = queue.get(id).await.expect("job exists");
    assert_eq!(job.status, ferrlabs_queue::JobStatus::Dead);
    assert_eq!(job.attempts, max_attempts);
    assert_eq!(
        u32::try_from(attempts_seen.load(Ordering::SeqCst)).unwrap_or(u32::MAX),
        max_attempts,
        "handler must have run exactly max_attempts times"
    );

    // Re-run the worker loop again and confirm the now-dead job is not
    // claimed a further time: dead jobs are excluded from the claim query
    // (`status IN ('queued','failed')`), so no additional attempt or
    // status change should occur.
    let attempts_after_dead = Arc::new(AtomicUsize::new(0));
    let second_worker = FailingWorker {
        attempts_seen: attempts_after_dead.clone(),
    };
    let second_handle = queue.spawn_worker(second_worker, fast_worker_config());
    tokio::time::sleep(Duration::from_millis(500)).await;
    second_handle.shutdown().await;

    assert_eq!(
        attempts_after_dead.load(Ordering::SeqCst),
        0,
        "a dead job must never be claimed again"
    );
    let job_after = queue.get(id).await.expect("job still exists");
    assert_eq!(job_after.status, ferrlabs_queue::JobStatus::Dead);
    assert_eq!(job_after.attempts, max_attempts);
}
