//! Integration test: a single job is claimed by exactly one of several
//! concurrent workers, exercising the real `FOR UPDATE SKIP LOCKED`
//! semantics against Postgres (not a mock).
//!
//! Requires Docker (or `TEST_DATABASE_URL`) via `ferrlabs-testkit`:
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
struct SingleJob {
    marker: u32,
}

impl Payload for SingleJob {
    const QUEUE: &'static str = "test.concurrent_claim.single_job";
}

struct CountingWorker {
    claimed_by: Arc<AtomicUsize>,
    worker_index: usize,
    delivered_to: Arc<std::sync::Mutex<Vec<usize>>>,
}

#[async_trait]
impl Worker<SingleJob> for CountingWorker {
    async fn handle(&self, _job: Job<SingleJob>) -> Result<(), WorkerError> {
        self.claimed_by.fetch_add(1, Ordering::SeqCst);
        self.delivered_to
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(self.worker_index);
        // Hold the "processing" window open briefly so a second worker
        // racing against the same row (if the claim query were broken)
        // would have a real chance to also observe it as claimable.
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(())
    }
}

fn fast_worker_config(name: &str) -> WorkerConfig {
    WorkerConfig {
        name: name.to_owned(),
        poll_interval: Duration::from_millis(20),
        sweep_interval: Duration::from_secs(60),
        stale_after: Duration::from_secs(300),
    }
}

#[tokio::test]
#[ignore = "requires docker (or TEST_DATABASE_URL); run with --features integration -- --ignored"]
async fn single_job_is_delivered_to_exactly_one_of_two_concurrent_workers() {
    let db = TestDb::fresh().await.expect("spin up test db");
    Queue::<SingleJob>::migrate(&db.pool)
        .await
        .expect("migrate jobs table");
    let queue = Queue::<SingleJob>::new(db.pool.clone());

    let id = queue
        .enqueue(SingleJob { marker: 1 }, EnqueueOptions::default())
        .await
        .expect("enqueue job");

    let claimed_by = Arc::new(AtomicUsize::new(0));
    let delivered_to = Arc::new(std::sync::Mutex::new(Vec::new()));

    let worker_a = CountingWorker {
        claimed_by: claimed_by.clone(),
        worker_index: 0,
        delivered_to: delivered_to.clone(),
    };
    let worker_b = CountingWorker {
        claimed_by: claimed_by.clone(),
        worker_index: 1,
        delivered_to: delivered_to.clone(),
    };

    // Two independent worker loops (two separate connections/tasks) racing
    // to claim from the same underlying `jobs` row.
    let handle_a = queue.spawn_worker(worker_a, fast_worker_config("worker-a"));
    let handle_b = queue.spawn_worker(worker_b, fast_worker_config("worker-b"));

    tokio::time::sleep(Duration::from_millis(600)).await;
    handle_a.shutdown().await;
    handle_b.shutdown().await;

    assert_eq!(
        claimed_by.load(Ordering::SeqCst),
        1,
        "the job must be handled exactly once, not zero or twice"
    );
    let delivered = delivered_to
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(delivered.len(), 1, "exactly one worker must have run it");

    let job = queue.get(id).await.expect("job exists");
    assert_eq!(job.status, ferrlabs_queue::JobStatus::Done);
}
