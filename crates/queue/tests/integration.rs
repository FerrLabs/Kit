use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ferrlabs_queue::{
    EnqueueOptions, Job, JobStatus, Payload, Queue, Worker, WorkerConfig, WorkerError,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Echo {
    msg: String,
    fail_modes: Vec<String>,
}

impl Payload for Echo {
    const QUEUE: &'static str = "test.echo";
}

#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<String>>,
}

struct RecordingWorker {
    rec: Arc<Recorder>,
}

#[async_trait]
impl Worker<Echo> for RecordingWorker {
    async fn handle(&self, job: Job<Echo>) -> Result<(), WorkerError> {
        self.rec.seen.lock().await.push(job.payload.msg.clone());
        for mode in &job.payload.fail_modes {
            match mode.as_str() {
                "retry-once" if job.attempt == 1 => {
                    return Err(WorkerError::retriable(anyhow::anyhow!("flaky once")));
                }
                "permanent" => {
                    return Err(WorkerError::permanent(anyhow::anyhow!("nope")));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

async fn pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Some(
        PgPool::connect(&url)
            .await
            .expect("connect to test postgres"),
    )
}

async fn reset(pool: &PgPool) {
    sqlx::query("DELETE FROM jobs WHERE queue = $1")
        .bind(Echo::QUEUE)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn enqueue_then_worker_marks_done() {
    let Some(pool) = pool().await else { return };
    Queue::<Echo>::migrate(&pool).await.unwrap();
    reset(&pool).await;

    let q = Queue::<Echo>::new(pool.clone());
    let rec = Arc::new(Recorder::default());
    let handle = q.spawn_worker(
        RecordingWorker { rec: rec.clone() },
        WorkerConfig {
            name: "test".into(),
            poll_interval: Duration::from_millis(100),
            sweep_interval: Duration::from_secs(60),
            stale_after: Duration::from_secs(60),
        },
    );

    let id = q
        .enqueue(
            Echo {
                msg: "hi".into(),
                fail_modes: vec![],
            },
            EnqueueOptions::default(),
        )
        .await
        .unwrap();

    for _ in 0..50 {
        let meta = q.get(id).await.unwrap();
        if meta.status == JobStatus::Done {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let meta = q.get(id).await.unwrap();
    assert_eq!(meta.status, JobStatus::Done);
    assert_eq!(rec.seen.lock().await.as_slice(), &["hi".to_owned()]);
    handle.shutdown().await;
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn idempotency_key_deduplicates() {
    let Some(pool) = pool().await else { return };
    Queue::<Echo>::migrate(&pool).await.unwrap();
    reset(&pool).await;

    let q = Queue::<Echo>::new(pool);
    let opts = EnqueueOptions {
        idempotency_key: Some("dedup-1".into()),
        ..Default::default()
    };
    let a = q
        .enqueue(
            Echo {
                msg: "first".into(),
                fail_modes: vec![],
            },
            opts.clone(),
        )
        .await
        .unwrap();
    let b = q
        .enqueue(
            Echo {
                msg: "second".into(),
                fail_modes: vec![],
            },
            opts,
        )
        .await
        .unwrap();
    assert_eq!(a, b);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn permanent_error_buries_immediately() {
    let Some(pool) = pool().await else { return };
    Queue::<Echo>::migrate(&pool).await.unwrap();
    reset(&pool).await;

    let q = Queue::<Echo>::new(pool.clone());
    let rec = Arc::new(Recorder::default());
    let handle = q.spawn_worker(
        RecordingWorker { rec: rec.clone() },
        WorkerConfig {
            name: "test".into(),
            poll_interval: Duration::from_millis(100),
            sweep_interval: Duration::from_secs(60),
            stale_after: Duration::from_secs(60),
        },
    );

    let id = q
        .enqueue(
            Echo {
                msg: "burn".into(),
                fail_modes: vec!["permanent".into()],
            },
            EnqueueOptions::default(),
        )
        .await
        .unwrap();

    for _ in 0..50 {
        let meta = q.get(id).await.unwrap();
        if meta.status == JobStatus::Dead {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let meta = q.get(id).await.unwrap();
    assert_eq!(meta.status, JobStatus::Dead);
    assert_eq!(meta.attempts, 1);
    handle.shutdown().await;
}
