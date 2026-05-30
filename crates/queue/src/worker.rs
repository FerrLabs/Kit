use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::Payload;
use crate::error::WorkerError;
use crate::job::{Job, JobId, backoff_seconds};
use crate::queue::notify_channel;

/// Handler interface implemented by each consumer of a queue.
///
/// `handle` runs once per claim. Return `Ok(())` to mark the job done,
/// `Err(WorkerError::Retriable)` to reschedule with backoff (until
/// `max_attempts` is reached, then the job goes to `dead`), or
/// `Err(WorkerError::Permanent)` to bury the job immediately.
#[async_trait]
pub trait Worker<P: Payload>: Send + Sync {
    async fn handle(&self, job: Job<P>) -> Result<(), WorkerError>;
}

/// Runtime knobs for a worker loop.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Human-readable name used in `locked_by` and log messages.
    pub name: String,
    /// Idle poll fallback when the LISTEN connection is silent.
    pub poll_interval: Duration,
    /// How often the sweeper releases jobs whose worker died holding them.
    pub sweep_interval: Duration,
    /// A `running` job whose `locked_at` is older than this is considered
    /// abandoned and returned to `queued` by the sweeper.
    pub stale_after: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            name: "worker".to_owned(),
            poll_interval: Duration::from_secs(5),
            sweep_interval: Duration::from_secs(30),
            stale_after: Duration::from_secs(300),
        }
    }
}

/// Handle returned by [`Queue::spawn_worker`](crate::queue::Queue::spawn_worker).
///
/// Calling [`shutdown`](WorkerHandle::shutdown) requests the loop to
/// stop after its current job finishes. Dropping the handle without
/// calling `shutdown` lets the task continue running.
pub struct WorkerHandle {
    shutdown: Arc<Notify>,
    loop_task: JoinHandle<()>,
    sweep_task: JoinHandle<()>,
    listen_task: JoinHandle<()>,
}

impl WorkerHandle {
    /// Signal the worker loop to stop and wait for it to drain.
    pub async fn shutdown(self) {
        self.shutdown.notify_waiters();
        let _ = self.loop_task.await;
        self.sweep_task.abort();
        self.listen_task.abort();
    }

    /// Abort the loop without waiting. Use only on hard shutdown.
    pub fn abort(self) {
        self.loop_task.abort();
        self.sweep_task.abort();
        self.listen_task.abort();
    }
}

pub(crate) fn spawn_worker_loop<P, W>(
    pool: PgPool,
    worker: Arc<W>,
    config: WorkerConfig,
) -> WorkerHandle
where
    P: Payload,
    W: Worker<P> + 'static,
{
    let WorkerConfig {
        name,
        poll_interval,
        sweep_interval,
        stale_after,
    } = config;
    let shutdown = Arc::new(Notify::new());
    let wake = Arc::new(Notify::new());
    let worker_id = format!("{name}-{}", Uuid::new_v4());

    let sweep_task = tokio::spawn(sweeper_loop(
        pool.clone(),
        sweep_interval,
        stale_after,
        shutdown.clone(),
    ));

    let listen_task = tokio::spawn(listener_loop(
        pool.clone(),
        P::QUEUE.to_owned(),
        wake.clone(),
        shutdown.clone(),
    ));

    let loop_task = tokio::spawn(run_loop::<P, W>(
        pool,
        worker,
        worker_id,
        poll_interval,
        wake,
        shutdown.clone(),
    ));

    WorkerHandle {
        shutdown,
        loop_task,
        sweep_task,
        listen_task,
    }
}

async fn run_loop<P, W>(
    pool: PgPool,
    worker: Arc<W>,
    worker_id: String,
    poll_interval: Duration,
    wake: Arc<Notify>,
    shutdown: Arc<Notify>,
) where
    P: Payload,
    W: Worker<P> + 'static,
{
    let queue = P::QUEUE;
    info!(queue, worker_id, "queue worker started");

    loop {
        if let Some(claimed) = claim_one(&pool, queue, &worker_id).await {
            let id = claimed.id;
            let attempts = claimed.attempts;
            let max_attempts = claimed.max_attempts;
            match serde_json::from_value::<P>(claimed.payload) {
                Ok(payload) => {
                    let job = Job {
                        id: JobId(id),
                        payload,
                        attempt: u32::try_from(attempts).unwrap_or(0),
                        max_attempts: u32::try_from(max_attempts).unwrap_or(0),
                        queue: queue.to_owned(),
                        org_id: claimed.org_id,
                        actor_id: claimed.actor_id,
                        run_at: claimed.run_at,
                        created_at: claimed.created_at,
                    };
                    let attempt = job.attempt;
                    match worker.handle(job).await {
                        Ok(()) => mark_done(&pool, id).await,
                        Err(WorkerError::Permanent(err)) => {
                            mark_dead(&pool, id, &err.to_string()).await;
                        }
                        Err(WorkerError::Retriable(err)) => {
                            if attempts >= max_attempts {
                                mark_dead(&pool, id, &err.to_string()).await;
                            } else {
                                let delay = backoff_seconds(attempt);
                                let next_run = Utc::now()
                                    + chrono::Duration::seconds(
                                        i64::try_from(delay).unwrap_or(i64::MAX),
                                    );
                                mark_failed_for_retry(&pool, id, &err.to_string(), next_run).await;
                            }
                        }
                    }
                }
                Err(err) => {
                    error!(queue, %id, error = %err, "failed to deserialize payload; marking dead");
                    mark_dead(&pool, id, &format!("payload deserialization failed: {err}")).await;
                }
            }
            continue;
        }

        tokio::select! {
            () = shutdown.notified() => {
                info!(queue, worker_id, "queue worker shutting down");
                break;
            }
            () = wake.notified() => {
                debug!(queue, "woke on pg_notify");
            }
            () = tokio::time::sleep(poll_interval) => {}
        }
    }
}

#[derive(sqlx::FromRow)]
struct Claimed {
    id: Uuid,
    payload: serde_json::Value,
    attempts: i32,
    max_attempts: i32,
    org_id: Option<Uuid>,
    actor_id: Option<Uuid>,
    run_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

async fn claim_one(pool: &PgPool, queue: &str, worker_id: &str) -> Option<Claimed> {
    let row = sqlx::query_as::<_, Claimed>(
        "UPDATE jobs
            SET status = 'running',
                locked_at = NOW(),
                locked_by = $1,
                attempts = attempts + 1,
                started_at = COALESCE(started_at, NOW())
          WHERE id = (
              SELECT id FROM jobs
               WHERE queue = $2
                 AND status IN ('queued','failed')
                 AND run_at <= NOW()
                 AND attempts < max_attempts
               ORDER BY priority DESC, run_at ASC
               FOR UPDATE SKIP LOCKED
               LIMIT 1
          )
          RETURNING id, payload, attempts, max_attempts, org_id, actor_id, run_at, created_at",
    )
    .bind(worker_id)
    .bind(queue)
    .fetch_optional(pool)
    .await;

    match row {
        Ok(claimed) => claimed,
        Err(err) => {
            warn!(queue, error = %err, "failed to claim job");
            None
        }
    }
}

async fn mark_done(pool: &PgPool, id: Uuid) {
    let res = sqlx::query(
        "UPDATE jobs
            SET status = 'done',
                completed_at = NOW(),
                last_error = NULL,
                locked_at = NULL,
                locked_by = NULL
          WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await;
    if let Err(err) = res {
        error!(%id, error = %err, "failed to mark job done");
    }
}

async fn mark_dead(pool: &PgPool, id: Uuid, err_msg: &str) {
    let res = sqlx::query(
        "UPDATE jobs
            SET status = 'dead',
                completed_at = NOW(),
                last_error = $2,
                locked_at = NULL,
                locked_by = NULL
          WHERE id = $1",
    )
    .bind(id)
    .bind(err_msg)
    .execute(pool)
    .await;
    if let Err(err) = res {
        error!(%id, error = %err, "failed to mark job dead");
    }
}

async fn mark_failed_for_retry(pool: &PgPool, id: Uuid, err_msg: &str, next_run: DateTime<Utc>) {
    let res = sqlx::query(
        "UPDATE jobs
            SET status = 'failed',
                last_error = $2,
                run_at = $3,
                locked_at = NULL,
                locked_by = NULL
          WHERE id = $1",
    )
    .bind(id)
    .bind(err_msg)
    .bind(next_run)
    .execute(pool)
    .await;
    if let Err(err) = res {
        error!(%id, error = %err, "failed to reschedule job");
    }
}

async fn sweeper_loop(
    pool: PgPool,
    interval: Duration,
    stale_after: Duration,
    shutdown: Arc<Notify>,
) {
    let stale_secs = i64::try_from(stale_after.as_secs()).unwrap_or(i64::MAX);
    loop {
        let cutoff = Utc::now() - chrono::Duration::seconds(stale_secs);
        let res = sqlx::query(
            "UPDATE jobs
                SET status = 'queued',
                    locked_at = NULL,
                    locked_by = NULL
              WHERE status = 'running'
                AND locked_at IS NOT NULL
                AND locked_at < $1",
        )
        .bind(cutoff)
        .execute(&pool)
        .await;
        if let Err(err) = res {
            warn!(error = %err, "sweeper failed");
        }

        tokio::select! {
            () = shutdown.notified() => break,
            () = tokio::time::sleep(interval) => {}
        }
    }
}

async fn listener_loop(pool: PgPool, queue: String, wake: Arc<Notify>, shutdown: Arc<Notify>) {
    let channel = notify_channel(&queue);
    loop {
        match PgListener::connect_with(&pool).await {
            Ok(mut listener) => {
                if let Err(err) = listener.listen(&channel).await {
                    warn!(channel, error = %err, "LISTEN failed; backing off");
                    if wait_or_shutdown(&shutdown, Duration::from_secs(5)).await {
                        return;
                    }
                    continue;
                }
                let mut stream = listener.into_stream();
                loop {
                    tokio::select! {
                        () = shutdown.notified() => return,
                        next = stream.next() => match next {
                            Some(Ok(_)) => wake.notify_waiters(),
                            Some(Err(err)) => {
                                warn!(channel, error = %err, "listener stream error; reconnecting");
                                break;
                            }
                            None => break,
                        }
                    }
                }
            }
            Err(err) => {
                warn!(channel, error = %err, "could not open LISTEN connection; backing off");
                if wait_or_shutdown(&shutdown, Duration::from_secs(5)).await {
                    return;
                }
            }
        }
    }
}

async fn wait_or_shutdown(shutdown: &Notify, dur: Duration) -> bool {
    tokio::select! {
        () = shutdown.notified() => true,
        () = tokio::time::sleep(dur) => false,
    }
}
