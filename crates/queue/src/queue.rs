use std::marker::PhantomData;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::Payload;
use crate::error::{QueueError, QueueResult};
use crate::job::{JobId, JobMeta, JobStatus};
use crate::schema::SCHEMA_SQL;
use crate::worker::{Worker, WorkerConfig, WorkerHandle, spawn_worker_loop};

/// Options accepted by [`Queue::enqueue`].
///
/// All fields have sensible defaults. `idempotency_key` makes enqueue
/// safe to retry from a handler — duplicate inserts return the existing
/// job's id instead of creating a second row.
#[derive(Debug, Default, Clone)]
pub struct EnqueueOptions {
    pub run_at: Option<DateTime<Utc>>,
    pub priority: i32,
    pub max_attempts: Option<u32>,
    pub idempotency_key: Option<String>,
    pub org_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
}

/// Filter accepted by [`Queue::list`].
#[derive(Debug, Default, Clone)]
pub struct JobFilter {
    pub status: Option<JobStatus>,
    pub org_id: Option<Uuid>,
    pub limit: Option<i64>,
}

/// Strongly-typed handle to a single logical queue.
///
/// One `Queue<P>` value owns a `PgPool` clone and produces / observes
/// jobs whose payload deserializes as `P`. The queue name is read from
/// [`Payload::QUEUE`] — same constant means same queue.
#[derive(Clone)]
pub struct Queue<P: Payload> {
    pool: PgPool,
    _payload: PhantomData<fn() -> P>,
}

impl<P: Payload> Queue<P> {
    /// Wrap a pool as a typed queue. Cheap, clones the pool handle.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            _payload: PhantomData,
        }
    }

    /// Access the underlying pool. Mostly useful for tests.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Create the `jobs` table and supporting indexes if they don't
    /// already exist. Idempotent — safe to call on every boot. **Must**
    /// be called once at API startup before spawning any worker.
    ///
    /// The same table backs every queue in the database; calling
    /// `migrate` from any typed `Queue<P>` is sufficient.
    pub async fn migrate(pool: &PgPool) -> QueueResult<()> {
        sqlx::raw_sql(SCHEMA_SQL).execute(pool).await?;
        Ok(())
    }

    /// Enqueue a job. Returns the row id.
    ///
    /// Honours [`EnqueueOptions::idempotency_key`]: when the same
    /// `(queue, key)` already exists, no new row is inserted and the
    /// previously-stored job's id is returned. Callers can therefore
    /// safely retry `enqueue` from at-least-once handlers.
    pub async fn enqueue(&self, payload: P, opts: EnqueueOptions) -> QueueResult<JobId> {
        let payload_json = serde_json::to_value(&payload)?;
        let queue = P::QUEUE;
        let run_at = opts.run_at.unwrap_or_else(Utc::now);
        let max_attempts = i32::try_from(opts.max_attempts.unwrap_or(3)).unwrap_or(3);

        let inserted: Option<(Uuid,)> = sqlx::query_as(
            "INSERT INTO jobs
                (queue, payload, priority, max_attempts, run_at,
                 idempotency_key, org_id, actor_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (queue, idempotency_key)
                WHERE idempotency_key IS NOT NULL
                DO NOTHING
             RETURNING id",
        )
        .bind(queue)
        .bind(&payload_json)
        .bind(opts.priority)
        .bind(max_attempts)
        .bind(run_at)
        .bind(opts.idempotency_key.as_deref())
        .bind(opts.org_id)
        .bind(opts.actor_id)
        .fetch_optional(&self.pool)
        .await?;

        let id = if let Some((id,)) = inserted {
            id
        } else if let Some(key) = opts.idempotency_key.as_deref() {
            let (existing,): (Uuid,) =
                sqlx::query_as("SELECT id FROM jobs WHERE queue = $1 AND idempotency_key = $2")
                    .bind(queue)
                    .bind(key)
                    .fetch_one(&self.pool)
                    .await?;
            existing
        } else {
            return Err(QueueError::Database(sqlx::Error::RowNotFound));
        };

        let _ = sqlx::query("SELECT pg_notify($1, $2)")
            .bind(notify_channel(queue))
            .bind(id.to_string())
            .execute(&self.pool)
            .await;

        Ok(JobId(id))
    }

    /// Mark a non-terminal job as `cancelled`. No-op (returns
    /// `JobNotFound`) if the job is already terminal or missing.
    pub async fn cancel(&self, id: JobId) -> QueueResult<()> {
        let res = sqlx::query(
            "UPDATE jobs
                SET status = 'cancelled', completed_at = NOW()
              WHERE id = $1
                AND queue = $2
                AND status NOT IN ('done','cancelled','dead')",
        )
        .bind(id.0)
        .bind(P::QUEUE)
        .execute(&self.pool)
        .await?;

        if res.rows_affected() == 0 {
            return Err(QueueError::JobNotFound(id.0));
        }
        Ok(())
    }

    /// List jobs from this queue, newest first. Useful for admin
    /// dashboards and debugging.
    pub async fn list(&self, filter: JobFilter) -> QueueResult<Vec<JobMeta>> {
        let limit = filter.limit.unwrap_or(100).clamp(1, 1000);
        let rows: Vec<JobRow> = sqlx::query_as::<_, JobRow>(
            "SELECT id, queue, status, priority, attempts, max_attempts, run_at,
                    locked_at, locked_by, last_error, idempotency_key, org_id,
                    actor_id, created_at, started_at, completed_at, payload
               FROM jobs
              WHERE queue = $1
                AND ($2::TEXT IS NULL OR status = $2)
                AND ($3::UUID IS NULL OR org_id = $3)
              ORDER BY created_at DESC
              LIMIT $4",
        )
        .bind(P::QUEUE)
        .bind(filter.status.map(|s| s.as_str().to_owned()))
        .bind(filter.org_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(JobRow::into_meta).collect()
    }

    /// Look up a single job by id.
    pub async fn get(&self, id: JobId) -> QueueResult<JobMeta> {
        let row: JobRow = sqlx::query_as::<_, JobRow>(
            "SELECT id, queue, status, priority, attempts, max_attempts, run_at,
                    locked_at, locked_by, last_error, idempotency_key, org_id,
                    actor_id, created_at, started_at, completed_at, payload
               FROM jobs
              WHERE id = $1 AND queue = $2",
        )
        .bind(id.0)
        .bind(P::QUEUE)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(QueueError::JobNotFound(id.0))?;
        row.into_meta()
    }

    /// Spawn an async worker loop bound to this queue. The returned
    /// [`WorkerHandle`] is used to trigger graceful shutdown.
    pub fn spawn_worker<W>(&self, worker: W, config: WorkerConfig) -> WorkerHandle
    where
        W: Worker<P> + 'static,
    {
        spawn_worker_loop::<P, W>(self.pool.clone(), Arc::new(worker), config)
    }
}

#[derive(sqlx::FromRow)]
struct JobRow {
    id: Uuid,
    queue: String,
    status: String,
    priority: i32,
    attempts: i32,
    max_attempts: i32,
    run_at: DateTime<Utc>,
    locked_at: Option<DateTime<Utc>>,
    locked_by: Option<String>,
    last_error: Option<String>,
    idempotency_key: Option<String>,
    org_id: Option<Uuid>,
    actor_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    payload: serde_json::Value,
}

impl JobRow {
    fn into_meta(self) -> QueueResult<JobMeta> {
        let status = self
            .status
            .parse::<JobStatus>()
            .map_err(|e| QueueError::Database(sqlx::Error::Decode(Box::new(e))))?;
        Ok(JobMeta {
            id: JobId(self.id),
            queue: self.queue,
            status,
            priority: self.priority,
            attempts: u32::try_from(self.attempts).unwrap_or(0),
            max_attempts: u32::try_from(self.max_attempts).unwrap_or(0),
            run_at: self.run_at,
            locked_at: self.locked_at,
            locked_by: self.locked_by,
            last_error: self.last_error,
            idempotency_key: self.idempotency_key,
            org_id: self.org_id,
            actor_id: self.actor_id,
            created_at: self.created_at,
            started_at: self.started_at,
            completed_at: self.completed_at,
            payload: self.payload,
        })
    }
}

pub(crate) fn notify_channel(queue: &str) -> String {
    let sanitized: String = queue
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("ferrlabs_queue_{sanitized}")
}
