# ferrlabs-queue

Postgres-backed durable job queue, shared by every FerrLabs service.

## Why this crate exists

Every paid product in the FerrLabs suite (FerrVault, FerrTrack, FerrGrowth,
FerrFleet, eventually FerrLens) needs a background-job primitive: send an
email through Resend, run an SEO audit, rotate a secret, sync GitHub PRs in
bulk, dispatch a Fleet run. Today each product would reach for its own
thing — Redis here, an in-memory `tokio::spawn` there, a brittle `sleep
loop` somewhere else.

`ferrlabs-queue` is that primitive, once, for the whole org.

## Why Postgres, not Redis / NATS / SQS

- **No new infrastructure.** Every product API already has a `PgPool` via
  `ferrlabs-db`. Adding Redis means another cluster to deploy, monitor,
  back up, secure, and pay for.
- **Free coordination.** `FOR UPDATE SKIP LOCKED` gives correct
  multi-worker dispatch with no extra moving parts. Add more workers,
  they cooperate via the database.
- **Debuggable with SQL.** When a job is stuck, you connect with `psql`
  and read the row. No special CLI, no proprietary inspector.
- **Transactional with business writes.** A handler can update its own
  tables and mark the job done in a single transaction — exactly-once
  side effects within the DB, at-least-once outside it.
- **Good enough throughput.** Hundreds of jobs per second per queue with
  the default schema; we'll cross that bridge when any product earns it.

## Quick start

```rust
use ferrlabs_queue::{
    EnqueueOptions, Job, Payload, Queue, Worker, WorkerConfig, WorkerError,
};
use std::sync::Arc;
use uuid::Uuid;

#[derive(serde::Serialize, serde::Deserialize)]
struct SendWelcomeEmail {
    user_id: Uuid,
    template: String,
}

impl Payload for SendWelcomeEmail {
    const QUEUE: &'static str = "email.send";
}

struct EmailWorker;

#[async_trait::async_trait]
impl Worker<SendWelcomeEmail> for EmailWorker {
    async fn handle(&self, job: Job<SendWelcomeEmail>) -> Result<(), WorkerError> {
        send_via_resend(&job.payload.user_id, &job.payload.template)
            .await
            .map_err(WorkerError::retriable)?;
        Ok(())
    }
}

// at API startup
Queue::<SendWelcomeEmail>::migrate(&pool).await?;
let q = Queue::<SendWelcomeEmail>::new(pool.clone());
let _handle = q.spawn_worker(EmailWorker, WorkerConfig::default()).await;

// from any handler
q.enqueue(
    SendWelcomeEmail { user_id, template: "welcome".into() },
    EnqueueOptions::default(),
).await?;
```

## Migration

`Queue::migrate(&pool)` creates the `jobs` table and its supporting
indexes. It is idempotent — call it once during API startup, before
spawning any worker. Safe to ship on every deploy. The same table backs
every queue in the database; calling `migrate` from any typed `Queue<P>`
is sufficient.

## Retry semantics

A `Worker::handle` returns one of three things:

| Return | Effect |
| --- | --- |
| `Ok(())` | Row flips to `done`, `completed_at = NOW()`. |
| `Err(WorkerError::Permanent(_))` | Row flips to `dead` immediately. No retry, ever. |
| `Err(WorkerError::Retriable(_))` | If `attempts < max_attempts`, row flips to `failed` and `run_at` is pushed by `2^attempts` seconds (capped at 1h). When `attempts >= max_attempts`, row flips to `dead`. |

The classification is the worker's responsibility — wrap each underlying
error with the variant that matches the failure mode (rate limit and 5xx
are retriable; bad payload, 4xx and "user deleted" are permanent).

## Idempotency

Pass `EnqueueOptions::idempotency_key = Some("unique-key")` to make
duplicate enqueues coalesce. The unique index is on
`(queue, idempotency_key)`, so the same key can be reused across
different queues. A second call returns the original `JobId` instead of
creating a new row — safe for retrying enqueue from at-least-once
handlers (webhooks, retried requests, etc.).

## Worker liveness

If a worker dies holding a `running` job (pod killed, OOM, network
split), the sweeper releases the row after
`WorkerConfig::stale_after` (default: 5 minutes). The job goes back to
`queued` and any worker can pick it up again. `attempts` is **not**
decremented — so the retry budget protects against a stuck job pinning
the queue forever.

## Shutdown

`Queue::spawn_worker` returns a `WorkerHandle`. Call `handle.shutdown()`
during your API's graceful-shutdown hook — the worker finishes its
current job (if any) and then exits cleanly. The sweeper and listener
tasks are aborted with the handle.

## Observability

Every loop emits `tracing` spans / events at the `info`, `debug`, and
`warn` levels. Hook your existing `tracing-subscriber` and the worker
will appear in your normal logs without extra configuration.

## Not in scope (for now)

- Cron-style recurring jobs — separate crate later.
- Priority queues beyond the integer `priority` column.
- Distributed coordinators. One Postgres is the source of truth, and
  that's the design.
- A web UI for inspecting jobs. FerrFleet will eat that surface.
