pub(crate) const SCHEMA_SQL: &str = r"
CREATE TABLE IF NOT EXISTS jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    queue           TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued'
                      CHECK (status IN ('queued','running','done','failed','cancelled','dead')),
    priority        INTEGER NOT NULL DEFAULT 0,
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 3,
    run_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at       TIMESTAMPTZ,
    locked_by       TEXT,
    last_error      TEXT,
    idempotency_key TEXT,
    org_id          UUID,
    actor_id        UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS jobs_poll_idx
    ON jobs(queue, status, priority DESC, run_at)
    WHERE status IN ('queued','failed');

CREATE INDEX IF NOT EXISTS jobs_org_idx ON jobs(org_id) WHERE org_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS jobs_idempotency_idx
    ON jobs(queue, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
";
