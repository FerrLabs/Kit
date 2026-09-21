//! Shared test helpers for FerrLabs APIs.
//!
//! [`TestDb`] spins up an ephemeral Postgres for integration tests and
//! tears it down when the value is dropped. v0.1 is function-based;
//! a `#[testkit::db]` proc-macro can be layered on top later without
//! changing the surface here.
//!
//! # Backend choice — testcontainers, not pgtemp
//!
//! `pgtemp` is the lower-overhead choice on Linux/macOS but currently
//! fails to compile on Windows (calls `libc::kill` and `libc::getuid`,
//! both unix-only). The FerrLabs dev machines target Windows + Linux,
//! so we use [`testcontainers`] with the official Postgres image. The
//! cost is a Docker dependency, which CI already has wherever the
//! `integration` feature gets enabled.
//!
//! # Running the integration test locally
//!
//! ```bash
//! cargo test -p ferrlabs-testkit --features integration -- --ignored
//! ```
//!
//! It is `#[ignore]` so a default `cargo test --workspace` succeeds on
//! machines without Docker.

#[cfg(feature = "api-version-golden")]
pub mod api_version_golden;

use std::path::Path;
use std::str::FromStr;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use uuid::Uuid;

use anyhow::{Context, Result};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use testcontainers::ContainerAsync;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

static DB_SEQ: AtomicU64 = AtomicU64::new(0);

/// Upper bound on the `Drop` cleanup. Short on purpose: deleting is a
/// convenience, the hourly GC on `postgres-ci` is the real guarantee.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TestDb {
    pub pool: PgPool,
    _container: Option<ContainerAsync<Postgres>>,
    /// Admin options and the name of the database to drop in `Drop`.
    /// `None` in testcontainer mode: the container takes everything with it.
    cleanup: Option<(PgConnectOptions, String)>,
}

impl TestDb {
    /// Spin up a fresh, isolated Postgres for a test.
    ///
    /// When `TEST_DATABASE_URL` is set, connect to that server and create a
    /// uniquely-named ephemeral database on it — no container runtime needed,
    /// so this works on self-hosted CI runners without Docker. Point it at a
    /// disposable Postgres (e.g. one started for the CI job); the per-run
    /// database is dropped on teardown on a **best-effort** basis — see the
    /// `Drop` impl: failures are ignored, destructors do not run on `SIGKILL`,
    /// and `WITH (FORCE)` needs Postgres 13+. Treat the hourly GC on the CI
    /// server as the actual guarantee. Otherwise it falls back to a
    /// Postgres testcontainer (local dev / Docker-capable CI).
    pub async fn fresh() -> Result<Self> {
        match std::env::var("TEST_DATABASE_URL") {
            Ok(base) if !base.is_empty() => Self::fresh_external(&base).await,
            _ => Self::fresh_container().await,
        }
    }

    async fn fresh_container() -> Result<Self> {
        let container = Postgres::default()
            .start()
            .await
            .context("starting postgres testcontainer")?;
        let host = container
            .get_host()
            .await
            .context("reading container host")?;
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .context("reading container port")?;
        let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .context("connecting to test postgres")?;
        Ok(Self {
            pool,
            _container: Some(container),
            cleanup: None,
        })
    }

    async fn fresh_external(base: &str) -> Result<Self> {
        let admin = PgConnectOptions::from_str(base).context("parsing TEST_DATABASE_URL")?;
        // Unique name per CALL, not per process. `std::process::id()` does
        // not work: every container has its own PID namespace where numbers
        // start low again, so two CI runs easily draw the same PID. When a
        // database from an earlier run survives, `CREATE DATABASE` fails on
        // `database "testkit_<pid>_0" already exists`.
        let db_name = format!(
            "testkit_{}_{}",
            &Uuid::new_v4().simple().to_string()[..12],
            DB_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(admin.clone())
            .await
            .context("connecting to TEST_DATABASE_URL")?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "CREATE DATABASE \"{db_name}\""
        )))
        .execute(&admin_pool)
        .await
        .context("creating ephemeral test database")?;
        admin_pool.close().await;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(admin.clone().database(&db_name))
            .await
            .context("connecting to ephemeral test database")?;
        Ok(Self {
            pool,
            _container: None,
            cleanup: Some((admin, db_name)),
        })
    }

    pub async fn run_migrations(&self, dir: &Path) -> Result<()> {
        let migrator = sqlx::migrate::Migrator::new(dir)
            .await
            .context("loading migrations")?;
        migrator
            .run(&self.pool)
            .await
            .context("running migrations")?;
        Ok(())
    }
}

impl Drop for TestDb {
    /// Drops the ephemeral database created by `fresh_external`.
    ///
    /// Without this, databases pile up forever on the shared server: the
    /// `postgres-ci` GC only purges the `ci_*` databases the workflow creates,
    /// not the `testkit_*` ones created here. That is what eventually caused
    /// name collisions in CI.
    ///
    /// `Drop` is synchronous and nothing guarantees a Tokio runtime is still
    /// running at that point, so a dedicated one is built on its own thread.
    /// The `join()` waits for the drop, so it is not lost if the process exits
    /// right after.
    ///
    /// `WITH (FORCE)` (Postgres 13+) closes the remaining connections: the
    /// pool on `self` is only closed after this `Drop`, so the database would
    /// otherwise still count as in use. Best-effort: an error here must never
    /// fail a test, and the hourly GC stays the safety net.
    fn drop(&mut self) {
        let Some((admin, db_name)) = self.cleanup.take() else {
            return;
        };
        let _ = std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            // Hard bound: this thread is `join()`ed, so without a timeout a
            // hanging connection (DNS, network, server gone) would freeze the
            // end of the test run. Best-effort means giving up silently.
            rt.block_on(async move {
                let _ = tokio::time::timeout(CLEANUP_TIMEOUT, async move {
                    if let Ok(pool) = PgPoolOptions::new()
                        .max_connections(1)
                        .acquire_timeout(CLEANUP_TIMEOUT)
                        .connect_with(admin)
                        .await
                    {
                        let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
                            "DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"
                        )))
                        .execute(&pool)
                        .await;
                        pool.close().await;
                    }
                })
                .await;
            });
        })
        .join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires docker; run with `cargo test -p ferrlabs-testkit -- --ignored`"]
    async fn fresh_db_executes_select_one() {
        let db = TestDb::fresh().await.expect("spin up test db");
        let row: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&db.pool)
            .await
            .expect("select 1");
        assert_eq!(row.0, 1);
    }

    /// Covers the `fresh_external` path, the one CI uses, and above all the
    /// `Drop` cleanup, which is what the fix was about.
    ///
    /// Needs a disposable Postgres reachable through `TEST_DATABASE_URL`:
    ///   docker run --rm -e POSTGRES_HOST_AUTH_METHOD=trust -p 5432:5432 postgres:17-alpine
    ///   TEST_DATABASE_URL=postgres://postgres@localhost:5432/postgres \
    ///     cargo test -p ferrlabs-testkit -- --ignored external
    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a disposable Postgres"]
    async fn external_db_is_dropped_on_teardown() {
        let base = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");

        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&base)
            .await
            .expect("connect to admin db");

        let count = |pool: PgPool| async move {
            let (n,): (i64,) =
                sqlx::query_as("SELECT count(*) FROM pg_database WHERE datname LIKE 'testkit\\_%'")
                    .fetch_one(&pool)
                    .await
                    .expect("count testkit databases");
            n
        };

        let before = count(admin_pool.clone()).await;

        {
            let db = TestDb::fresh_external(&base).await.expect("fresh external");
            let row: (i32,) = sqlx::query_as("SELECT 1")
                .fetch_one(&db.pool)
                .await
                .expect("select 1");
            assert_eq!(row.0, 1);
            assert_eq!(
                count(admin_pool.clone()).await,
                before + 1,
                "the ephemeral database must exist during the test"
            );
        } // <- Drop here: the database must go away

        assert_eq!(
            count(admin_pool.clone()).await,
            before,
            "the ephemeral database must be dropped in Drop"
        );
        admin_pool.close().await;
    }
}
