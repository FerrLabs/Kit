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

use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use testcontainers::ContainerAsync;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

static DB_SEQ: AtomicU64 = AtomicU64::new(0);

pub struct TestDb {
    pub pool: PgPool,
    _container: Option<ContainerAsync<Postgres>>,
}

impl TestDb {
    /// Spin up a fresh, isolated Postgres for a test.
    ///
    /// When `TEST_DATABASE_URL` is set, connect to that server and create a
    /// uniquely-named ephemeral database on it — no container runtime needed,
    /// so this works on self-hosted CI runners without Docker. Point it at a
    /// disposable Postgres (e.g. one started for the CI job); the per-run
    /// databases are not dropped on teardown. Otherwise it falls back to a
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
        })
    }

    async fn fresh_external(base: &str) -> Result<Self> {
        let admin = PgConnectOptions::from_str(base).context("parsing TEST_DATABASE_URL")?;
        let db_name = format!(
            "testkit_{}_{}",
            std::process::id(),
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
            .connect_with(admin.database(&db_name))
            .await
            .context("connecting to ephemeral test database")?;
        Ok(Self {
            pool,
            _container: None,
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
}
