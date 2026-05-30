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

use anyhow::{Context, Result};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use testcontainers::ContainerAsync;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

pub struct TestDb {
    pub pool: PgPool,
    _container: ContainerAsync<Postgres>,
}

impl TestDb {
    pub async fn fresh() -> Result<Self> {
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
            _container: container,
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
