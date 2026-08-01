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
use uuid::Uuid;

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
    /// Options d'admin + nom de la base a supprimer au `Drop`.
    /// `None` pour le mode testcontainer : le conteneur emporte tout avec lui.
    cleanup: Option<(PgConnectOptions, String)>,
}

impl TestDb {
    /// Spin up a fresh, isolated Postgres for a test.
    ///
    /// When `TEST_DATABASE_URL` is set, connect to that server and create a
    /// uniquely-named ephemeral database on it — no container runtime needed,
    /// so this works on self-hosted CI runners without Docker. Point it at a
    /// disposable Postgres (e.g. one started for the CI job); the per-run
    /// database is dropped on teardown. Otherwise it falls back to a
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
        // Nom unique par APPEL, pas par processus. `std::process::id()` ne
        // convient pas : chaque conteneur a son propre espace de noms PID, où
        // les numeros repartent bas — deux runs CI tirent facilement le meme
        // PID. Comme ces bases ne sont jamais supprimees (voir plus bas), une
        // base d'un run precedent survit et le `CREATE DATABASE` echoue sur
        // « database "testkit_<pid>_0" already exists ».
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

impl Drop for TestDb {
    /// Supprime la base ephemere creee par `fresh_external`.
    ///
    /// Sans cela les bases s'accumulent indefiniment sur le serveur partage :
    /// le GC de `postgres-ci` ne purge que les bases `ci_*` creees par le
    /// workflow, pas les `testkit_*` creees ici. C'est ce qui a fini par
    /// provoquer des collisions de noms en CI.
    ///
    /// `Drop` est synchrone et rien ne garantit qu'un runtime Tokio soit encore
    /// actif a cet instant : on en cree un dedie sur un thread a part. Le
    /// `join()` attend la suppression, pour qu'elle ne soit pas perdue si le
    /// processus se termine dans la foulee.
    ///
    /// `WITH (FORCE)` (Postgres 13+) ferme les connexions restantes : le pool
    /// de `self` n'est ferme qu'apres ce `Drop`, la base serait sinon encore
    /// consideree comme utilisee. Best-effort : une erreur ici ne doit jamais
    /// faire echouer un test, le GC horaire reste le filet de securite.
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
            rt.block_on(async move {
                if let Ok(pool) = PgPoolOptions::new()
                    .max_connections(1)
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
            });
        })
        .join();
    }
}
