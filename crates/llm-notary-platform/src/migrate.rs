use std::env;

use anyhow::{Context, Result};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations-postgres");
const SET_MIGRATION_LOCK_TIMEOUT: &str = "SET lock_timeout = '60s'";

/// Applies the hosted platform's PostgreSQL schema migrations.
pub async fn run_migrations() -> Result<()> {
    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_MIGRATIONS_URL")
        .context("DATABASE_MIGRATIONS_URL must be set to a direct PostgreSQL connection URL")?;
    let options = database_url
        .parse::<PgConnectOptions>()
        .context("DATABASE_MIGRATIONS_URL must be a PostgreSQL connection URL")?;
    println!("Connecting to the API database for migrations");
    let database: PgPool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .context("opening API database")?;
    let mut connection = database
        .acquire()
        .await
        .context("acquiring API database migration connection")?;
    sqlx::query(SET_MIGRATION_LOCK_TIMEOUT)
        .execute(&mut *connection)
        .await
        .context("setting API database migration lock timeout")?;
    println!("Applying API PostgreSQL migrations");
    MIGRATOR
        .run_direct(&mut *connection)
        .await
        .context("migrating API database")?;
    println!("API PostgreSQL migrations are current");
    Ok(())
}
