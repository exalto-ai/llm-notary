use std::env;

use anyhow::{Context, Result};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations-postgres");

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let options = database_url
        .parse::<PgConnectOptions>()
        .context("DATABASE_URL must be a PostgreSQL connection URL")?;
    let database: PgPool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .context("opening API database")?;
    MIGRATOR
        .run(&database)
        .await
        .context("migrating API database")?;
    println!("API PostgreSQL migrations are current");
    Ok(())
}
