#[tokio::main]
async fn main() -> anyhow::Result<()> {
    llm_notary_api::migrate::run_migrations().await
}
