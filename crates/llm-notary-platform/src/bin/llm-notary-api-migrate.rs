#[tokio::main]
async fn main() -> anyhow::Result<()> {
    llm_notary_platform::migrate::run_migrations().await
}
