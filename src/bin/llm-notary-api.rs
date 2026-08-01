#[tokio::main]
async fn main() -> anyhow::Result<()> {
    llm_notary_platform::run_api().await
}
