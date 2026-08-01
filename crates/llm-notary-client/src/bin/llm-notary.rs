#[tokio::main]
async fn main() -> anyhow::Result<()> {
    llm_notary_client::run().await
}
