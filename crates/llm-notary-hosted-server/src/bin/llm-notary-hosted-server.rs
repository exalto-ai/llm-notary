#[tokio::main]
async fn main() -> anyhow::Result<()> {
    llm_notary_hosted_server::run().await
}
