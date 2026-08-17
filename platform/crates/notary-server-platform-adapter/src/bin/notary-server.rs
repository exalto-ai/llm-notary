#[tokio::main]
async fn main() -> anyhow::Result<()> {
    notary_server_platform_adapter::run().await
}
