#[tokio::main]
async fn main() -> anyhow::Result<()> {
    notary_api::NotaryApiArgs::from_env()?.run().await
}
