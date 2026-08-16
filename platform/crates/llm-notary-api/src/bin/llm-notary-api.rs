#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    match (arguments.next(), arguments.next()) {
        (None, None) => llm_notary_api::run_api().await,
        (Some(argument), None) if argument == "--verification-worker" => {
            llm_notary_api::run_verification_worker()
        }
        _ => anyhow::bail!("unsupported llm-notary-api arguments"),
    }
}
