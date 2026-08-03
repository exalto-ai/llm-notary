#[tokio::main]
async fn main() {
    if let Err(error) = llm_notary_client::run_cli().await {
        eprintln!("{error}");
        std::process::exit(error.exit_code());
    }
}
