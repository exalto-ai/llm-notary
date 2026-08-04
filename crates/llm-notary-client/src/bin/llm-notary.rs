#[tokio::main]
async fn main() {
    if let Err(error) = llm_notary_client::run_cli().await {
        if !error.is_reported() {
            eprintln!("{error}");
        }
        std::process::exit(error.exit_code());
    }
}
