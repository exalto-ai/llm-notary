use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use certified::run_notary_session;
use clap::Parser;
use k256::ecdsa::SigningKey;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(about = "LLM Notary TLSNotary service")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7047")]
    listen: SocketAddr,

    /// A file containing exactly 32 hexadecimal bytes. This key is the trust
    /// root for receipts, so use an HSM/KMS in a real deployment.
    #[arg(long)]
    signing_key: PathBuf,

    /// Exact provider hostnames this notary may connect to in Proxy-TLS mode.
    /// Supplying this explicitly is required in production; the development
    /// defaults cover the two supported provider adapters.
    #[arg(long, default_values_t = ["api.openai.com".to_owned(), "api.anthropic.com".to_owned()])]
    allow_host: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let key_text = std::fs::read_to_string(&args.signing_key)
        .with_context(|| format!("reading {}", args.signing_key.display()))?;
    let bytes = hex::decode(key_text.trim()).context("signing key must be hexadecimal")?;
    if bytes.len() != 32 {
        bail!("signing key must contain exactly 32 bytes");
    }
    let key = Arc::new(SigningKey::from_slice(&bytes).context("invalid secp256k1 key")?);
    let allowed_hosts = Arc::new(
        args.allow_host
            .into_iter()
            .map(|host| host.to_ascii_lowercase())
            .collect::<Vec<_>>(),
    );
    let public_key = hex::encode(key.verifying_key().to_sec1_bytes());
    let listener = TcpListener::bind(args.listen).await?;
    tracing::info!(address = %args.listen, public_key, "LLM Notary service listening");
    println!("LLM Notary public key: {public_key}");

    loop {
        let (stream, address) = listener.accept().await?;
        stream.set_nodelay(true)?;
        tracing::info!(%address, "notary client connected");
        let key = Arc::clone(&key);
        let allowed_hosts = Arc::clone(&allowed_hosts);
        tokio::spawn(async move {
            if let Err(error) = run_notary_session(stream, key, allowed_hosts).await {
                tracing::warn!(%address, %error, "notary session failed");
            }
        });
    }
}
