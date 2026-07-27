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
    /// defaults cover the supported provider adapters.
    #[arg(long, default_values_t = [
        "api.openai.com".to_owned(),
        "api.anthropic.com".to_owned(),
        "api.deepseek.com".to_owned(),
    ])]
    allow_host: Vec<String>,

    /// Largest private-proof chunk accepted from a client. This is a service
    /// resource limit; clients cannot raise it in their proof request.
    #[arg(long, default_value_t = 128 * 1024)]
    max_private_chunk_bytes: usize,

    /// Largest total private transcript commitment set accepted in one proof.
    /// This bounds transcript bytes when every individual chunk is valid.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_total_private_chunk_bytes: usize,

    /// Largest number of private commitments accepted in one proof. Each
    /// commitment creates a child proof VM, so this bounds fixed proof work.
    #[arg(long, default_value_t = 128)]
    max_private_chunk_commitments: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.max_private_chunk_bytes == 0
        || args.max_total_private_chunk_bytes == 0
        || args.max_private_chunk_commitments == 0
    {
        bail!("private chunk limits must be non-zero");
    }
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
        let max_private_chunk_bytes = args.max_private_chunk_bytes;
        let max_total_private_chunk_bytes = args.max_total_private_chunk_bytes;
        let max_private_chunk_commitments = args.max_private_chunk_commitments;
        tokio::spawn(async move {
            if let Err(error) = run_notary_session(
                stream,
                key,
                allowed_hosts,
                max_private_chunk_bytes,
                max_total_private_chunk_bytes,
                max_private_chunk_commitments,
            )
            .await
            {
                tracing::warn!(%address, %error, "notary session failed");
            }
        });
    }
}
