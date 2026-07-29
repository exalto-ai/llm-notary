use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use certified::{
    DEFAULT_NOTARY_MAX_FRAME_BYTES, NotarySessionMode, read_notary_session_mode,
    run_notary_session_after_prelude,
};
use clap::Parser;
use k256::ecdsa::SigningKey;
use tokio::{net::TcpListener, sync::Semaphore, time::timeout};

#[derive(Parser, Debug)]
#[command(about = "LLM Notary TLSNotary service")]
struct Args {
    /// Print the signing key's SEC1 public key and exit. Used by deployment
    /// health checks without exposing the private key.
    #[arg(long)]
    print_public_key: bool,
    #[arg(long, default_value = "127.0.0.1:7047")]
    listen: SocketAddr,

    /// A file containing exactly 32 hexadecimal bytes. This key is the trust
    /// root for receipts, so use an HSM/KMS in a real deployment.
    #[arg(long)]
    signing_key: PathBuf,

    /// Reject new capture sessions while continuing to finalize bundles that
    /// were captured before a planned key handoff.
    #[arg(long)]
    finalize_only: bool,

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

    /// Largest serialized proof or attestation frame accepted from a paired
    /// proxy. This must match the proxy's --max-frame-bytes setting.
    #[arg(long, default_value_t = DEFAULT_NOTARY_MAX_FRAME_BYTES)]
    max_frame_bytes: usize,

    /// Maximum number of simultaneous capture or finalization sessions.
    #[arg(long, default_value_t = 2)]
    max_concurrent_sessions: usize,

    /// Maximum number of sockets waiting to send a valid protocol prelude.
    #[arg(long, default_value_t = 128)]
    max_pending_connections: usize,

    /// Time allowed for a new socket to send its complete protocol prelude.
    #[arg(long, default_value_t = 10)]
    prelude_timeout_secs: u64,

    /// Hard wall-clock limit for one notary protocol session.
    #[arg(long, default_value_t = 30 * 60)]
    session_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.max_private_chunk_bytes == 0
        || args.max_total_private_chunk_bytes == 0
        || args.max_private_chunk_commitments == 0
        || args.max_concurrent_sessions == 0
        || args.max_pending_connections == 0
        || args.prelude_timeout_secs == 0
        || args.session_timeout_secs == 0
    {
        bail!("notary resource limits must be non-zero");
    }
    if args.max_frame_bytes == 0 || args.max_frame_bytes > u32::MAX as usize {
        bail!(
            "notary frame limit must be between 1 and {} bytes",
            u32::MAX
        );
    }
    let key_text = std::fs::read_to_string(&args.signing_key)
        .with_context(|| format!("reading {}", args.signing_key.display()))?;
    let bytes = hex::decode(key_text.trim()).context("signing key must be hexadecimal")?;
    if bytes.len() != 32 {
        bail!("signing key must contain exactly 32 bytes");
    }
    let key = Arc::new(SigningKey::from_slice(&bytes).context("invalid secp256k1 key")?);
    let public_key = hex::encode(key.verifying_key().to_sec1_bytes());
    if args.print_public_key {
        println!("{public_key}");
        return Ok(());
    }
    let allowed_hosts = Arc::new(
        args.allow_host
            .into_iter()
            .map(|host| host.to_ascii_lowercase())
            .collect::<Vec<_>>(),
    );
    let listener = TcpListener::bind(args.listen).await?;
    let session_permits = Arc::new(Semaphore::new(args.max_concurrent_sessions));
    let connection_permits = Arc::new(Semaphore::new(args.max_pending_connections));
    tracing::info!(address = %args.listen, public_key, "LLM Notary service listening");
    println!("LLM Notary public key: {public_key}");

    loop {
        let (mut stream, address) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let Ok(connection_permit) = Arc::clone(&connection_permits).try_acquire_owned() else {
            tracing::warn!(%address, "notary connection rejected at pending-connection limit");
            continue;
        };
        tracing::info!(%address, "notary client connected");
        let key = Arc::clone(&key);
        let allowed_hosts = Arc::clone(&allowed_hosts);
        let max_private_chunk_bytes = args.max_private_chunk_bytes;
        let max_total_private_chunk_bytes = args.max_total_private_chunk_bytes;
        let max_private_chunk_commitments = args.max_private_chunk_commitments;
        let max_frame_bytes = args.max_frame_bytes;
        let prelude_timeout = std::time::Duration::from_secs(args.prelude_timeout_secs);
        let session_timeout = std::time::Duration::from_secs(args.session_timeout_secs);
        let session_permits = Arc::clone(&session_permits);
        let finalize_only = args.finalize_only;
        tokio::spawn(async move {
            let mode = match timeout(prelude_timeout, read_notary_session_mode(&mut stream)).await {
                Ok(Ok(mode)) => mode,
                Ok(Err(error)) => {
                    tracing::warn!(%address, %error, "invalid notary session prelude");
                    return;
                }
                Err(_) => {
                    tracing::warn!(%address, "notary session prelude timed out");
                    return;
                }
            };
            drop(connection_permit);
            if !session_mode_allowed(finalize_only, mode) {
                tracing::warn!(%address, "capture rejected by finalize-only notary");
                return;
            }
            let Ok(session_permit) = session_permits.try_acquire_owned() else {
                tracing::warn!(%address, "notary session rejected at concurrency limit");
                return;
            };
            let result = timeout(
                session_timeout,
                run_notary_session_after_prelude(
                    stream,
                    mode,
                    key,
                    allowed_hosts,
                    max_private_chunk_bytes,
                    max_total_private_chunk_bytes,
                    max_private_chunk_commitments,
                    max_frame_bytes,
                ),
            )
            .await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(%address, %error, "notary session failed"),
                Err(_) => tracing::warn!(%address, "notary session timed out"),
            }
            drop(session_permit);
        });
    }
}

fn session_mode_allowed(finalize_only: bool, mode: NotarySessionMode) -> bool {
    !finalize_only || mode == NotarySessionMode::Finalize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalize_only_rejects_capture_before_protocol_admission() {
        assert!(!session_mode_allowed(true, NotarySessionMode::Capture));
        assert!(session_mode_allowed(true, NotarySessionMode::Finalize));
        assert!(session_mode_allowed(false, NotarySessionMode::Capture));
    }
}
