mod cli;
mod client;
mod compress;
mod crypto;
mod discover;
mod error;
mod hash;
mod mnemonic;
mod models;
mod net;
mod protocol;
mod relay;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::{
    cli::{Cli, Commands, HashArg},
    client::{receiver::ReceiveConfig, sender::SendConfig},
    error::RcrocError,
    models::HashAlgorithm,
};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();

    match cli.command {
        Commands::Relay {
            listen,
            relay_password,
        } => {
            relay::run_relay(&listen, &relay_password).await?;
        }
        Commands::Send {
            paths,
            secret,
            relay,
            relay_password,
            transfers,
            no_compress,
            hash_algorithm,
            proxy,
            lan_discovery,
        } => {
            let (secret, generated) = resolve_secret(secret, true)?;
            if generated {
                println!("Secret: {secret}");
            }
            client::sender::run_send(SendConfig {
                paths,
                secret,
                relay_addr: relay,
                relay_password,
                no_compress,
                transfers,
                proxy,
                lan_discovery,
                hash_algorithm: map_hash_algorithm(hash_algorithm),
            })
            .await?;
        }
        Commands::Receive {
            secret,
            relay,
            relay_password,
            out,
            transfers,
            proxy,
            lan_discovery,
            discover_timeout,
            resume,
        } => {
            let (secret, _) = resolve_secret(secret, false)?;
            client::receiver::run_receive(ReceiveConfig {
                secret,
                output_dir: out,
                relay_addr: relay,
                relay_password,
                proxy,
                lan_discovery,
                discover_timeout_secs: discover_timeout,
                resume,
                max_transfers: transfers,
            })
            .await?;
        }
    }

    Ok(())
}

fn resolve_secret(
    secret: Option<String>,
    generate_if_missing: bool,
) -> std::result::Result<(String, bool), RcrocError> {
    if let Some(s) = secret
        && !s.trim().is_empty()
    {
        return Ok((s, false));
    }

    if let Ok(env_secret) = std::env::var("CROC_SECRET")
        && !env_secret.trim().is_empty()
    {
        return Ok((env_secret, false));
    }

    if generate_if_missing {
        let generated = mnemonic::generate_secret();
        info!("generated temporary secret for this transfer");
        return Ok((generated, true));
    }

    Err(RcrocError::InvalidSecret(
        "missing secret; use --secret or CROC_SECRET".to_string(),
    ))
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn map_hash_algorithm(value: HashArg) -> HashAlgorithm {
    match value {
        HashArg::Sha256 => HashAlgorithm::Sha256,
        HashArg::Xxh3 => HashAlgorithm::Xxh3,
    }
}
