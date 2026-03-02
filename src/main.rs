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
mod ui;

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

    let cli = parse_cli_with_receive_shorthand();

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
            lan_discovery: _,
            no_lan_discovery,
        } => {
            let (secret, _generated) = resolve_secret(secret, true)?;
            print_send_instructions(
                &secret,
                &relay,
                &relay_password,
                no_lan_discovery,
                transfers,
                hash_algorithm,
            );
            client::sender::run_send(SendConfig {
                paths,
                secret,
                relay_addr: relay,
                relay_password,
                no_compress,
                transfers,
                proxy,
                lan_discovery: !no_lan_discovery,
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
            lan_discovery: _,
            no_lan_discovery,
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
                lan_discovery: !no_lan_discovery,
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

fn parse_cli_with_receive_shorthand() -> Cli {
    let args: Vec<String> = std::env::args().collect();
    let rewritten = rewrite_receive_shorthand_args(args);
    Cli::parse_from(rewritten)
}

fn rewrite_receive_shorthand_args(args: Vec<String>) -> Vec<String> {
    if args.len() < 2 {
        return args;
    }

    let first = args[1].as_str();
    let known = matches!(
        first,
        "send" | "receive" | "relay" | "help" | "--help" | "-h" | "--version" | "-V"
    );
    if known || first.starts_with('-') {
        return args;
    }

    let mut rewritten = Vec::with_capacity(args.len() + 2);
    rewritten.push(args[0].clone());
    rewritten.push("receive".to_string());
    rewritten.push("--secret".to_string());
    rewritten.push(args[1].clone());
    rewritten.extend(args.into_iter().skip(2));
    rewritten
}

fn print_send_instructions(
    secret: &str,
    relay: &str,
    relay_password: &str,
    no_lan_discovery: bool,
    transfers: usize,
    hash_algorithm: HashArg,
) {
    let mut cmd = format!("rcroc {} --relay {}", shell_quote(secret), shell_quote(relay));
    if relay_password != "pass" {
        cmd.push_str(&format!(" --relay-password {}", shell_quote(relay_password)));
    }
    if no_lan_discovery {
        cmd.push_str(" --no-lan-discovery");
    }
    if transfers != 4 {
        cmd.push_str(&format!(" --transfers {transfers}"));
    }
    if !matches!(hash_algorithm, HashArg::Xxh3) {
        cmd.push_str(" --hash-algorithm sha256");
    }

    println!("Code is: {secret}");
    println!();
    println!("On the other computer run");
    println!();
    println!("{cmd}");
    println!();
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' | '@'))
    {
        return value.to_string();
    }

    let escaped = value.replace('\'', "'\\''");
    format!("'{escaped}'")
}

#[cfg(test)]
mod tests {
    use super::rewrite_receive_shorthand_args;

    #[test]
    fn rewrites_secret_shorthand_to_receive_command() {
        let args = vec![
            "rcroc".to_string(),
            "abc123".to_string(),
            "--relay".to_string(),
            "1.2.3.4:9009".to_string(),
        ];
        let rewritten = rewrite_receive_shorthand_args(args);
        assert_eq!(
            rewritten,
            vec![
                "rcroc",
                "receive",
                "--secret",
                "abc123",
                "--relay",
                "1.2.3.4:9009",
            ]
        );
    }

    #[test]
    fn keeps_known_subcommand_unchanged() {
        let args = vec![
            "rcroc".to_string(),
            "send".to_string(),
            "a.txt".to_string(),
        ];
        let rewritten = rewrite_receive_shorthand_args(args.clone());
        assert_eq!(rewritten, args);
    }
}
