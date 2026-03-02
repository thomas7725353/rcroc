use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "rcroc",
    version,
    about = "Rust rewrite MVP for croc-style transfer"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum HashArg {
    Sha256,
    Xxh3,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Relay {
        #[arg(long, default_value = "0.0.0.0:9009")]
        listen: String,
        #[arg(long, default_value = "pass")]
        relay_password: String,
    },
    Send {
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<PathBuf>,
        #[arg(long)]
        secret: Option<String>,
        #[arg(long, default_value = "127.0.0.1:9009")]
        relay: String,
        #[arg(long, default_value = "pass")]
        relay_password: String,
        #[arg(long, default_value_t = 4, hide = true)]
        transfers: usize,
        #[arg(long)]
        no_compress: bool,
        #[arg(long, value_enum, default_value_t = HashArg::Xxh3, hide = true)]
        hash_algorithm: HashArg,
        #[arg(long)]
        proxy: Option<String>,
        #[arg(long, hide = true)]
        lan_discovery: bool,
        #[arg(long)]
        no_lan_discovery: bool,
    },
    Receive {
        #[arg(long)]
        secret: Option<String>,
        #[arg(long, default_value = "127.0.0.1:9009")]
        relay: String,
        #[arg(long, default_value = "pass")]
        relay_password: String,
        #[arg(long, default_value = ".")]
        out: PathBuf,
        #[arg(long, default_value_t = 4, hide = true)]
        transfers: usize,
        #[arg(long)]
        proxy: Option<String>,
        #[arg(long, hide = true)]
        lan_discovery: bool,
        #[arg(long)]
        no_lan_discovery: bool,
        #[arg(long, default_value_t = 3)]
        discover_timeout: u64,
        #[arg(long, default_value_t = true)]
        resume: bool,
    },
}
