use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::enrich;

#[derive(Debug, Parser)]
#[command(name = "crab")]
#[command(
    about = "CRAB - Cli Response Action Buddy",
    long_about = "CRAB is a lightweight, easy to use tool to perform quick analysis of artifacts."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(arg_required_else_help = true)]
    Enrich {
        #[command(subcommand)]
        command: EnrichCommands,
    },
}

#[derive(Debug, Subcommand)]
enum EnrichCommands {
    #[command(arg_required_else_help = true)]
    Ip {
        address: Option<String>,
        #[arg(long)]
        path: Option<PathBuf>,
    },
    #[command(arg_required_else_help = true)]
    Hash {
        sig: Option<String>,
        #[arg(long)]
        path: Option<PathBuf>,
    },
    #[command(arg_required_else_help = true)]
    Domain {
        name: Option<String>,
        #[arg(long)]
        path: Option<PathBuf>,
    },
    #[command(arg_required_else_help = true)]
    Url {
        link: Option<String>,
        #[arg(long)]
        path: Option<PathBuf>,
    },
}

pub fn run() {
    let args = Cli::parse();
    match args.command {
        Commands::Enrich { command } => enrich(command),
    }
}

fn enrich(command: EnrichCommands) {
    match command {
        EnrichCommands::Ip { address, path } => enrich::ip::pass_ip_args(address, path),
        EnrichCommands::Hash { sig, path } => enrich::hash::pass_hash_args(sig, path),
        EnrichCommands::Domain { name, path } => enrich::domain::pass_domain_args(name, path),
        EnrichCommands::Url { link, path } => enrich::url::pass_url_args(link, path),
    }
}
