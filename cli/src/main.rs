//! # Identity CLI
//!
//! Command-line interface for the decentralized identity management system.
//! Provides commands for DID management, credential issuance, and verification.

use clap::{Parser, Subcommand};
use anyhow::Result;

mod commands;
mod config;
mod utils;

use commands::*;

#[derive(Parser)]
#[command(name = "identity-cli")]
#[command(about = "Decentralized Identity Management System CLI")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// DID management commands
    Did {
        #[command(subcommand)]
        action: DidCommands,
    },
    /// Verifiable Credential commands
    Vc {
        #[command(subcommand)]
        action: VcCommands,
    },
    /// Attestation commands
    Attest {
        #[command(subcommand)]
        action: AttestCommands,
    },
    /// Demo scenarios
    Demo {
        #[command(subcommand)]
        scenario: DemoCommands,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Did { action } => handle_did_command(action).await,
        Commands::Vc { action } => handle_vc_command(action).await,
        Commands::Attest { action } => handle_attest_command(action).await,
        Commands::Demo { scenario } => handle_demo_command(scenario).await,
    }
}
