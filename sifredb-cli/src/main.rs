//! `SifreDB` CLI tool for key management and operations.

#![warn(clippy::pedantic, clippy::nursery)]

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sifredb")]
#[command(about = "SifreDB key management CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate new encryption keys
    Keygen {
        /// Output directory for keys
        #[arg(short, long, default_value = "./keys")]
        output: String,
    },
    /// Rewrap encrypted data with new KEK
    Rewrap {
        /// Old KEK identifier
        #[arg(long)]
        old_kek: String,
        /// New KEK identifier
        #[arg(long)]
        new_kek: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output } => {
            println!("Generating keys in: {output}");
            println!("(Implementation pending)");
        }
        Commands::Rewrap { old_kek, new_kek } => {
            println!("Rewrapping from {old_kek} to {new_kek}");
            println!("(Implementation pending)");
        }
    }
}
