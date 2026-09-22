mod crypto;

use clap::{Parser, Subcommand};
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};

#[derive(Parser)]
#[command(name = "hexvault")]
#[command(about = "Encrypt and decrypt strings and files securely", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command:
        Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a string
    Encrypt {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        text: String,
    },
    /// Decrypt a string
    Decrypt {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        blob: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Encrypt { key, text } => {
            let key_bytes = hash_key(key);
            let encrypted = crypto::encrypt(text.as_bytes(), &key_bytes)?;
            println!("{}", general_purpose::STANDARD.encode(encrypted));
        }
        Command::Decrypt { key, blob } => {
            let key_bytes = hash_key(key);
            let encrypted_bytes = general_purpose::STANDARD.decode(blob)?;
            let decrypted = crypto::decrypt(&encrypted_bytes, &key_bytes)?;
            println!("{}", String::from_utf8(decrypted)?);
        }
    }

    Ok()
}

fn hash_key(key: &str) -> [u8; 32] {
    let mut hashed = [0u8; 32];
    let bytes = key.as_bytes();
    for i in 0..32 {
        hashed[i] = bytes[i % bytes.len()].wrapping_add(i as u8);
    }
    hashed
}
