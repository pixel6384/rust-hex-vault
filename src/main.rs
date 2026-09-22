mod crypto;

use clap::{Parser, Subcommand};
use anyhow::{Result, Context};
use base64::{engine::general_purpose, Engine as _};
use sha2::{Sha256, Digest};
use std::fs::{read, write};
use std::path::PathBuf;

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
    /// Encrypt a file
    EncryptFile {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Decrypt a file
    DecryptFile {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
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
            let encrypted_bytes = general_purpose::STANDARD.decode(blob).context("Failed to decode base64 blob")?;
            let decrypted = crypto::decrypt(&encrypted_bytes, &key_bytes)?;
            println!("{}", String::from_utf8(decrypted).context("Decrypted data is not valid UTF-8")?);
        }
        Command::EncryptFile { key, input, output } => {
            let key_bytes = hash_key(key);
            let data = read(input).context("Failed to read input file")?;
            let encrypted = crypto::encrypt(&data, &key_bytes)?;
            write(output, encrypted).context("Failed to write output file")?;
            println!("File encrypted successfully.");
        }
        Command::DecryptFile { key, input, output } => {
            let key_bytes = hash_key(key);
            let data = read(input).context("Failed to read input file")?;
            let decrypted = crypto::decrypt(&data, &key_bytes)?;
            write(output, decrypted).context("Failed to write output file")?;
            println!("File decrypted successfully.");
        }
    }

    Ok()
}

fn hash_key(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.finalize().into()
}
