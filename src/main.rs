mod crypto;

use clap::{Parser, Subcommand};
use anyhow::{Result, Context};
use base64::{engine::general_purpose, Engine as _};
use sha2::{Sha256, Digest};
use std::fs::{read, write, File};
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "hexvault")]
#[command(about = "Encrypt and decrypt strings and files securely", long_about = None)]
#[command(version = env!("CARGO_PKG_VERSION"))]
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
    /// Manage a vault of secrets
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
}

#[derive(Subcommand)]
enum VaultAction {
    /// Add or update a secret in the vault
    Set {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        vault_path: PathBuf,
        name: String,
        value: String,
    },
    /// Retrieve a secret from the vault
    Get {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        vault_path: PathBuf,
        name: String,
    },
    /// List all keys in the vault
    List {
        #[arg(short, long)]
        vault_path: PathBuf,
    },
}

#[derive(Serialize, Deserialize, Default)]
struct Vault {
    entries: HashMap<String, String>,
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
            let decrypted = crypto::decrypt(&encrypted_bytes, &key_bytes)
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}. Please check your key and blob.", e))?;
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
            let decrypted = crypto::decrypt(&data, &key_bytes)
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}. Please check your key and the file.", e))?;
            write(output, decrypted).context("Failed to write output file")?;
            println!("File decrypted successfully.");
        }
        Command::Vault { action } => match action {
            VaultAction::Set { key, vault_path, name, value } => {
                let key_bytes = hash_key(key);
                let encrypted = crypto::encrypt(value.as_bytes(), &key_bytes)?;
                let blob = general_purpose::STANDARD.encode(encrypted);

                let mut vault = load_vault(vault_path)?;
                vault.entries.insert(name.clone(), blob);
                save_vault(vault_path, &vault)?;
                println!("Secret '{}' stored in vault.", name);
            }
            VaultAction::Get { key, vault_path, name } => {
                let key_bytes = hash_key(key);
                let vault = load_vault(vault_path)?;
                let blob = vault.entries.get(name).context(format!("Secret '{}' not found in vault", name))?;
                let encrypted_bytes = general_purpose::STANDARD.decode(blob).context("Failed to decode base64 blob")?;
                let decrypted = crypto::decrypt(&encrypted_bytes, &key_bytes)
                    .map_err(|e| anyhow::anyhow!("Decryption failed: {}. Check your key.", e))?;
                println!("{}", String::from_utf8(decrypted).context("Decrypted data is not valid UTF-8")?);
            }
            VaultAction::List { vault_path } => {
                let vault = load_vault(vault_path)?;
                if vault.entries.is_empty() {
                    println!("Vault is empty.");
                } else {
                    println!("Vault entries:");
                    for name in vault.entries.keys() {
                        println!(" - {}", name);
                    }
                }
            }
        },
    }

    Ok()
}

fn hash_key(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.finalize().into()
}

fn load_vault(path: &PathBuf) -> Result<Vault> {
    if !path.exists() {
        return Ok(Vault::default());
    }
    let file = File::open(path).context("Failed to open vault file")?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).context("Failed to parse vault JSON")
}

fn save_vault(path: &PathBuf, vault: &Vault) -> Result<()> {
    let file = File::create(path).context("Failed to create vault file")?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, vault).context("Failed to write vault JSON")
}
