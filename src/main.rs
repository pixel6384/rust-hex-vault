mod crypto;

use clap::{Parser, Subcommand};
use anyhow::{Result, Context};
use base64::{engine::general_purpose, Engine as _};
use std::fs::{read, write};
use std::io::{self, Write};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use rand::{RngCore, rngs::OsRng};

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
        key: Option<String>,
        #[arg(short, long)]
        text: String,
        #[arg(short, long)]
        salt: Option<String>,
    },
    /// Decrypt a string
    Decrypt {
        #[arg(short, long)]
        key: Option<String>,
        #[arg(short, long)]
        blob: String,
        #[arg(short, long)]
        salt: Option<String>,
    },
    /// Encrypt a file
    EncryptFile {
        #[arg(short, long)]
        key: Option<String>,
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long)]
        salt: Option<String>,
    },
    /// Decrypt a file
    DecryptFile {
        #[arg(short, long)]
        key: Option<String>,
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long)]
        salt: Option<String>,
    },
    /// Manage a vault of secrets
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
    /// Generate a random salt for key derivation
    GenSalt,
}

#[derive(Subcommand)]
enum VaultAction {
    /// Add or update a secret in the vault
    Set {
        #[arg(short, long)]
        key: Option<String>,
        #[arg(short, long)]
        vault_path: PathBuf,
        name: String,
        value: String,
    },
    /// Retrieve a secret from the vault
    Get {
        #[arg(short, long)]
        key: Option<String>,
        #[arg(short, long)]
        vault_path: PathBuf,
        name: String,
    },
    /// Remove a secret from the vault
    Delete {
        #[arg(short, long)]
        key: Option<String>,
        #[arg(short, long)]
        vault_path: PathBuf,
        name: String,
    },
    /// List all keys in the vault
    List {
        #[arg(short, long)]
        key: Option<String>,
        #[arg(short, long)]
        vault_path: PathBuf,
    },
    /// Completely wipe the vault file
    Wipe {
        #[arg(short, long)]
        vault_path: PathBuf,
    },
    /// Show vault metadata
    Info {
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
        Command::Encrypt { key, text, salt } => {
            let key_val = resolve_key(key)?;
            let salt_bytes = resolve_salt(salt);
            let key_bytes = crypto::derive_key(&key_val, &salt_bytes);
            let encrypted = crypto::encrypt(text.as_bytes(), &key_bytes)?;
            println!("{}", general_purpose::STANDARD.encode(encrypted));
        }
        Command::Decrypt { key, blob, salt } => {
            let key_val = resolve_key(key)?;
            let salt_bytes = resolve_salt(salt);
            let key_bytes = crypto::derive_key(&key_val, &salt_bytes);
            let encrypted_bytes = general_purpose::STANDARD.decode(blob).context("Failed to decode base64 blob")?;
            let decrypted = crypto::decrypt(&encrypted_bytes, &key_bytes)
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}. Please check your key and blob.", e))?;
            println!("{}", String::from_utf8(decrypted).context("Decrypted data is not valid UTF-8")?);
        }
        Command::EncryptFile { key, input, output, salt } => {
            let key_val = resolve_key(key)?;
            let salt_bytes = resolve_salt(salt);
            let key_bytes = crypto::derive_key(&key_val, &salt_bytes);
            let data = read(input).context("Failed to read input file")?;
            let encrypted = crypto::encrypt(&data, &key_bytes)?;
            write(output, encrypted).context("Failed to write output file")?;
            println!("File encrypted successfully.");
        }
        Command::DecryptFile { key, input, output, salt } => {
            let key_val = resolve_key(key)?;
            let salt_bytes = resolve_salt(salt);
            let key_bytes = crypto::derive_key(&key_val, &salt_bytes);
            let data = read(input).context("Failed to read input file")?;
            let decrypted = crypto::decrypt(&data, &key_bytes)
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}. Please check your key and the file.", e))?;
            write(output, decrypted).context("Failed to write output file")?;
            println!("File decrypted successfully.");
        }
        Command::Vault { action } => match action {
            VaultAction::Set { key, vault_path, name, value } => {
                let key_val = resolve_key(key)?;
                let mut vault = load_vault(vault_path, &key_val)?;
                
                vault.entries.insert(name.clone(), value.clone());
                save_vault(vault_path, &vault, &key_val)?;
                println!("Secret '{}' stored in vault.", name);
            }
            VaultAction::Get { key, vault_path, name } => {
                let key_val = resolve_key(key)?;
                let vault = load_vault(vault_path, &key_val)?;
                let value = vault.entries.get(name).context(format!("Secret '{}' not found in vault", name))?;
                println!("{}", value);
            }
            VaultAction::Delete { key, vault_path, name } => {
                let key_val = resolve_key(key)?;
                let mut vault = load_vault(vault_path, &key_val)?;
                if vault.entries.remove(name).is_some() {
                    save_vault(vault_path, &vault, &key_val)?;
                    println!("Secret '{}' removed from vault.", name);
                } else {
                    println!("Secret '{}' not found in vault.", name);
                }
            }
            VaultAction::List { key, vault_path } => {
                let key_val = resolve_key(key)?;
                let vault = load_vault(vault_path, &key_val)?;
                if vault.entries.is_empty() {
                    println!("Vault is empty.");
                } else {
                    println!("Vault entries:");
                    for name in vault.entries.keys() {
                        println!(" - {}", name);
                    }
                }
            }
            VaultAction::Wipe { vault_path } => {
                if vault_path.exists() {
                    std::fs::remove_file(vault_path).context("Failed to delete vault file")?;
                    println!("Vault at {:?} has been wiped.", vault_path);
                } else {
                    println!("Vault file does not exist.");
                }
            }
            VaultAction::Info { vault_path } => {
                if vault_path.exists() {
                    let data = read(vault_path).context("Failed to read vault file")?;
                    println!("Vault Path: {:?}", vault_path);
                    println!("Encrypted Size: {} bytes", data.len());
                } else {
                    println!("Vault file does not exist.");
                }
            }
        },
        Command::GenSalt => {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            println!("{}", general_purpose::STANDARD.encode(salt));
        }
    }

    Ok()
}

fn resolve_key(key_arg: &Option<String>) -> Result<String> {
    if let Some(k) = key_arg {
        return Ok(k.clone());
    }
    
    if let Ok(k) = std::env::var("HEXVAULT_KEY") {
        return Ok(k);
    }

    print!("Enter password: ");
    io::stdout().flush()?;
    
    let password = rpassword::read_password().context("Failed to read password from stdin")?;
    let password = password.trim().to_string();
    
    if password.is_empty() {
        return Err(anyhow::anyhow!("Password cannot be empty"));
    }
    
    Ok(password)
}

fn resolve_salt(salt_arg: &Option<String>) -> Vec<u8> {
    if let Some(s) = salt_arg {
        general_purpose::STANDARD.decode(s).unwrap_or_else(|_| s.as_bytes().to_vec())
    } else {
        b"rust-hex-vault-static-salt".to_vec()
    }
}

fn load_vault(path: &PathBuf, password: &str) -> Result<Vault> {
    if !path.exists() {
        return Ok(Vault::default());
    }
    
    let data = read(path).context("Failed to read vault file")?;
    if data.len() < 16 {
        return Err(anyhow::anyhow!("Vault file is corrupted or too short"));
    }

    let (salt, encrypted_data) = data.split_at(16);
    let key_bytes = crypto::derive_key(password, salt);
    
    let decrypted_data = crypto::decrypt(encrypted_data, &key_bytes)
        .map_err(|e| anyhow::anyhow!("Vault decryption failed: {}. Incorrect password?", e))?;

    serde_json::from_slice(&decrypted_data).context("Failed to parse vault JSON")
}

fn save_vault(path: &PathBuf, vault: &Vault, password: &str) -> Result<()> {
    let json_data = serde_json::to_vec_pretty(vault).context("Failed to serialize vault JSON")?;
    
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    
    let key_bytes = crypto::derive_key(password, &salt);
    
    let encrypted_data = crypto::encrypt(&json_data, &key_bytes).context("Failed to encrypt vault")?;
    
    let mut final_data = salt.to_vec();
    final_data.extend(encrypted_data);
    
    write(path, final_data).context("Failed to write vault file")
}
