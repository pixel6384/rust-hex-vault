mod crypto;

use clap::{Parser, Subcommand};
use anyhow::{Result, Context};
use base64::{engine::general_purpose, Engine as _};
use std::fs::{read, write, File};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
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
    salt: Option<String>,
    entries: HashMap<String, String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Encrypt { key, text, salt } => {
            let key_val = resolve_key(key)?;
            let key_bytes = derive_key(&key_val, salt.as_deref());
            let encrypted = crypto::encrypt(text.as_bytes(), &key_bytes)?;
            println!("{}", general_purpose::STANDARD.encode(encrypted));
        }
        Command::Decrypt { key, blob, salt } => {
            let key_val = resolve_key(key)?;
            let key_bytes = derive_key(&key_val, salt.as_deref());
            let encrypted_bytes = general_purpose::STANDARD.decode(blob).context("Failed to decode base64 blob")?;
            let decrypted = crypto::decrypt(&encrypted_bytes, &key_bytes)
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}. Please check your key and blob.", e))?;
            println!("{}", String::from_utf8(decrypted).context("Decrypted data is not valid UTF-8")?);
        }
        Command::EncryptFile { key, input, output, salt } => {
            let key_val = resolve_key(key)?;
            let key_bytes = derive_key(&key_val, salt.as_deref());
            let data = read(input).context("Failed to read input file")?;
            let encrypted = crypto::encrypt(&data, &key_bytes)?;
            write(output, encrypted).context("Failed to write output file")?;
            println!("File encrypted successfully.");
        }
        Command::DecryptFile { key, input, output, salt } => {
            let key_val = resolve_key(key)?;
            let key_bytes = derive_key(&key_val, salt.as_deref());
            let data = read(input).context("Failed to read input file")?;
            let decrypted = crypto::decrypt(&data, &key_bytes)
                .map_err(|e| anyhow::anyhow!("Decryption failed: {}. Please check your key and the file.", e))?;
            write(output, decrypted).context("Failed to write output file")?;
            println!("File decrypted successfully.");
        }
        Command::Vault { action } => match action {
            VaultAction::Set { key, vault_path, name, value } => {
                let key_val = resolve_key(key)?;
                let mut vault = load_vault(vault_path)?;
                
                let salt = vault.salt.clone().unwrap_or_else(|| {
                    let mut s = [0u8; 16];
                    OsRng.fill_bytes(&mut s);
                    let encoded = general_purpose::STANDARD.encode(s);
                    vault.salt = Some(encoded.clone());
                    encoded
                });

                let key_bytes = derive_key(&key_val, Some(&salt));
                let encrypted = crypto::encrypt(value.as_bytes(), &key_bytes)?;
                let blob = general_purpose::STANDARD.encode(encrypted);

                vault.entries.insert(name.clone(), blob);
                save_vault(vault_path, &vault)?;
                println!("Secret '{}' stored in vault.", name);
            }
            VaultAction::Get { key, vault_path, name } => {
                let key_val = resolve_key(key)?;
                let vault = load_vault(vault_path)?;
                let salt = vault.salt.as_deref().context("Vault salt not found")?;
                
                let key_bytes = derive_key(&key_val, Some(salt));
                let blob = vault.entries.get(name).context(format!("Secret '{}' not found in vault", name))?;
                let encrypted_bytes = general_purpose::STANDARD.decode(blob).context("Failed to decode base64 blob")?;
                let decrypted = crypto::decrypt(&encrypted_bytes, &key_bytes)
                    .map_err(|e| anyhow::anyhow!("Decryption failed: {}. Check your key.", e))?;
                println!("{}", String::from_utf8(decrypted).context("Decrypted data is not valid UTF-8")?);
            }
            VaultAction::Delete { vault_path, name } => {
                let mut vault = load_vault(vault_path)?;
                if vault.entries.remove(name).is_some() {
                    save_vault(vault_path, &vault)?;
                    println!("Secret '{}' removed from vault.", name);
                } else {
                    println!("Secret '{}' not found in vault.", name);
                }
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

fn derive_key(password: &str, salt: Option<&str>) -> [u8; 32] {
    let mut key = [0u8; 32];
    const ITERATIONS: u32 = 600_000;
    
    if let Some(s) = salt {
        let salt_bytes = general_purpose::STANDARD.decode(s).unwrap_or_else(|_| s.as_bytes().to_vec());
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt_bytes, ITERATIONS, &mut key);
    } else {
        pbkdf2_hmac::<Sha256>(password.as_bytes(), b"rust-hex-vault-static-salt", ITERATIONS, &mut key);
    }
    
    key
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
