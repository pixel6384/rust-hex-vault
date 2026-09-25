use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use anyhow::{anyhow, Result};
use rand::RngCore;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// Derives a 32-byte key from a password and salt using PBKDF2-HMAC-SHA256.
pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    const ITERATIONS: u32 = 600_000;
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, ITERATIONS, &mut key);
    key
}

pub fn encrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Invalid key length: {}", e))?;
    
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| anyhow!("Encryption failure: {}", e))?;

    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);
    Ok(result)
}

pub fn decrypt(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if encrypted_data.len() < 12 {
        return Err(anyhow!("Ciphertext too short"));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Invalid key length: {}", e))?;

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Decryption failure: {}", e))
}

#[cfg(test)]
mod tests {
    use super;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let data = b"Hello, secure world!";
        
        let encrypted = encrypt(data, &key).expect("Encryption failed");
        let decrypted = decrypt(&encrypted, &key).expect("Decryption failed");
        
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let data = b"Secret message";
        
        let encrypted = encrypt(data, &key1).expect("Encryption failed");
        let result = decrypt(&encrypted, &key2);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_corrupted_data() {
        let key = [0u8; 32];
        let data = b"Secret message";
        
        let mut encrypted = encrypt(data, &key).expect("Encryption failed");
        // Corrupt the ciphertext part (after the 12-byte nonce)
        if encrypted.len() > 12 {
            encrypted[13] ^= 0xFF;
        }
        
        let result = decrypt(&encrypted, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = [0u8; 16];
        let data = b"data";
        
        assert!(encrypt(data, &short_key).is_err());
        assert!(decrypt(b"123456789012encrypted", &short_key).is_err());
    }

    #[test]
    fn test_ciphertext_too_short() {
        let key = [0u8; 32];
        let too_short = [0u8; 11];
        
        let result = decrypt(&too_short, &key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Ciphertext too short"));
    }
}