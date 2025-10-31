//! Vault for encryption and decryption operations.
//!
//! The Vault provides high-level encryption and decryption operations using
//! envelope encryption with AEAD ciphers.

use crate::context::EncryptionContext;
use crate::error::Error;
use crate::header::{EncryptionHeader, HeaderFlags};
use crate::kdf::generate_dek;
use crate::key_provider::KeyProvider;
use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use secrecy::ExposeSecret;
use std::sync::Arc;

/// Nonce size for ChaCha20-Poly1305 (96 bits).
const NONCE_SIZE: usize = 12;

/// Cipher mode for encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    /// ChaCha20-Poly1305 AEAD cipher (default).
    ChaCha20Poly1305,
}

impl Default for CipherMode {
    fn default() -> Self {
        Self::ChaCha20Poly1305
    }
}

/// Vault for encryption and decryption operations.
///
/// The Vault uses envelope encryption:
/// 1. Generate a random DEK (Data Encryption Key)
/// 2. Encrypt data with the DEK using AEAD
/// 3. Wrap (encrypt) the DEK with a KEK (Key Encryption Key) from the provider
/// 4. Store the wrapped DEK in the ciphertext header
///
/// # Example
///
/// ```ignore
/// use sifredb::vault::{Vault, CipherMode};
/// use sifredb::context::EncryptionContext;
/// use sifredb_key_file::FileKeyProvider;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let provider = FileKeyProvider::new("./keys")?;
/// let vault = Vault::new(provider, CipherMode::default());
///
/// let context = EncryptionContext::new("users", "email");
/// let plaintext = b"alice@example.com";
///
/// let ciphertext = vault.encrypt(plaintext, &context)?;
/// let decrypted = vault.decrypt(&ciphertext, &context)?;
///
/// assert_eq!(plaintext, &decrypted[..]);
/// # Ok(())
/// # }
/// ```
pub struct Vault<P: KeyProvider> {
    provider: Arc<P>,
    cipher_mode: CipherMode,
}

impl<P: KeyProvider> Vault<P> {
    /// Creates a new Vault with the specified key provider and cipher mode.
    ///
    /// # Arguments
    ///
    /// * `provider` - Key provider for KEK management
    /// * `cipher_mode` - Cipher mode to use for encryption
    pub fn new(provider: P, cipher_mode: CipherMode) -> Self {
        Self { provider: Arc::new(provider), cipher_mode }
    }

    /// Encrypts plaintext using envelope encryption.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data to encrypt
    /// * `context` - Encryption context for domain separation
    ///
    /// # Returns
    ///
    /// Ciphertext with embedded header: `[header][encrypted_data]`
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key provider operations fail
    /// - Encryption fails
    /// - Header serialization fails
    pub fn encrypt(&self, plaintext: &[u8], context: &EncryptionContext) -> Result<Vec<u8>, Error> {
        // Generate a random DEK for this encryption operation
        let dek = generate_dek();

        // Get the current KEK ID
        let kek_id = self.provider.current_kek_id()?;

        // Wrap the DEK with the KEK
        let wrapped_dek = self.provider.wrap_dek(&kek_id, dek.expose_secret())?;

        // Generate a random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);

        // Encrypt the plaintext with the DEK
        let ciphertext = match self.cipher_mode {
            CipherMode::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(dek.expose_secret())
                    .map_err(|e| Error::EncryptionFailed(format!("Invalid DEK: {e}")))?;

                let nonce = Nonce::from(nonce_bytes);

                // Use context as associated data for additional authentication
                let aad = context.to_string();

                cipher
                    .encrypt(
                        &nonce,
                        chacha20poly1305::aead::Payload { msg: plaintext, aad: aad.as_bytes() },
                    )
                    .map_err(|e| {
                        Error::EncryptionFailed(format!("ChaCha20-Poly1305 encryption failed: {e}"))
                    })?
            }
        };

        // Create header
        let header =
            EncryptionHeader::new(kek_id, wrapped_dek, HeaderFlags::empty(), nonce_bytes.to_vec());

        // Serialize header
        let header_bytes = header.to_bytes()?;

        // Combine header and ciphertext
        let mut result = Vec::with_capacity(header_bytes.len() + ciphertext.len());
        result.extend_from_slice(&header_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypts ciphertext using envelope encryption.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Encrypted data with header
    /// * `context` - Encryption context (must match the one used for encryption)
    ///
    /// # Returns
    ///
    /// The original plaintext.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Header parsing fails
    /// - Key provider operations fail
    /// - Decryption fails
    /// - Authentication fails
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        context: &EncryptionContext,
    ) -> Result<Vec<u8>, Error> {
        // Parse header
        let (header, header_len) = EncryptionHeader::from_bytes(ciphertext)?;

        // Extract the encrypted data
        let encrypted_data = &ciphertext[header_len..];

        // Unwrap the DEK
        let dek = self.provider.unwrap_dek(header.kek_id(), header.wrapped_dek())?;

        // Decrypt the data
        let plaintext = match self.cipher_mode {
            CipherMode::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(dek.expose_secret())
                    .map_err(|e| Error::DecryptionFailed(format!("Invalid DEK: {e}")))?;

                let nonce_bytes: [u8; NONCE_SIZE] = header
                    .nonce()
                    .try_into()
                    .map_err(|_| Error::DecryptionFailed("Invalid nonce size".to_string()))?;
                let nonce = Nonce::from(nonce_bytes);

                // Use context as associated data for authentication
                let aad = context.to_string();

                cipher
                    .decrypt(
                        &nonce,
                        chacha20poly1305::aead::Payload {
                            msg: encrypted_data,
                            aad: aad.as_bytes(),
                        },
                    )
                    .map_err(|_| Error::AuthenticationFailed)?
            }
        };

        Ok(plaintext)
    }
}

impl<P: KeyProvider> Clone for Vault<P> {
    fn clone(&self) -> Self {
        Self { provider: Arc::clone(&self.provider), cipher_mode: self.cipher_mode }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::KeyProviderError;
    use secrecy::SecretVec;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // Mock key provider for testing
    struct MockKeyProvider {
        keks: Mutex<HashMap<String, SecretVec<u8>>>,
        current_kek_id: String,
    }

    impl MockKeyProvider {
        fn new() -> Self {
            let mut keks = HashMap::new();
            let kek = SecretVec::new(vec![42u8; 32]);
            keks.insert("test_kek".to_string(), kek);

            Self { keks: Mutex::new(keks), current_kek_id: "test_kek".to_string() }
        }
    }

    impl KeyProvider for MockKeyProvider {
        fn create_kek(&self) -> Result<String, KeyProviderError> {
            let kek_id = format!("kek_{}", self.keks.lock().unwrap().len());
            let kek = SecretVec::new(vec![1u8; 32]);
            self.keks.lock().unwrap().insert(kek_id.clone(), kek);
            Ok(kek_id)
        }

        fn current_kek_id(&self) -> Result<String, KeyProviderError> {
            Ok(self.current_kek_id.clone())
        }

        fn wrap_dek(&self, kek_id: &str, dek: &[u8]) -> Result<Vec<u8>, KeyProviderError> {
            let keks = self.keks.lock().unwrap();
            let kek = keks
                .get(kek_id)
                .ok_or_else(|| KeyProviderError::KekNotFound(kek_id.to_string()))?;

            // Simple XOR "encryption" for testing
            let wrapped: Vec<u8> =
                dek.iter().zip(kek.expose_secret().iter().cycle()).map(|(d, k)| d ^ k).collect();

            drop(keks);
            Ok(wrapped)
        }

        fn unwrap_dek(
            &self,
            kek_id: &str,
            wrapped_dek: &[u8],
        ) -> Result<SecretVec<u8>, KeyProviderError> {
            let keks = self.keks.lock().unwrap();
            let kek = keks
                .get(kek_id)
                .ok_or_else(|| KeyProviderError::KekNotFound(kek_id.to_string()))?;

            // Simple XOR "decryption" for testing (XOR is symmetric)
            let dek: Vec<u8> = wrapped_dek
                .iter()
                .zip(kek.expose_secret().iter().cycle())
                .map(|(w, k)| w ^ k)
                .collect();

            drop(keks);
            Ok(SecretVec::new(dek))
        }
    }

    #[test]
    fn test_vault_encrypt_decrypt_round_trip() {
        let provider = MockKeyProvider::new();
        let vault = Vault::new(provider, CipherMode::default());
        let context = EncryptionContext::new("users", "email");

        let plaintext = b"alice@example.com";
        let ciphertext = vault.encrypt(plaintext, &context).expect("Encryption failed");
        let decrypted = vault.decrypt(&ciphertext, &context).expect("Decryption failed");

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_vault_different_plaintexts() {
        let provider = MockKeyProvider::new();
        let vault = Vault::new(provider, CipherMode::default());
        let context = EncryptionContext::new("users", "email");

        let plaintext1 = b"alice@example.com";
        let plaintext2 = b"bob@example.com";

        let ciphertext1 = vault.encrypt(plaintext1, &context).unwrap();
        let ciphertext2 = vault.encrypt(plaintext2, &context).unwrap();

        // Different plaintexts should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);

        let decrypted1 = vault.decrypt(&ciphertext1, &context).unwrap();
        let decrypted2 = vault.decrypt(&ciphertext2, &context).unwrap();

        assert_eq!(plaintext1, &decrypted1[..]);
        assert_eq!(plaintext2, &decrypted2[..]);
    }

    #[test]
    fn test_vault_different_contexts() {
        let provider = MockKeyProvider::new();
        let vault = Vault::new(provider, CipherMode::default());

        let context1 = EncryptionContext::new("users", "email");
        let context2 = EncryptionContext::new("users", "name");

        let plaintext = b"alice@example.com";

        let ciphertext1 = vault.encrypt(plaintext, &context1).unwrap();
        let ciphertext2 = vault.encrypt(plaintext, &context2).unwrap();

        // Same plaintext with different contexts should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);

        // Decrypt with correct contexts
        let decrypted1 = vault.decrypt(&ciphertext1, &context1).unwrap();
        let decrypted2 = vault.decrypt(&ciphertext2, &context2).unwrap();

        assert_eq!(plaintext, &decrypted1[..]);
        assert_eq!(plaintext, &decrypted2[..]);
    }

    #[test]
    fn test_vault_wrong_context_fails() {
        let provider = MockKeyProvider::new();
        let vault = Vault::new(provider, CipherMode::default());

        let context1 = EncryptionContext::new("users", "email");
        let context2 = EncryptionContext::new("users", "name");

        let plaintext = b"alice@example.com";
        let ciphertext = vault.encrypt(plaintext, &context1).unwrap();

        // Decrypt with wrong context should fail authentication
        let result = vault.decrypt(&ciphertext, &context2);
        assert!(matches!(result, Err(Error::AuthenticationFailed)));
    }

    #[test]
    fn test_vault_empty_plaintext() {
        let provider = MockKeyProvider::new();
        let vault = Vault::new(provider, CipherMode::default());
        let context = EncryptionContext::new("users", "email");

        let plaintext = b"";
        let ciphertext = vault.encrypt(plaintext, &context).unwrap();
        let decrypted = vault.decrypt(&ciphertext, &context).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_vault_large_plaintext() {
        let provider = MockKeyProvider::new();
        let vault = Vault::new(provider, CipherMode::default());
        let context = EncryptionContext::new("users", "data");

        let plaintext = vec![42u8; 10000];
        let ciphertext = vault.encrypt(&plaintext, &context).unwrap();
        let decrypted = vault.decrypt(&ciphertext, &context).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_vault_corrupted_ciphertext_fails() {
        let provider = MockKeyProvider::new();
        let vault = Vault::new(provider, CipherMode::default());
        let context = EncryptionContext::new("users", "email");

        let plaintext = b"alice@example.com";
        let mut ciphertext = vault.encrypt(plaintext, &context).unwrap();

        // Corrupt the ciphertext
        let len = ciphertext.len();
        if len > 10 {
            ciphertext[len - 1] ^= 0xFF;
        }

        // Decryption should fail
        let result = vault.decrypt(&ciphertext, &context);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_clone() {
        let provider = MockKeyProvider::new();
        let vault1 = Vault::new(provider, CipherMode::default());
        let vault2 = vault1.clone();

        let context = EncryptionContext::new("users", "email");
        let plaintext = b"test";

        let ciphertext = vault1.encrypt(plaintext, &context).unwrap();
        let decrypted = vault2.decrypt(&ciphertext, &context).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }
}
