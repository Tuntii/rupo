//! Deterministic encryption using AES-SIV for equality queries.
//!
//! AES-SIV (Synthetic IV) is a misuse-resistant authenticated encryption mode
//! that produces deterministic output for the same plaintext and context.
//! This enables equality queries on encrypted data without revealing patterns
//! across different contexts.
//!
//! # Security Properties
//!
//! - **Deterministic**: Same plaintext + context → same ciphertext
//! - **Misuse-resistant**: Safe even with nonce reuse
//! - **Authenticated**: Provides confidentiality and authenticity
//! - **Context-bound**: Different contexts produce different ciphertexts
//!
//! # Use Cases
//!
//! - Database equality queries (`WHERE email = ?`)
//! - Deduplication
//! - Deterministic tokens
//!
//! # Security Warning
//!
//! Deterministic encryption reveals equality patterns. Use only for fields
//! requiring equality queries. For other fields, use AEAD encryption.

use aes_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256SivAead,
};
use secrecy::{ExposeSecret, SecretVec};
use zeroize::Zeroizing;

use crate::{context::EncryptionContext, error::Error};

/// Deterministic encryption using AES-256-SIV.
///
/// # Example
///
/// ```rust,ignore
/// use sifredb::deterministic::DeterministicVault;
/// use sifredb::context::EncryptionContext;
/// use secrecy::SecretVec;
///
/// let key = SecretVec::new(vec![0u8; 64]); // 64 bytes for AES-256-SIV
/// let vault = DeterministicVault::new(key);
/// let context = EncryptionContext::new("users", "email");
///
/// let ciphertext1 = vault.encrypt(b"alice@example.com", &context)?;
/// let ciphertext2 = vault.encrypt(b"alice@example.com", &context)?;
/// assert_eq!(ciphertext1, ciphertext2); // Deterministic!
/// ```
pub struct DeterministicVault {
    /// AES-256-SIV requires a 64-byte key (512 bits)
    key: SecretVec<u8>,
}

impl DeterministicVault {
    /// Creates a new deterministic vault with the provided key.
    ///
    /// # Arguments
    ///
    /// * `key` - A 64-byte (512-bit) key for AES-256-SIV
    ///
    /// # Errors
    ///
    /// Returns an error if the key length is not 64 bytes.
    pub fn new(key: SecretVec<u8>) -> Result<Self, Error> {
        if key.expose_secret().len() != 64 {
            return Err(Error::InvalidKeyLength {
                expected: 64,
                actual: key.expose_secret().len(),
            });
        }
        Ok(Self { key })
    }

    /// Encrypts plaintext deterministically using the given context.
    ///
    /// The context is used as Additional Associated Data (AAD), ensuring
    /// that the same plaintext with different contexts produces different
    /// ciphertexts.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt
    /// * `context` - Encryption context (used as AAD)
    ///
    /// # Returns
    ///
    /// Deterministic ciphertext (same input → same output)
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt(&self, plaintext: &[u8], context: &EncryptionContext) -> Result<Vec<u8>, Error> {
        let cipher = Aes256SivAead::new_from_slice(self.key.expose_secret())
            .map_err(|e| Error::Encryption(format!("Failed to create AES-SIV cipher: {e}")))?;

        // Use context as AAD for domain separation
        let aad = Zeroizing::new(context.to_string().into_bytes());
        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };

        // AES-SIV is deterministic - uses empty nonce
        cipher
            .encrypt(&Default::default(), payload)
            .map_err(|e| Error::Encryption(format!("AES-SIV encryption failed: {e}")))
    }

    /// Decrypts ciphertext that was encrypted with the same key and context.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data
    /// * `context` - Encryption context (must match encryption context)
    ///
    /// # Returns
    ///
    /// Original plaintext
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ciphertext is corrupted
    /// - The context doesn't match
    /// - Authentication fails
    pub fn decrypt(&self, ciphertext: &[u8], context: &EncryptionContext) -> Result<Vec<u8>, Error> {
        let cipher = Aes256SivAead::new_from_slice(self.key.expose_secret())
            .map_err(|e| Error::Decryption(format!("Failed to create AES-SIV cipher: {e}")))?;

        // Use same context as AAD
        let aad = Zeroizing::new(context.to_string().into_bytes());
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };

        // AES-SIV uses empty nonce
        cipher
            .decrypt(&Default::default(), payload)
            .map_err(|e| Error::Decryption(format!("AES-SIV decryption failed: {e}")))
    }
}

impl Clone for DeterministicVault {
    fn clone(&self) -> Self {
        // Safe to clone since we're cloning the SecretVec wrapper
        Self {
            key: SecretVec::new(self.key.expose_secret().to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_vault() -> DeterministicVault {
        let key = SecretVec::new(vec![0x42; 64]);
        DeterministicVault::new(key).unwrap()
    }

    #[test]
    fn test_deterministic_encryption() {
        let vault = create_test_vault();
        let context = EncryptionContext::new("users", "email");
        let plaintext = b"alice@example.com";

        let ciphertext1 = vault.encrypt(plaintext, &context).unwrap();
        let ciphertext2 = vault.encrypt(plaintext, &context).unwrap();

        // Same plaintext + context should produce same ciphertext
        assert_eq!(ciphertext1, ciphertext2, "Encryption must be deterministic");
    }

    #[test]
    fn test_deterministic_decrypt() {
        let vault = create_test_vault();
        let context = EncryptionContext::new("users", "email");
        let plaintext = b"alice@example.com";

        let ciphertext = vault.encrypt(plaintext, &context).unwrap();
        let decrypted = vault.decrypt(&ciphertext, &context).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_different_plaintexts_different_ciphertexts() {
        let vault = create_test_vault();
        let context = EncryptionContext::new("users", "email");

        let ct1 = vault.encrypt(b"alice@example.com", &context).unwrap();
        let ct2 = vault.encrypt(b"bob@example.com", &context).unwrap();

        assert_ne!(ct1, ct2, "Different plaintexts must produce different ciphertexts");
    }

    #[test]
    fn test_different_contexts_different_ciphertexts() {
        let vault = create_test_vault();
        let plaintext = b"alice@example.com";

        let ctx1 = EncryptionContext::new("users", "email");
        let ctx2 = EncryptionContext::new("users", "phone");

        let ct1 = vault.encrypt(plaintext, &ctx1).unwrap();
        let ct2 = vault.encrypt(plaintext, &ctx2).unwrap();

        assert_ne!(ct1, ct2, "Different contexts must produce different ciphertexts");
    }

    #[test]
    fn test_wrong_context_fails_authentication() {
        let vault = create_test_vault();
        let plaintext = b"alice@example.com";

        let ctx1 = EncryptionContext::new("users", "email");
        let ctx2 = EncryptionContext::new("users", "phone");

        let ciphertext = vault.encrypt(plaintext, &ctx1).unwrap();
        let result = vault.decrypt(&ciphertext, &ctx2);

        assert!(result.is_err(), "Decryption with wrong context must fail");
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let vault = create_test_vault();
        let context = EncryptionContext::new("users", "email");
        let plaintext = b"alice@example.com";

        let mut ciphertext = vault.encrypt(plaintext, &context).unwrap();
        
        // Corrupt the ciphertext
        if let Some(byte) = ciphertext.first_mut() {
            *byte ^= 0xFF;
        }

        let result = vault.decrypt(&ciphertext, &context);
        assert!(result.is_err(), "Corrupted ciphertext must fail authentication");
    }

    #[test]
    fn test_empty_plaintext() {
        let vault = create_test_vault();
        let context = EncryptionContext::new("users", "email");

        let ciphertext = vault.encrypt(b"", &context).unwrap();
        let decrypted = vault.decrypt(&ciphertext, &context).unwrap();

        assert_eq!(b"", decrypted.as_slice());
    }

    #[test]
    fn test_large_plaintext() {
        let vault = create_test_vault();
        let context = EncryptionContext::new("users", "data");
        let plaintext = vec![0x42; 10_000];

        let ciphertext = vault.encrypt(&plaintext, &context).unwrap();
        let decrypted = vault.decrypt(&ciphertext, &context).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = SecretVec::new(vec![0x42; 32]);
        let result = DeterministicVault::new(short_key);

        assert!(result.is_err(), "Should reject key with wrong length");
        if let Err(Error::InvalidKeyLength { expected, actual }) = result {
            assert_eq!(expected, 64);
            assert_eq!(actual, 32);
        }
    }

    #[test]
    fn test_multi_tenant_isolation() {
        let vault = create_test_vault();
        let plaintext = b"secret@example.com";

        let ctx_tenant1 = EncryptionContext::new("users", "email").with_tenant("tenant1");
        let ctx_tenant2 = EncryptionContext::new("users", "email").with_tenant("tenant2");

        let ct1 = vault.encrypt(plaintext, &ctx_tenant1).unwrap();
        let ct2 = vault.encrypt(plaintext, &ctx_tenant2).unwrap();

        assert_ne!(ct1, ct2, "Different tenants must produce different ciphertexts");

        // Verify decryption works with correct tenant
        let decrypted1 = vault.decrypt(&ct1, &ctx_tenant1).unwrap();
        assert_eq!(plaintext, decrypted1.as_slice());

        // Verify wrong tenant fails
        let result = vault.decrypt(&ct1, &ctx_tenant2);
        assert!(result.is_err(), "Wrong tenant must fail decryption");
    }

    #[test]
    fn test_vault_clone() {
        let vault1 = create_test_vault();
        let vault2 = vault1.clone();
        let context = EncryptionContext::new("users", "email");
        let plaintext = b"test@example.com";

        let ct1 = vault1.encrypt(plaintext, &context).unwrap();
        let ct2 = vault2.encrypt(plaintext, &context).unwrap();

        // Cloned vault should produce same deterministic output
        assert_eq!(ct1, ct2);

        // Both should decrypt successfully
        let pt1 = vault1.decrypt(&ct1, &context).unwrap();
        let pt2 = vault2.decrypt(&ct2, &context).unwrap();
        assert_eq!(pt1, pt2);
        assert_eq!(plaintext, pt1.as_slice());
    }
}
