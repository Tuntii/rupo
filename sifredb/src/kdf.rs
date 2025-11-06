//! Key derivation using HKDF (HMAC-based Key Derivation Function).
//!
//! This module implements key derivation for generating Data Encryption Keys (DEKs)
//! from a Key Encryption Key (KEK) using HKDF with SHA-256.

use crate::context::EncryptionContext;
use crate::error::Error;
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretVec};
use sha2::Sha256;

/// Standard DEK size in bytes (256 bits).
pub const DEK_SIZE: usize = 32;

/// Derives a Data Encryption Key (DEK) from a KEK using HKDF.
///
/// The derivation uses the encryption context as the `info` parameter for domain separation:
/// `tenant_id|table_name|column_name|version`
///
/// # Arguments
///
/// * `kek` - The Key Encryption Key to derive from
/// * `context` - The encryption context for domain separation
///
/// # Returns
///
/// A 32-byte DEK suitable for AEAD encryption.
///
/// # Errors
///
/// Returns `Error::KeyDerivation` if the derivation fails.
///
/// # Example
///
/// ```
/// use sifredb::kdf::derive_dek;
/// use sifredb::context::EncryptionContext;
/// use secrecy::SecretVec;
///
/// let kek = SecretVec::new(vec![0u8; 32]);
/// let context = EncryptionContext::new("users", "email");
/// let dek = derive_dek(&kek, &context).expect("DEK derivation failed");
/// ```
pub fn derive_dek(
    kek: &SecretVec<u8>,
    context: &EncryptionContext,
) -> Result<SecretVec<u8>, Error> {
    // Create HKDF instance with the KEK as input key material
    let hkdf = Hkdf::<Sha256>::new(None, kek.expose_secret());

    // Use the context string as the info parameter for domain separation
    let info = context.to_string();
    let info_bytes = info.as_bytes();

    // Derive a DEK of the standard size
    let mut dek = vec![0u8; DEK_SIZE];
    hkdf.expand(info_bytes, &mut dek).map_err(|_| Error::KeyDerivation)?;

    Ok(SecretVec::new(dek))
}

/// Generates a random DEK for envelope encryption.
///
/// This DEK should be wrapped (encrypted) with a KEK before storage.
///
/// # Returns
///
/// A 32-byte random DEK.
///
/// # Example
///
/// ```
/// use sifredb::kdf::generate_dek;
/// use secrecy::ExposeSecret;
///
/// let dek = generate_dek();
/// assert_eq!(dek.expose_secret().len(), 32);
/// ```
#[must_use]
pub fn generate_dek() -> SecretVec<u8> {
    use chacha20poly1305::aead::{rand_core::RngCore, OsRng};

    let mut dek = vec![0u8; DEK_SIZE];
    OsRng.fill_bytes(&mut dek);
    SecretVec::new(dek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_dek_deterministic() {
        let kek = SecretVec::new(vec![1u8; 32]);
        let context =
            EncryptionContext::new("users", "email").with_tenant("tenant_123").with_version(1);

        let dek1 = derive_dek(&kek, &context).expect("DEK derivation failed");
        let dek2 = derive_dek(&kek, &context).expect("DEK derivation failed");

        // Same KEK and context should produce the same DEK
        assert_eq!(dek1.expose_secret(), dek2.expose_secret());
    }

    #[test]
    fn test_derive_dek_different_contexts() {
        let kek = SecretVec::new(vec![1u8; 32]);
        let context1 = EncryptionContext::new("users", "email");
        let context2 = EncryptionContext::new("users", "name");

        let dek1 = derive_dek(&kek, &context1).expect("DEK derivation failed");
        let dek2 = derive_dek(&kek, &context2).expect("DEK derivation failed");

        // Different contexts should produce different DEKs
        assert_ne!(dek1.expose_secret(), dek2.expose_secret());
    }

    #[test]
    fn test_derive_dek_different_tenants() {
        let kek = SecretVec::new(vec![1u8; 32]);
        let context1 = EncryptionContext::new("users", "email").with_tenant("tenant_1");
        let context2 = EncryptionContext::new("users", "email").with_tenant("tenant_2");

        let dek1 = derive_dek(&kek, &context1).expect("DEK derivation failed");
        let dek2 = derive_dek(&kek, &context2).expect("DEK derivation failed");

        // Different tenants should produce different DEKs
        assert_ne!(dek1.expose_secret(), dek2.expose_secret());
    }

    #[test]
    fn test_derive_dek_different_versions() {
        let kek = SecretVec::new(vec![1u8; 32]);
        let context1 = EncryptionContext::new("users", "email").with_version(1);
        let context2 = EncryptionContext::new("users", "email").with_version(2);

        let dek1 = derive_dek(&kek, &context1).expect("DEK derivation failed");
        let dek2 = derive_dek(&kek, &context2).expect("DEK derivation failed");

        // Different versions should produce different DEKs
        assert_ne!(dek1.expose_secret(), dek2.expose_secret());
    }

    #[test]
    fn test_derive_dek_output_length() {
        let kek = SecretVec::new(vec![42u8; 32]);
        let context = EncryptionContext::new("test_table", "test_column");

        let dek = derive_dek(&kek, &context).expect("DEK derivation failed");

        assert_eq!(dek.expose_secret().len(), DEK_SIZE);
    }

    #[test]
    fn test_generate_dek() {
        let dek1 = generate_dek();
        let dek2 = generate_dek();

        // Generated DEKs should be different
        assert_ne!(dek1.expose_secret(), dek2.expose_secret());

        // Both should be the correct size
        assert_eq!(dek1.expose_secret().len(), DEK_SIZE);
        assert_eq!(dek2.expose_secret().len(), DEK_SIZE);
    }

    #[test]
    fn test_derive_dek_with_different_keks() {
        let kek1 = SecretVec::new(vec![1u8; 32]);
        let kek2 = SecretVec::new(vec![2u8; 32]);
        let context = EncryptionContext::new("users", "email");

        let dek1 = derive_dek(&kek1, &context).expect("DEK derivation failed");
        let dek2 = derive_dek(&kek2, &context).expect("DEK derivation failed");

        // Different KEKs should produce different DEKs
        assert_ne!(dek1.expose_secret(), dek2.expose_secret());
    }

    // RFC 5869 Test Vector (using HKDF-SHA256)
    // https://tools.ietf.org/html/rfc5869#appendix-A.1
    // Test Case 1: Basic test with SHA-256
    #[test]
    fn test_hkdf_rfc5869_test_case_1() {
        // Input Key Material: 22 octets of 0x0b
        const IKM_HEX: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        // Salt: 13 octets from 0x00 to 0x0c
        const SALT_HEX: &str = "000102030405060708090a0b0c";
        // Context/Info: 10 octets from 0xf0 to 0xf9
        const INFO_HEX: &str = "f0f1f2f3f4f5f6f7f8f9";
        // Expected Output: 42 octets
        const EXPECTED_OKM_HEX: &str =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

        let ikm = hex::decode(IKM_HEX).unwrap();
        let salt = hex::decode(SALT_HEX).unwrap();
        let info = hex::decode(INFO_HEX).unwrap();
        let expected_okm = hex::decode(EXPECTED_OKM_HEX).unwrap();

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = vec![0u8; 42];
        hkdf.expand(&info, &mut okm).expect("HKDF expand failed");

        assert_eq!(okm, expected_okm);
    }
}
