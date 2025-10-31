//! Blind index generation for searchable encryption.
//!
//! Blind indexes allow equality queries on encrypted data without revealing
//! the plaintext value. They use HMAC with a secret pepper for domain separation.

use crate::context::IndexContext;
use crate::error::Error;
use crate::key_provider::KeyProvider;
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Standard blind index output size (16 bytes).
pub const BLIND_INDEX_SIZE: usize = 16;

/// Generates a blind index for searchable encryption.
///
/// The blind index is computed as:
/// `HMAC-SHA256(pepper, value || context)[..16]`
///
/// # Arguments
///
/// * `provider` - Key provider that supplies the pepper
/// * `value` - The plaintext value to index
/// * `context` - Index context for domain separation
///
/// # Returns
///
/// A 16-byte blind index that can be stored alongside encrypted data.
///
/// # Errors
///
/// Returns error if:
/// - Pepper is not available from the provider
/// - HMAC computation fails
///
/// # Example
///
/// ```ignore
/// use sifredb::blind_index::generate_blind_index;
/// use sifredb::context::IndexContext;
/// use sifredb_key_file::FileKeyProvider;
///
/// let provider = FileKeyProvider::new("./keys")?;
/// let context = IndexContext::new("users", "email");
/// let index = generate_blind_index(&provider, b"alice@example.com", &context)?;
/// ```
pub fn generate_blind_index<P: KeyProvider>(
    provider: &P,
    value: &[u8],
    context: &IndexContext,
) -> Result<Vec<u8>, Error> {
    // Get pepper from provider
    let pepper = provider
        .get_pepper()?
        .ok_or_else(|| Error::IndexGenerationFailed("Pepper not available".to_string()))?;

    // Create HMAC instance with pepper as key
    let mut mac = HmacSha256::new_from_slice(pepper.expose_secret())
        .map_err(|e| Error::IndexGenerationFailed(format!("Invalid pepper: {e}")))?;

    // Include value
    mac.update(value);

    // Include context for domain separation (tenant|table|column)
    let context_str = context.to_string();
    mac.update(context_str.as_bytes());

    // Compute HMAC and truncate to BLIND_INDEX_SIZE
    let result = mac.finalize();
    let bytes = result.into_bytes();

    Ok(bytes[..BLIND_INDEX_SIZE].to_vec())
}

/// Generates a deterministic blind index suitable for equality queries.
///
/// This is a convenience wrapper around `generate_blind_index` that ensures
/// the same value and context always produce the same index.
///
/// # Arguments
///
/// * `provider` - Key provider that supplies the pepper
/// * `value` - The plaintext value to index
/// * `context` - Index context for domain separation
///
/// # Returns
///
/// A deterministic 16-byte blind index.
///
/// # Errors
///
/// Returns error if index generation fails.
///
/// # Example
///
/// ```ignore
/// use sifredb::blind_index::generate_deterministic_index;
/// use sifredb::context::IndexContext;
/// use sifredb_key_file::FileKeyProvider;
///
/// let provider = FileKeyProvider::new("./keys")?;
/// let context = IndexContext::new("users", "email");
///
/// let index1 = generate_deterministic_index(&provider, b"alice@example.com", &context)?;
/// let index2 = generate_deterministic_index(&provider, b"alice@example.com", &context)?;
///
/// assert_eq!(index1, index2); // Same input produces same index
/// ```
pub fn generate_deterministic_index<P: KeyProvider>(
    provider: &P,
    value: &[u8],
    context: &IndexContext,
) -> Result<Vec<u8>, Error> {
    generate_blind_index(provider, value, context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::KeyProviderError;
    use secrecy::SecretVec;

    // Mock key provider for testing
    struct MockKeyProvider {
        pepper: Option<SecretVec<u8>>,
    }

    impl MockKeyProvider {
        fn with_pepper(pepper: Vec<u8>) -> Self {
            Self { pepper: Some(SecretVec::new(pepper)) }
        }

        fn without_pepper() -> Self {
            Self { pepper: None }
        }
    }

    impl KeyProvider for MockKeyProvider {
        fn create_kek(&self) -> Result<String, KeyProviderError> {
            Ok("mock_kek".to_string())
        }

        fn current_kek_id(&self) -> Result<String, KeyProviderError> {
            Ok("mock_kek".to_string())
        }

        fn wrap_dek(&self, _kek_id: &str, dek: &[u8]) -> Result<Vec<u8>, KeyProviderError> {
            Ok(dek.to_vec())
        }

        fn unwrap_dek(
            &self,
            _kek_id: &str,
            wrapped_dek: &[u8],
        ) -> Result<SecretVec<u8>, KeyProviderError> {
            Ok(SecretVec::new(wrapped_dek.to_vec()))
        }

        fn get_pepper(&self) -> Result<Option<SecretVec<u8>>, KeyProviderError> {
            Ok(self.pepper.as_ref().map(|p| SecretVec::new(p.expose_secret().clone())))
        }
    }

    #[test]
    fn test_blind_index_deterministic() {
        let provider = MockKeyProvider::with_pepper(vec![42u8; 32]);
        let context = IndexContext::new("users", "email");
        let value = b"alice@example.com";

        let index1 = generate_blind_index(&provider, value, &context).unwrap();
        let index2 = generate_blind_index(&provider, value, &context).unwrap();

        assert_eq!(index1, index2);
        assert_eq!(index1.len(), BLIND_INDEX_SIZE);
    }

    #[test]
    fn test_blind_index_different_values() {
        let provider = MockKeyProvider::with_pepper(vec![42u8; 32]);
        let context = IndexContext::new("users", "email");

        let index1 = generate_blind_index(&provider, b"alice@example.com", &context).unwrap();
        let index2 = generate_blind_index(&provider, b"bob@example.com", &context).unwrap();

        assert_ne!(index1, index2);
    }

    #[test]
    fn test_blind_index_different_contexts() {
        let provider = MockKeyProvider::with_pepper(vec![42u8; 32]);
        let value = b"alice@example.com";

        let context1 = IndexContext::new("users", "email");
        let context2 = IndexContext::new("users", "phone");

        let index1 = generate_blind_index(&provider, value, &context1).unwrap();
        let index2 = generate_blind_index(&provider, value, &context2).unwrap();

        assert_ne!(index1, index2);
    }

    #[test]
    fn test_blind_index_different_tenants() {
        let provider = MockKeyProvider::with_pepper(vec![42u8; 32]);
        let value = b"alice@example.com";

        let context1 = IndexContext::new("users", "email").with_tenant("tenant_1");
        let context2 = IndexContext::new("users", "email").with_tenant("tenant_2");

        let index1 = generate_blind_index(&provider, value, &context1).unwrap();
        let index2 = generate_blind_index(&provider, value, &context2).unwrap();

        assert_ne!(index1, index2);
    }

    #[test]
    fn test_blind_index_no_pepper() {
        let provider = MockKeyProvider::without_pepper();
        let context = IndexContext::new("users", "email");
        let value = b"alice@example.com";

        let result = generate_blind_index(&provider, value, &context);
        assert!(matches!(result, Err(Error::IndexGenerationFailed(_))));
    }

    #[test]
    fn test_blind_index_output_size() {
        let provider = MockKeyProvider::with_pepper(vec![42u8; 32]);
        let context = IndexContext::new("users", "email");

        let index = generate_blind_index(&provider, b"test", &context).unwrap();
        assert_eq!(index.len(), BLIND_INDEX_SIZE);
    }

    #[test]
    fn test_deterministic_index_wrapper() {
        let provider = MockKeyProvider::with_pepper(vec![42u8; 32]);
        let context = IndexContext::new("users", "email");
        let value = b"alice@example.com";

        let index1 = generate_deterministic_index(&provider, value, &context).unwrap();
        let index2 = generate_deterministic_index(&provider, value, &context).unwrap();

        assert_eq!(index1, index2);
    }

    #[test]
    fn test_blind_index_empty_value() {
        let provider = MockKeyProvider::with_pepper(vec![42u8; 32]);
        let context = IndexContext::new("users", "email");

        let index = generate_blind_index(&provider, b"", &context).unwrap();
        assert_eq!(index.len(), BLIND_INDEX_SIZE);
    }

    #[test]
    fn test_blind_index_large_value() {
        let provider = MockKeyProvider::with_pepper(vec![42u8; 32]);
        let context = IndexContext::new("users", "data");
        let large_value = vec![7u8; 10000];

        let index = generate_blind_index(&provider, &large_value, &context).unwrap();
        assert_eq!(index.len(), BLIND_INDEX_SIZE);
    }
}
