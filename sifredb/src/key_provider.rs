//! Key provider abstraction for key management.

use crate::error::KeyProviderError;
use secrecy::SecretVec;

/// Provides key management operations for encryption/decryption.
///
/// Implementations must be thread-safe (`Send + Sync`) to support
/// concurrent encryption operations.
///
/// # Example
///
/// ```rust,ignore
/// use sifredb::key_provider::KeyProvider;
///
/// struct MyProvider;
///
/// impl KeyProvider for MyProvider {
///     fn create_kek(&self) -> Result<String, KeyProviderError> {
///         // Implementation
///     }
///     // ... other methods
/// }
/// ```
pub trait KeyProvider: Send + Sync {
    /// Creates a new Key Encryption Key (KEK) and returns its identifier.
    ///
    /// # Errors
    ///
    /// Returns `KeyProviderError::CreationFailed` if KEK creation fails.
    fn create_kek(&self) -> Result<String, KeyProviderError>;

    /// Returns the identifier of the current (active) KEK.
    ///
    /// # Errors
    ///
    /// Returns `KeyProviderError::NoActiveKek` if no KEK is configured.
    fn current_kek_id(&self) -> Result<String, KeyProviderError>;

    /// Wraps (encrypts) a Data Encryption Key (DEK) with the specified KEK.
    ///
    /// # Arguments
    ///
    /// * `kek_id` - Identifier of the KEK to use for wrapping
    /// * `dek` - The plaintext DEK to wrap (typically 32 bytes)
    ///
    /// # Errors
    ///
    /// Returns `KeyProviderError::WrapFailed` if wrapping fails.
    fn wrap_dek(&self, kek_id: &str, dek: &[u8]) -> Result<Vec<u8>, KeyProviderError>;

    /// Unwraps (decrypts) a Data Encryption Key (DEK) using the specified KEK.
    ///
    /// # Arguments
    ///
    /// * `kek_id` - Identifier of the KEK used for wrapping
    /// * `wrapped_dek` - The encrypted DEK to unwrap
    ///
    /// # Returns
    ///
    /// Returns the plaintext DEK in a `SecretVec` for memory safety.
    ///
    /// # Errors
    ///
    /// Returns `KeyProviderError::UnwrapFailed` if unwrapping fails.
    fn unwrap_dek(
        &self,
        kek_id: &str,
        wrapped_dek: &[u8],
    ) -> Result<SecretVec<u8>, KeyProviderError>;

    /// Returns the pepper value for blind index generation.
    ///
    /// # Returns
    ///
    /// Returns `None` if the provider doesn't support blind indexes.
    ///
    /// # Errors
    ///
    /// Returns `KeyProviderError::PepperUnavailable` if pepper retrieval fails.
    fn get_pepper(&self) -> Result<Option<SecretVec<u8>>, KeyProviderError> {
        Ok(None)
    }
}
