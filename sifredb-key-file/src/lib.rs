//! File-based key provider for `SifreDB`.
//!
//! This provider stores keys in the filesystem and is suitable for
//! development and testing environments.

#![warn(clippy::pedantic, clippy::nursery)]

use sifredb::error::KeyProviderError;
use sifredb::key_provider::KeyProvider;
use secrecy::SecretVec;
use std::path::PathBuf;

/// File-based key provider for development and testing.
///
/// Keys are stored in the filesystem with the following structure:
/// ```text
/// keys/
/// ├── kek_v1.key      (32 bytes, 0600 permissions)
/// ├── kek_v2.key      (32 bytes, 0600 permissions)
/// ├── current -> kek_v2.key  (symlink to active KEK)
/// └── pepper.key      (32 bytes, 0600 permissions)
/// ```
pub struct FileKeyProvider {
    key_dir: PathBuf,
}

impl FileKeyProvider {
    /// Creates a new `FileKeyProvider`.
    ///
    /// # Arguments
    ///
    /// * `key_dir` - Directory containing key files
    ///
    /// # Errors
    ///
    /// Returns error if directory doesn't exist or has incorrect permissions.
    pub fn new(key_dir: impl Into<PathBuf>) -> Result<Self, KeyProviderError> {
        let key_dir = key_dir.into();
        if !key_dir.exists() {
            return Err(KeyProviderError::CreationFailed(format!(
                "Key directory does not exist: {}",
                key_dir.display()
            )));
        }
        Ok(Self { key_dir })
    }

    /// Initializes a new key directory with a fresh KEK and pepper.
    ///
    /// # Errors
    ///
    /// Returns error if directory creation or key generation fails.
    pub fn init(_key_dir: impl Into<PathBuf>) -> Result<(), KeyProviderError> {
        // Placeholder implementation
        // Will be implemented in Task 2.2
        Ok(())
    }
}

impl KeyProvider for FileKeyProvider {
    fn create_kek(&self) -> Result<String, KeyProviderError> {
        // Placeholder implementation
        Err(KeyProviderError::CreationFailed(
            "Not yet implemented".to_string(),
        ))
    }

    fn current_kek_id(&self) -> Result<String, KeyProviderError> {
        // Placeholder implementation
        Err(KeyProviderError::NoActiveKek)
    }

    fn wrap_dek(&self, _kek_id: &str, _dek: &[u8]) -> Result<Vec<u8>, KeyProviderError> {
        // Placeholder implementation
        Err(KeyProviderError::WrapFailed(
            "Not yet implemented".to_string(),
        ))
    }

    fn unwrap_dek(
        &self,
        _kek_id: &str,
        _wrapped_dek: &[u8],
    ) -> Result<SecretVec<u8>, KeyProviderError> {
        // Placeholder implementation
        Err(KeyProviderError::UnwrapFailed(
            "Not yet implemented".to_string(),
        ))
    }

    fn get_pepper(&self) -> Result<Option<SecretVec<u8>>, KeyProviderError> {
        // Placeholder implementation
        Ok(None)
    }
}
