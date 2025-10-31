//! File-based key provider for `SifreDB`.
//!
//! This provider stores keys in the filesystem and is suitable for
//! development and testing environments.
//!
//! # Security Warning
//!
//! This provider is NOT recommended for production use. Keys are stored
//! in plaintext on disk. For production, use a KMS provider (AWS KMS, GCP KMS, etc.).

#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretVec};
use sifredb::error::KeyProviderError;
use sifredb::key_provider::KeyProvider;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const KEK_SIZE: usize = 32; // 256 bits
const PEPPER_SIZE: usize = 32; // 256 bits
const NONCE_SIZE: usize = 12; // 96 bits for ChaCha20-Poly1305

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
///
/// # Example
///
/// ```no_run
/// use sifredb_key_file::FileKeyProvider;
/// use sifredb::key_provider::KeyProvider;
///
/// // Initialize a new key directory
/// FileKeyProvider::init("./keys").expect("Failed to initialize keys");
///
/// // Load the provider
/// let provider = FileKeyProvider::new("./keys").expect("Failed to load provider");
///
/// // Use the provider
/// let kek_id = provider.current_kek_id().expect("No active KEK");
/// ```
pub struct FileKeyProvider {
    key_dir: PathBuf,
}

impl FileKeyProvider {
    /// Creates a new `FileKeyProvider` from an existing key directory.
    ///
    /// # Arguments
    ///
    /// * `key_dir` - Directory containing key files
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Directory doesn't exist
    /// - No current KEK symlink exists
    /// - File permissions are incorrect (Unix only)
    pub fn new(key_dir: impl Into<PathBuf>) -> Result<Self, KeyProviderError> {
        let key_dir = key_dir.into();

        if !key_dir.exists() {
            return Err(KeyProviderError::CreationFailed(format!(
                "Key directory does not exist: {}",
                key_dir.display()
            )));
        }

        let current_link = key_dir.join("current");
        if !current_link.exists() {
            return Err(KeyProviderError::NoActiveKek);
        }

        let provider = Self { key_dir };

        // Verify file permissions on Unix
        #[cfg(unix)]
        provider.check_permissions()?;

        Ok(provider)
    }

    /// Initializes a new key directory with a fresh KEK and pepper.
    ///
    /// This creates:
    /// - A new KEK (`kek_v1.key`)
    /// - A symlink pointing to the current KEK
    /// - A pepper for blind indexes
    ///
    /// # Errors
    ///
    /// Returns error if directory creation or key generation fails.
    pub fn init(key_dir: impl Into<PathBuf>) -> Result<(), KeyProviderError> {
        let key_dir = key_dir.into();

        // Create directory if it doesn't exist
        fs::create_dir_all(&key_dir)?;

        // Generate first KEK
        let kek_id = "kek_v1";
        let kek_path = key_dir.join(format!("{kek_id}.key"));
        let kek = generate_random_key(KEK_SIZE);
        write_key_file(&kek_path, &kek)?;

        // Create symlink to current KEK
        let current_link = key_dir.join("current");
        create_symlink(&kek_path, &current_link)?;

        // Generate pepper
        let pepper_path = key_dir.join("pepper.key");
        let pepper = generate_random_key(PEPPER_SIZE);
        write_key_file(&pepper_path, &pepper)?;

        Ok(())
    }

    /// Checks file permissions on Unix systems.
    #[cfg(unix)]
    fn check_permissions(&self) -> Result<(), KeyProviderError> {
        use std::os::unix::fs::PermissionsExt;

        let entries = fs::read_dir(&self.key_dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            // Skip symlinks and directories
            if path.is_symlink() || path.is_dir() {
                continue;
            }

            let metadata = fs::metadata(&path)?;
            let permissions = metadata.permissions();
            let mode = permissions.mode() & 0o777;

            if mode != 0o600 {
                return Err(KeyProviderError::CreationFailed(format!(
                    "Insecure file permissions on {}: {:o} (expected 0600)",
                    path.display(),
                    mode
                )));
            }
        }

        Ok(())
    }

    /// Reads a KEK from disk.
    fn read_kek(&self, kek_id: &str) -> Result<SecretVec<u8>, KeyProviderError> {
        let kek_path = self.key_dir.join(format!("{kek_id}.key"));

        if !kek_path.exists() {
            return Err(KeyProviderError::KekNotFound(kek_id.to_string()));
        }

        let mut file = File::open(&kek_path)?;
        let mut kek = vec![0u8; KEK_SIZE];
        file.read_exact(&mut kek)?;

        Ok(SecretVec::new(kek))
    }

    /// Resolves the current KEK symlink to get the KEK ID.
    fn resolve_current_kek(&self) -> Result<String, KeyProviderError> {
        let current_link = self.key_dir.join("current");

        if !current_link.exists() {
            return Err(KeyProviderError::NoActiveKek);
        }

        let target = fs::read_link(&current_link)?;
        let filename = target.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            KeyProviderError::CreationFailed("Invalid current KEK symlink".to_string())
        })?;

        // Extract kek_id from "kek_v1.key" -> "kek_v1"
        let kek_id = filename.strip_suffix(".key").ok_or_else(|| {
            KeyProviderError::CreationFailed("Invalid KEK filename format".to_string())
        })?;

        Ok(kek_id.to_string())
    }

    /// Finds the next KEK version number.
    fn next_kek_version(&self) -> Result<u32, KeyProviderError> {
        let entries = fs::read_dir(&self.key_dir)?;
        let mut max_version = 0u32;

        for entry in entries {
            let entry = entry?;
            let filename = entry.file_name();
            let filename_str = filename.to_string_lossy();

            // Parse "kek_v1.key" -> 1
            if let Some(version_str) =
                filename_str.strip_prefix("kek_v").and_then(|s| s.strip_suffix(".key"))
            {
                if let Ok(version) = version_str.parse::<u32>() {
                    max_version = max_version.max(version);
                }
            }
        }

        Ok(max_version + 1)
    }
}

impl KeyProvider for FileKeyProvider {
    fn create_kek(&self) -> Result<String, KeyProviderError> {
        let version = self.next_kek_version()?;
        let kek_id = format!("kek_v{version}");
        let kek_path = self.key_dir.join(format!("{kek_id}.key"));

        // Generate new KEK
        let kek = generate_random_key(KEK_SIZE);
        write_key_file(&kek_path, &kek)?;

        // Update current symlink
        let current_link = self.key_dir.join("current");
        if current_link.exists() {
            fs::remove_file(&current_link)?;
        }
        create_symlink(&kek_path, &current_link)?;

        Ok(kek_id)
    }

    fn current_kek_id(&self) -> Result<String, KeyProviderError> {
        self.resolve_current_kek()
    }

    fn wrap_dek(&self, kek_id: &str, dek: &[u8]) -> Result<Vec<u8>, KeyProviderError> {
        let kek = self.read_kek(kek_id)?;

        // Use ChaCha20-Poly1305 to wrap the DEK
        let cipher = ChaCha20Poly1305::new_from_slice(kek.expose_secret())
            .map_err(|e| KeyProviderError::WrapFailed(format!("Invalid KEK: {e}")))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Encrypt DEK
        let ciphertext = cipher
            .encrypt(&nonce, dek)
            .map_err(|e| KeyProviderError::WrapFailed(format!("Encryption failed: {e}")))?;

        // Return nonce || ciphertext
        let mut wrapped = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        wrapped.extend_from_slice(&nonce_bytes);
        wrapped.extend_from_slice(&ciphertext);

        Ok(wrapped)
    }

    fn unwrap_dek(
        &self,
        kek_id: &str,
        wrapped_dek: &[u8],
    ) -> Result<SecretVec<u8>, KeyProviderError> {
        if wrapped_dek.len() < NONCE_SIZE {
            return Err(KeyProviderError::UnwrapFailed("Wrapped DEK too short".to_string()));
        }

        let kek = self.read_kek(kek_id)?;

        // Use ChaCha20-Poly1305 to unwrap the DEK
        let cipher = ChaCha20Poly1305::new_from_slice(kek.expose_secret())
            .map_err(|e| KeyProviderError::UnwrapFailed(format!("Invalid KEK: {e}")))?;

        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = wrapped_dek.split_at(NONCE_SIZE);
        let nonce_array: [u8; NONCE_SIZE] = nonce_bytes
            .try_into()
            .map_err(|_| KeyProviderError::UnwrapFailed("Invalid nonce size".to_string()))?;
        let nonce = Nonce::from(nonce_array);

        // Decrypt DEK
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| KeyProviderError::UnwrapFailed(format!("Decryption failed: {e}")))?;

        Ok(SecretVec::new(plaintext))
    }

    fn get_pepper(&self) -> Result<Option<SecretVec<u8>>, KeyProviderError> {
        let pepper_path = self.key_dir.join("pepper.key");

        if !pepper_path.exists() {
            return Ok(None);
        }

        let mut file = File::open(&pepper_path)?;
        let mut pepper = vec![0u8; PEPPER_SIZE];
        file.read_exact(&mut pepper)?;

        Ok(Some(SecretVec::new(pepper)))
    }
}

/// Generates a random key of the specified size.
fn generate_random_key(size: usize) -> Vec<u8> {
    let mut key = vec![0u8; size];
    OsRng.fill_bytes(&mut key);
    key
}

/// Writes a key to a file with secure permissions.
fn write_key_file(path: &Path, key: &[u8]) -> Result<(), KeyProviderError> {
    let mut file = File::create(path)?;
    file.write_all(key)?;

    // Set permissions to 0600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }

    Ok(())
}

/// Creates a symlink (cross-platform).
fn create_symlink(target: &Path, link: &Path) -> Result<(), KeyProviderError> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)?;
    }

    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link)?;
    }

    Ok(())
}
