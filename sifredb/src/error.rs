//! Error types for `SifreDB` operations.

use std::fmt;

/// Main error type for `SifreDB` operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Encryption operation failed
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Authentication tag verification failed (data may be corrupted or tampered)
    #[error("authentication failed: ciphertext may be corrupted or tampered")]
    AuthenticationFailed,

    /// Key provider operation failed
    #[error("key provider error: {0}")]
    KeyProvider(#[from] KeyProviderError),

    /// Encryption header parsing failed
    #[error("invalid header: {0}")]
    InvalidHeader(String),

    /// Key derivation failed
    #[error("key derivation failed")]
    KeyDerivation,

    /// Unsupported protocol version
    #[error("unsupported version: {version} (supported: {supported})")]
    UnsupportedVersion {
        /// The version found in the ciphertext
        version: u8,
        /// Supported versions
        supported: String,
    },

    /// Blind index generation failed
    #[error("blind index generation failed: {0}")]
    IndexGenerationFailed(String),

    /// I/O operation failed
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors specific to key provider operations.
#[derive(Debug)]
pub enum KeyProviderError {
    /// KEK not found
    KekNotFound(String),

    /// KEK creation failed
    CreationFailed(String),

    /// No active KEK configured
    NoActiveKek,

    /// DEK wrapping failed
    WrapFailed(String),

    /// DEK unwrapping failed
    UnwrapFailed(String),

    /// Pepper not available
    PepperUnavailable(String),

    /// I/O operation failed
    Io(std::io::Error),
}

impl fmt::Display for KeyProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KekNotFound(id) => write!(f, "KEK not found: {id}"),
            Self::CreationFailed(msg) => write!(f, "KEK creation failed: {msg}"),
            Self::NoActiveKek => write!(f, "no active KEK configured"),
            Self::WrapFailed(msg) => write!(f, "DEK wrap failed: {msg}"),
            Self::UnwrapFailed(msg) => write!(f, "DEK unwrap failed: {msg}"),
            Self::PepperUnavailable(msg) => write!(f, "pepper not available: {msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for KeyProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for KeyProviderError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}
