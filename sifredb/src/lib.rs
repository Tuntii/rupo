//! # `SifreDB`
//!
//! Field-level encryption library with envelope encryption, blind indexes,
//! and support for multiple key management backends.
//!
//! ## Features
//!
//! - AEAD encryption (ChaCha20-Poly1305, AES-GCM)
//! - Deterministic encryption (AES-SIV) for equality queries
//! - Blind indexes for searchable encryption
//! - Envelope encryption with KEK/DEK separation
//! - Multi-tenant key isolation
//! - Key rotation support
//!
//! ## Example
//!
//! ```rust,ignore
//! use sifredb::prelude::*;
//!
//! let provider = FileKeyProvider::new("./keys")?;
//! let vault = Vault::new(provider, CipherMode::default());
//! let context = EncryptionContext::new("users", "email");
//!
//! let ciphertext = vault.encrypt(b"alice@example.com", &context)?;
//! let plaintext = vault.decrypt(&ciphertext, &context)?;
//! ```

#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

pub mod context;
pub mod error;
pub mod key_provider;
pub mod deterministic;

pub mod prelude {
    //! Convenience re-exports for common use.
    pub use crate::context::{EncryptionContext, IndexContext};
    pub use crate::deterministic::DeterministicVault;
    pub use crate::error::{Error, KeyProviderError};
    pub use crate::key_provider::KeyProvider;
}
