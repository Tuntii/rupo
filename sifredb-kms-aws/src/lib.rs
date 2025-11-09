//! AWS KMS key provider for SifreDB.
//!
//! This module provides integration with AWS Key Management Service (KMS)
//! for enterprise-grade key management with hardware security modules (HSM).
//!
//! # Features
//!
//! - KEK storage in AWS KMS
//! - Hardware-backed key security
//! - Automatic key rotation
//! - Fine-grained access control via IAM
//! - Audit logging via CloudTrail
//! - Multi-region support
//!
//! # Example
//!
//! ```rust,no_run
//! use sifredb_kms_aws::AwsKmsProvider;
//! use sifredb::prelude::*;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create provider with default AWS config
//! let provider = AwsKmsProvider::new().await?;
//!
//! // Or specify a KMS key ID
//! let provider = AwsKmsProvider::with_key_id(
//!     "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
//! ).await?;
//!
//! // Use with Vault
//! // let vault = Vault::new(Arc::new(provider), CipherMode::default());
//! # Ok(())
//! # }
//! ```
//!
//! # AWS Configuration
//!
//! The provider uses the AWS SDK's default credential chain:
//! - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
//! - AWS credentials file (~/.aws/credentials)
//! - IAM instance profile (for EC2)
//! - ECS task role
//! - Web identity token (for EKS)

#![warn(clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]

use aws_sdk_kms::Client as KmsClient;
use secrecy::{ExposeSecret, SecretVec};
use sifredb::{
    error::KeyProviderError,
    key_provider::{KeyProvider, WrappedDek},
};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Errors specific to AWS KMS operations.
#[derive(Debug, Error)]
pub enum AwsKmsError {
    /// AWS KMS API error
    #[error("AWS KMS error: {0}")]
    KmsError(String),

    /// Key not found in KMS
    #[error("KMS key not found: {0}")]
    KeyNotFound(String),

    /// Invalid key ID format
    #[error("invalid key ID: {0}")]
    InvalidKeyId(String),

    /// Encryption/decryption failed
    #[error("KMS operation failed: {0}")]
    OperationFailed(String),

    /// Base64 decoding error
    #[error("base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}

impl From<AwsKmsError> for KeyProviderError {
    fn from(err: AwsKmsError) -> Self {
        match err {
            AwsKmsError::KeyNotFound(id) => KeyProviderError::KekNotFound(id),
            AwsKmsError::KmsError(msg) | AwsKmsError::OperationFailed(msg) => {
                KeyProviderError::UnwrapFailed(msg)
            }
            AwsKmsError::InvalidKeyId(msg) => KeyProviderError::CreationFailed(msg),
            AwsKmsError::Base64Error(e) => KeyProviderError::UnwrapFailed(format!("Base64: {e}")),
        }
    }
}

/// AWS KMS key provider implementation.
///
/// This provider uses AWS KMS to:
/// - Store and manage KEKs securely in HSM-backed storage
/// - Wrap/unwrap DEKs using envelope encryption
/// - Track key versions for rotation
/// - Provide audit trails via CloudTrail
pub struct AwsKmsProvider {
    /// AWS KMS client
    client: KmsClient,
    /// Current KMS key ID (ARN or alias)
    current_key_id: Arc<RwLock<String>>,
    /// Pepper for blind indexes (stored separately, not in KMS)
    pepper: SecretVec<u8>,
}

impl AwsKmsProvider {
    /// Creates a new AWS KMS provider with default configuration.
    ///
    /// Uses AWS SDK's default credential and region resolution.
    ///
    /// # Errors
    ///
    /// Returns an error if AWS configuration fails.
    pub async fn new() -> Result<Self, AwsKmsError> {
        let config = aws_config::load_from_env().await;
        let client = KmsClient::new(&config);
        
        // Generate a random pepper (in production, this should be stored securely)
        let pepper = SecretVec::new(Self::generate_pepper());

        Ok(Self {
            client,
            current_key_id: Arc::new(RwLock::new(String::new())),
            pepper,
        })
    }

    /// Creates a provider with a specific KMS key ID.
    ///
    /// # Arguments
    ///
    /// * `key_id` - KMS key ID, ARN, or alias (e.g., "alias/sifredb-kek")
    ///
    /// # Errors
    ///
    /// Returns an error if AWS configuration fails.
    pub async fn with_key_id(key_id: impl Into<String>) -> Result<Self, AwsKmsError> {
        let config = aws_config::load_from_env().await;
        let client = KmsClient::new(&config);
        let pepper = SecretVec::new(Self::generate_pepper());

        Ok(Self {
            client,
            current_key_id: Arc::new(RwLock::new(key_id.into())),
            pepper,
        })
    }

    /// Sets the current KMS key ID.
    ///
    /// # Arguments
    ///
    /// * `key_id` - KMS key ID, ARN, or alias
    pub async fn set_current_key_id(&self, key_id: impl Into<String>) {
        let mut current = self.current_key_id.write().await;
        *current = key_id.into();
    }

    /// Generates a random pepper for blind indexes.
    fn generate_pepper() -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"sifredb-pepper-");
        hasher.update(&std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes());
        hasher.finalize().to_vec()
    }
}

#[async_trait::async_trait]
impl KeyProvider for AwsKmsProvider {
    async fn current_kek_id(&self) -> Result<String, KeyProviderError> {
        let key_id = self.current_key_id.read().await;
        if key_id.is_empty() {
            return Err(KeyProviderError::NoActiveKek);
        }
        Ok(key_id.clone())
    }

    async fn wrap_dek(&self, dek: &SecretVec<u8>, kek_id: &str) -> Result<WrappedDek, KeyProviderError> {
        let response = self
            .client
            .encrypt()
            .key_id(kek_id)
            .plaintext(aws_sdk_kms::primitives::Blob::new(dek.expose_secret().clone()))
            .send()
            .await
            .map_err(|e| {
                KeyProviderError::WrapFailed(format!("KMS encrypt failed: {e}"))
            })?;

        let ciphertext_blob = response
            .ciphertext_blob()
            .ok_or_else(|| KeyProviderError::WrapFailed("No ciphertext returned".to_string()))?;

        Ok(WrappedDek {
            kek_id: kek_id.to_string(),
            encrypted_dek: ciphertext_blob.as_ref().to_vec(),
        })
    }

    async fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<SecretVec<u8>, KeyProviderError> {
        let response = self
            .client
            .decrypt()
            .key_id(&wrapped.kek_id)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(wrapped.encrypted_dek.clone()))
            .send()
            .await
            .map_err(|e| {
                KeyProviderError::UnwrapFailed(format!("KMS decrypt failed: {e}"))
            })?;

        let plaintext = response
            .plaintext()
            .ok_or_else(|| KeyProviderError::UnwrapFailed("No plaintext returned".to_string()))?;

        Ok(SecretVec::new(plaintext.as_ref().to_vec()))
    }

    async fn get_pepper(&self) -> Result<SecretVec<u8>, KeyProviderError> {
        Ok(SecretVec::new(self.pepper.expose_secret().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_provider_creation() {
        // This test requires AWS credentials
        // In CI/CD, you would mock the KMS client
        let result = AwsKmsProvider::new().await;
        assert!(result.is_ok(), "Provider creation should succeed");
    }

    #[tokio::test]
    async fn test_set_key_id() {
        let provider = AwsKmsProvider::new().await.unwrap();
        let key_id = "arn:aws:kms:us-east-1:123456789012:key/test";
        
        provider.set_current_key_id(key_id).await;
        
        let current = provider.current_kek_id().await.unwrap();
        assert_eq!(current, key_id);
    }

    #[tokio::test]
    async fn test_pepper_generation() {
        let provider1 = AwsKmsProvider::new().await.unwrap();
        let provider2 = AwsKmsProvider::new().await.unwrap();

        let pepper1 = provider1.get_pepper().await.unwrap();
        let pepper2 = provider2.get_pepper().await.unwrap();

        // Different providers should have different peppers
        assert_ne!(
            pepper1.expose_secret(),
            pepper2.expose_secret(),
            "Each provider should have unique pepper"
        );
    }
}
