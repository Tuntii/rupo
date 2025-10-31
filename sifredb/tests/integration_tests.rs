//! Integration tests for sifredb with FileKeyProvider.

use sifredb::blind_index::generate_blind_index;
use sifredb::context::{EncryptionContext, IndexContext};
use sifredb::key_provider::KeyProvider;
use sifredb::vault::{CipherMode, Vault};
use sifredb_key_file::FileKeyProvider;
use tempfile::TempDir;

#[test]
fn test_end_to_end_encryption_with_file_provider() {
    // Create a temporary directory for keys
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_dir = temp_dir.path();

    // Initialize the key directory
    FileKeyProvider::init(key_dir).expect("Failed to initialize keys");

    // Create the provider
    let provider = FileKeyProvider::new(key_dir).expect("Failed to create provider");

    // Create a vault
    let vault = Vault::new(provider, CipherMode::default());

    // Define encryption context
    let context = EncryptionContext::new("users", "email");

    // Test data
    let plaintext = b"alice@example.com";

    // Encrypt
    let ciphertext = vault.encrypt(plaintext, &context).expect("Encryption failed");

    // Decrypt
    let decrypted = vault.decrypt(&ciphertext, &context).expect("Decryption failed");

    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_blind_index_with_file_provider() {
    // Create a temporary directory for keys
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_dir = temp_dir.path();

    // Initialize the key directory
    FileKeyProvider::init(key_dir).expect("Failed to initialize keys");

    // Create the provider
    let provider = FileKeyProvider::new(key_dir).expect("Failed to create provider");

    // Define index context
    let context = IndexContext::new("users", "email");

    // Test data
    let value = b"alice@example.com";

    // Generate blind index
    let index1 = generate_blind_index(&provider, value, &context).expect("Index generation failed");
    let index2 = generate_blind_index(&provider, value, &context).expect("Index generation failed");

    // Same value should produce same index
    assert_eq!(index1, index2);

    // Different value should produce different index
    let index3 = generate_blind_index(&provider, b"bob@example.com", &context)
        .expect("Index generation failed");
    assert_ne!(index1, index3);
}

#[test]
fn test_multi_tenant_isolation() {
    // Create a temporary directory for keys
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_dir = temp_dir.path();

    // Initialize the key directory
    FileKeyProvider::init(key_dir).expect("Failed to initialize keys");

    // Create the provider
    let provider = FileKeyProvider::new(key_dir).expect("Failed to create provider");

    // Create a vault
    let vault = Vault::new(provider, CipherMode::default());

    // Same value, different tenants
    let plaintext = b"secret_data";
    let context1 = EncryptionContext::new("users", "data").with_tenant("tenant_1");
    let context2 = EncryptionContext::new("users", "data").with_tenant("tenant_2");

    // Encrypt with different tenants
    let ciphertext1 = vault.encrypt(plaintext, &context1).expect("Encryption failed");
    let ciphertext2 = vault.encrypt(plaintext, &context2).expect("Encryption failed");

    // Ciphertexts should be different
    assert_ne!(ciphertext1, ciphertext2);

    // Decrypt with correct contexts
    let decrypted1 = vault.decrypt(&ciphertext1, &context1).expect("Decryption failed");
    let decrypted2 = vault.decrypt(&ciphertext2, &context2).expect("Decryption failed");

    assert_eq!(plaintext, &decrypted1[..]);
    assert_eq!(plaintext, &decrypted2[..]);

    // Decrypt with wrong tenant should fail
    let result = vault.decrypt(&ciphertext1, &context2);
    assert!(result.is_err());
}

#[test]
fn test_key_rotation() {
    // Create a temporary directory for keys
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_dir = temp_dir.path();

    // Initialize the key directory
    FileKeyProvider::init(key_dir).expect("Failed to initialize keys");

    // Create the provider
    let provider = FileKeyProvider::new(key_dir).expect("Failed to create provider");

    // Create a vault
    let vault = Vault::new(provider, CipherMode::default());

    // Define encryption context
    let context = EncryptionContext::new("users", "email");

    // Test data
    let plaintext = b"alice@example.com";

    // Encrypt with KEK v1
    let ciphertext1 = vault.encrypt(plaintext, &context).expect("Encryption failed");

    // Get the provider to rotate keys
    let provider2 = FileKeyProvider::new(key_dir).expect("Failed to create provider");

    // Create a new KEK (this simulates key rotation)
    let new_kek_id = provider2.create_kek().expect("Failed to create new KEK");
    assert_eq!(new_kek_id, "kek_v2");

    // Create a new vault with the rotated provider
    let vault2 = Vault::new(provider2, CipherMode::default());

    // New encryptions should use the new KEK
    let ciphertext2 = vault2.encrypt(plaintext, &context).expect("Encryption failed");

    // Both ciphertexts should decrypt correctly
    let decrypted1 = vault2.decrypt(&ciphertext1, &context).expect("Decryption failed");
    let decrypted2 = vault2.decrypt(&ciphertext2, &context).expect("Decryption failed");

    assert_eq!(plaintext, &decrypted1[..]);
    assert_eq!(plaintext, &decrypted2[..]);
}

#[test]
fn test_context_as_aad() {
    // Create a temporary directory for keys
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let key_dir = temp_dir.path();

    // Initialize the key directory
    FileKeyProvider::init(key_dir).expect("Failed to initialize keys");

    // Create the provider
    let provider = FileKeyProvider::new(key_dir).expect("Failed to create provider");

    // Create a vault
    let vault = Vault::new(provider, CipherMode::default());

    // Define encryption contexts
    let context1 = EncryptionContext::new("users", "email");
    let context2 = EncryptionContext::new("users", "phone");

    // Test data
    let plaintext = b"sensitive_data";

    // Encrypt with context1
    let ciphertext = vault.encrypt(plaintext, &context1).expect("Encryption failed");

    // Try to decrypt with context2 (should fail because context is used as AAD)
    let result = vault.decrypt(&ciphertext, &context2);
    assert!(result.is_err());

    // Decrypt with correct context should succeed
    let decrypted = vault.decrypt(&ciphertext, &context1).expect("Decryption failed");
    assert_eq!(plaintext, &decrypted[..]);
}
