//! Basic usage example for `SifreDB`.

use sifredb::blind_index::generate_blind_index;
use sifredb::prelude::*;
use sifredb_key_file::FileKeyProvider;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("SifreDB Basic Usage Example");
    println!("============================\n");

    // Setup: Create a temporary directory for keys
    let key_dir = PathBuf::from("./example_keys");

    // Initialize the key directory if it doesn't exist
    if !key_dir.exists() {
        println!("Initializing key directory at {:?}...", key_dir);
        FileKeyProvider::init(&key_dir)?;
        println!("✓ Key directory initialized\n");
    }

    // Create a key provider
    let provider = FileKeyProvider::new(&key_dir)?;
    println!("✓ FileKeyProvider created\n");

    // Create a vault for encryption
    let vault = Vault::new(provider, CipherMode::default());
    println!("✓ Vault created with ChaCha20-Poly1305\n");

    // Define encryption context
    let context =
        EncryptionContext::new("users", "email").with_tenant("tenant_123").with_version(1);

    println!("Encryption Context: {context}");
    println!("  - Tenant: {:?}", context.tenant_id());
    println!("  - Table: {}", context.table_name());
    println!("  - Column: {}", context.column_name());
    println!("  - Version: {}\n", context.version());

    // Example data
    let plaintext = b"alice@example.com";
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));

    // Encrypt the data
    let ciphertext = vault.encrypt(plaintext, &context)?;
    println!("✓ Encrypted ({} bytes)", ciphertext.len());

    // Decrypt the data
    let decrypted = vault.decrypt(&ciphertext, &context)?;
    println!("✓ Decrypted: {}", String::from_utf8_lossy(&decrypted));

    // Verify round-trip
    assert_eq!(plaintext, &decrypted[..]);
    println!("✓ Round-trip verification successful\n");

    // Generate a blind index for searchable encryption
    // Note: In production, you might want to use the same provider or clone it
    let provider_for_index = FileKeyProvider::new(&key_dir)?;
    let index_context = IndexContext::from(&context);
    let blind_index = generate_blind_index(&provider_for_index, plaintext, &index_context)?;

    println!("Blind Index (hex): {}", hex::encode(&blind_index));
    println!("✓ Blind index generated ({} bytes)\n", blind_index.len());

    // Demonstrate deterministic indexing
    let blind_index2 = generate_blind_index(&provider_for_index, plaintext, &index_context)?;
    assert_eq!(blind_index, blind_index2);
    println!("✓ Deterministic indexing verified\n");

    // Show that different values produce different indexes
    let plaintext2 = b"bob@example.com";
    let blind_index3 = generate_blind_index(&provider_for_index, plaintext2, &index_context)?;
    assert_ne!(blind_index, blind_index3);
    println!("✓ Different values produce different indexes\n");

    println!("============================");
    println!("All operations successful! 🎉");

    // Cleanup
    println!("\nNote: Key directory at {:?} can be deleted manually", key_dir);

    Ok(())
}
