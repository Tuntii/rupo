# SifreDB

A Rust library for field-level encryption with envelope encryption and blind indexes.

[![Crates.io](https://img.shields.io/crates/v/sifredb.svg)](https://crates.io/crates/sifredb)
[![Documentation](https://docs.rs/sifredb/badge.svg)](https://docs.rs/sifredb)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](https://github.com/tunayengin/sifredb)

## Features

- 🔐 **AEAD Encryption**: ChaCha20-Poly1305 and AES-GCM support
- 🔍 **Blind Indexes**: Searchable encryption without revealing plaintext
- 🔑 **Envelope Encryption**: KEK/DEK separation for key management
- 🔄 **Key Rotation**: Built-in support for rotating encryption keys
- 🏢 **Multi-tenant Isolation**: Secure data isolation per tenant
- 🛡️ **Deterministic Encryption**: Enables equality queries on encrypted data
- 🚀 **Zero-copy Operations**: Efficient memory usage
- 🔒 **Memory Safety**: Automatic zeroing of sensitive data

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
sifredb = "0.1"
```

## Quick Start

```rust
use sifredb::prelude::*;

// Create a key provider
let provider = FileKeyProvider::new("./keys")?;
let vault = Vault::new(provider, CipherMode::default());

// Define encryption context
let context = EncryptionContext::new("users", "email")
    .with_tenant("tenant_123");

// Encrypt
let ciphertext = vault.encrypt(b"alice@example.com", &context)?;

// Decrypt
let plaintext = vault.decrypt(&ciphertext, &context)?;
```

## Advanced Usage

### Blind Indexes for Searchable Encryption

```rust
use sifredb::prelude::*;

let vault = Vault::new(provider, CipherMode::default());
let context = EncryptionContext::new("users", "email");

// Create blind index for searching
let email = b"alice@example.com";
let ciphertext = vault.encrypt(email, &context)?;
let blind_index = vault.create_blind_index(email, &context)?;

// Store both ciphertext and blind_index in your database
// Later, search using the blind index without decrypting
let search_index = vault.create_blind_index(b"alice@example.com", &context)?;
// Compare: search_index == blind_index
```

### Deterministic Encryption

```rust
use sifredb::prelude::*;

let vault = Vault::new(provider, CipherMode::Deterministic);
let context = EncryptionContext::new("users", "ssn");

// Same input always produces same ciphertext
let ciphertext1 = vault.encrypt(b"123-45-6789", &context)?;
let ciphertext2 = vault.encrypt(b"123-45-6789", &context)?;
assert_eq!(ciphertext1, ciphertext2); // Enables equality queries
```

### Key Rotation

```rust
use sifredb::prelude::*;

// Rotate to a new key version
let new_context = context.with_key_version(2);
let old_ciphertext = vault.encrypt(data, &context)?;

// Decrypt with old key, re-encrypt with new key
let plaintext = vault.decrypt(&old_ciphertext, &context)?;
let new_ciphertext = vault.encrypt(&plaintext, &new_context)?;
```

### Multi-tenant Support

```rust
use sifredb::prelude::*;

// Tenant A
let context_a = EncryptionContext::new("users", "email")
    .with_tenant("tenant_a");
let cipher_a = vault.encrypt(b"alice@tenant-a.com", &context_a)?;

// Tenant B (isolated encryption)
let context_b = EncryptionContext::new("users", "email")
    .with_tenant("tenant_b");
let cipher_b = vault.encrypt(b"bob@tenant-b.com", &context_b)?;
```

## Key Providers

### File-based Provider

```rust
use sifredb_key_file::FileKeyProvider;

let provider = FileKeyProvider::new("./keys")?;
```

### AWS KMS Provider

```rust
use sifredb_kms_aws::AwsKmsProvider;

let provider = AwsKmsProvider::new("arn:aws:kms:...").await?;
```

### Custom Provider

Implement the `KeyProvider` trait for your own key management:

```rust
use sifredb::key_provider::KeyProvider;

struct MyCustomProvider;

impl KeyProvider for MyCustomProvider {
    fn get_kek(&self, context: &EncryptionContext) -> Result<Vec<u8>> {
        // Your key retrieval logic
    }
}
```

## Security Considerations

- **Key Management**: Use a secure key management system (KMS) in production
- **Context Binding**: Always use appropriate encryption contexts
- **Memory Safety**: Sensitive data is automatically zeroed on drop
- **Key Rotation**: Implement regular key rotation policies
- **Audit Logging**: Log all encryption/decryption operations

## Architecture

SifreDB uses envelope encryption:

1. **KEK (Key Encryption Key)**: Master key from KMS
2. **DEK (Data Encryption Key)**: Generated per encryption operation
3. **Encrypted Data**: Payload encrypted with DEK
4. **Encrypted DEK**: DEK encrypted with KEK

This architecture enables:
- Efficient key rotation
- Secure key storage
- Fast decryption operations

## Crates in this Workspace

- **sifredb**: Core encryption library
- **sifredb-derive**: Derive macros for automatic encryption
- **sifredb-cli**: Command-line tool for key management
- **sifredb-key-file**: File-based key provider
- **sifredb-kms-aws**: AWS KMS integration

## Examples

See the [examples](./examples) directory for more use cases:

- [Basic Usage](./examples/basic_usage.rs)
- [Deterministic Encryption](./examples/deterministic_encryption.rs)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Status

🚧 This project is under active development. APIs may change before 1.0 release.

## Acknowledgments

Built with modern Rust cryptography libraries including `chacha20poly1305`, `aes-gcm`, and `hkdf`.

