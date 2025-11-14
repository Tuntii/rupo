# SifreDB

[![Crates.io](https://img.shields.io/crates/v/sifredb.svg)](https://crates.io/crates/sifredb)
[![Documentation](https://docs.rs/sifredb/badge.svg)](https://docs.rs/sifredb)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](https://github.com/Tuntii/sifredb)

A Rust library for field-level encryption with envelope encryption and blind indexes.

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

// Create encryption context
let context = EncryptionContext::new("users", "email")
    .with_tenant("tenant_123");

// Use deterministic vault for encryption
let key = b"32-byte-key-here-must-be-32-byte";
let vault = DeterministicVault::new(key);

// Encrypt
let plaintext = b"alice@example.com";
let ciphertext = vault.encrypt(plaintext, &context)?;

// Decrypt
let decrypted = vault.decrypt(&ciphertext, &context)?;
assert_eq!(plaintext, &decrypted[..]);
```

## Deterministic Encryption

Deterministic encryption produces the same ciphertext for the same plaintext, enabling equality queries:

```rust
use sifredb::prelude::*;

let vault = DeterministicVault::new(key);
let context = EncryptionContext::new("users", "ssn");

let cipher1 = vault.encrypt(b"123-45-6789", &context)?;
let cipher2 = vault.encrypt(b"123-45-6789", &context)?;

// Same plaintext = same ciphertext (enables database equality queries)
assert_eq!(cipher1, cipher2);
```

## Encryption Context

The encryption context binds encrypted data to specific use cases:

```rust
use sifredb::prelude::*;

let context = EncryptionContext::new("users", "email")
    .with_tenant("tenant_abc")     // Multi-tenant isolation
    .with_version(1);               // Key version for rotation

// Context is cryptographically bound to the ciphertext
// Decryption with wrong context will fail
```

## Multi-tenant Isolation

Different tenants use different encryption keys automatically:

```rust
use sifredb::prelude::*;

let vault = DeterministicVault::new(key);

// Tenant A
let context_a = EncryptionContext::new("users", "email")
    .with_tenant("tenant_a");
let cipher_a = vault.encrypt(b"alice@tenant-a.com", &context_a)?;

// Tenant B (different encryption due to different context)
let context_b = EncryptionContext::new("users", "email")
    .with_tenant("tenant_b");
let cipher_b = vault.encrypt(b"alice@tenant-b.com", &context_b)?;

// Ciphertexts are different even if email addresses were the same
```

## Security Considerations

- **Context Binding**: Always use appropriate encryption contexts
- **Key Management**: Use secure key derivation and storage
- **Memory Safety**: Sensitive data is automatically zeroed on drop
- **Deterministic Mode**: Only use for data that needs equality queries
- **Key Rotation**: Implement regular key rotation policies

## Architecture

SifreDB uses AES-SIV (Synthetic IV) for deterministic encryption:

- **Context Binding**: Encryption context is cryptographically mixed with plaintext
- **Authentication**: Built-in authentication prevents tampering
- **Deterministic**: Same input always produces same output
- **Misuse Resistant**: Safe even with key reuse

For probabilistic encryption, combine with external key providers for full envelope encryption.

## Related Crates

- **[sifredb-key-file](https://crates.io/crates/sifredb-key-file)**: File-based key provider
- **[sifredb-kms-aws](https://crates.io/crates/sifredb-kms-aws)**: AWS KMS integration
- **[sifredb-derive](https://crates.io/crates/sifredb-derive)**: Derive macros
- **[sifredb-cli](https://crates.io/crates/sifredb-cli)**: Command-line tool

## Examples

See the repository for more examples:
- Deterministic encryption
- Multi-tenant isolation
- Key rotation patterns

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
