# sifredb-key-file

[![Crates.io](https://img.shields.io/crates/v/sifredb-key-file.svg)](https://crates.io/crates/sifredb-key-file)
[![Documentation](https://docs.rs/sifredb-key-file/badge.svg)](https://docs.rs/sifredb-key-file)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](https://github.com/Tuntii/sifredb)

File-based key provider for [SifreDB](https://crates.io/crates/sifredb).

## Features

- 🔐 Secure file-based key storage
- 🔑 Key encryption at rest
- 📁 Hierarchical key organization
- 🔄 Key rotation support
- 🏢 Multi-tenant key isolation

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
sifredb = "0.1"
sifredb-key-file = "0.1"
```

## Usage

### Initialize Key Directory

```rust
use sifredb_key_file::FileKeyProvider;
use std::path::Path;

// Initialize a new key directory
let key_dir = Path::new("./keys");
FileKeyProvider::init(key_dir)?;
```

### Create Provider

```rust
use sifredb_key_file::FileKeyProvider;

let provider = FileKeyProvider::new("./keys")?;
```

### Use with SifreDB Vault

```rust
use sifredb::prelude::*;
use sifredb_key_file::FileKeyProvider;

let provider = FileKeyProvider::new("./keys")?;
let vault = DeterministicVault::with_provider(provider);

let context = EncryptionContext::new("users", "email");
let ciphertext = vault.encrypt(b"alice@example.com", &context)?;
```

## Key Storage Structure

Keys are stored in a hierarchical directory structure:

```
./keys/
├── tenant_a/
│   ├── users_email_v1.key
│   └── orders_total_v1.key
└── tenant_b/
    └── users_email_v1.key
```

## Security Considerations

- **Key Protection**: Keys are encrypted at rest using ChaCha20-Poly1305
- **File Permissions**: Ensure key directory has restricted access (600/700)
- **Backup Strategy**: Implement secure key backup procedures
- **Key Rotation**: Regularly rotate keys and maintain old versions for decryption
- **Production Use**: Consider using a KMS for production environments

## Key Rotation

```rust
use sifredb::prelude::*;
use sifredb_key_file::FileKeyProvider;

let provider = FileKeyProvider::new("./keys")?;

// Old context with version 1
let old_context = EncryptionContext::new("users", "email")
    .with_tenant("tenant_a")
    .with_version(1);

// New context with version 2
let new_context = old_context.clone().with_version(2);

// Decrypt with old key, re-encrypt with new key
let plaintext = vault.decrypt(&old_ciphertext, &old_context)?;
let new_ciphertext = vault.encrypt(&plaintext, &new_context)?;
```

## Best Practices

1. **Restrict Access**: Use file system permissions to protect keys
2. **Regular Backups**: Backup keys securely and separately
3. **Key Versioning**: Use version numbers for smooth rotation
4. **Testing**: Test key rotation procedures regularly
5. **Monitoring**: Monitor key file access and modifications

## Limitations

- Not suitable for high-throughput scenarios (use KMS instead)
- Requires file system access
- No built-in key distribution mechanism
- Single-node only (no automatic replication)

## Alternative Providers

For production environments, consider:

- **[sifredb-kms-aws](https://crates.io/crates/sifredb-kms-aws)**: AWS KMS integration
- Custom providers implementing the `KeyProvider` trait

## Related Crates

- **[sifredb](https://crates.io/crates/sifredb)**: Core encryption library
- **[sifredb-kms-aws](https://crates.io/crates/sifredb-kms-aws)**: AWS KMS integration
- **[sifredb-cli](https://crates.io/crates/sifredb-cli)**: Command-line tool

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
