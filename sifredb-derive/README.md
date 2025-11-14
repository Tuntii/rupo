# sifredb-derive

[![Crates.io](https://img.shields.io/crates/v/sifredb-derive.svg)](https://crates.io/crates/sifredb-derive)
[![Documentation](https://docs.rs/sifredb-derive/badge.svg)](https://docs.rs/sifredb-derive)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](https://github.com/Tuntii/sifredb)

Derive macros for [SifreDB](https://crates.io/crates/sifredb) - automatic field-level encryption.

## Features

- Automatic encryption/decryption of struct fields
- Custom attribute configuration
- Type-safe encryption contexts
- Compile-time validation

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
sifredb = "0.1"
sifredb-derive = "0.1"
```

## Usage

```rust
use sifredb_derive::Encrypt;
use sifredb::prelude::*;

#[derive(Encrypt)]
struct User {
    pub id: i32,
    
    #[encrypt]
    pub email: String,
    
    #[encrypt]
    pub ssn: String,
}
```

The derive macro automatically generates encryption and decryption methods for annotated fields.

## Attributes

- `#[encrypt]` - Mark field for encryption
- `#[encrypt(deterministic)]` - Use deterministic encryption for equality queries
- `#[encrypt(context = "custom")]` - Specify custom encryption context

## Related Crates

- **[sifredb](https://crates.io/crates/sifredb)**: Core encryption library
- **[sifredb-key-file](https://crates.io/crates/sifredb-key-file)**: File-based key provider
- **[sifredb-kms-aws](https://crates.io/crates/sifredb-kms-aws)**: AWS KMS integration

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../LICENSE-MIT))

at your option.
