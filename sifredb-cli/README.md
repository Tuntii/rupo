# sifredb-cli

[![Crates.io](https://img.shields.io/crates/v/sifredb-cli.svg)](https://crates.io/crates/sifredb-cli)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](https://github.com/Tuntii/sifredb)

Command-line tool for [SifreDB](https://crates.io/crates/sifredb) key management.

## Features

- 🔑 Key generation and management
- 🔄 Key rotation utilities
- 📁 Key directory initialization
- 🔍 Key inspection and validation
- 🏢 Multi-tenant key management

## Installation

### From crates.io

```bash
cargo install sifredb-cli
```

### From source

```bash
git clone https://github.com/Tuntii/sifredb.git
cd sifredb/sifredb-cli
cargo install --path .
```

## Usage

### Initialize Key Directory

```bash
sifredb init ./keys
```

### Generate New Key

```bash
sifredb keygen --tenant tenant_a --table users --column email --version 1
```

### List Keys

```bash
sifredb list ./keys
```

### Rotate Key

```bash
sifredb rotate --tenant tenant_a --table users --column email --from 1 --to 2
```

### Validate Keys

```bash
sifredb validate ./keys
```

## Commands

### `init`

Initialize a new key directory structure.

```bash
sifredb init <directory>
```

### `keygen`

Generate a new encryption key.

```bash
sifredb keygen [OPTIONS]

Options:
  --tenant <TENANT>      Tenant ID
  --table <TABLE>        Table name
  --column <COLUMN>      Column name
  --version <VERSION>    Key version [default: 1]
  --output <OUTPUT>      Output directory [default: ./keys]
```

### `list`

List all keys in a directory.

```bash
sifredb list <directory>
```

### `rotate`

Rotate encryption keys.

```bash
sifredb rotate [OPTIONS]

Options:
  --tenant <TENANT>      Tenant ID
  --table <TABLE>        Table name
  --column <COLUMN>      Column name
  --from <VERSION>       Current version
  --to <VERSION>         New version
  --keys <DIRECTORY>     Key directory [default: ./keys]
```

### `validate`

Validate key files and directory structure.

```bash
sifredb validate <directory>
```

## Configuration

The CLI can be configured via environment variables:

- `SIFREDB_KEYS_DIR`: Default key directory
- `SIFREDB_LOG_LEVEL`: Logging level (debug, info, warn, error)

## Examples

### Complete Workflow

```bash
# 1. Initialize key directory
sifredb init ./my-keys

# 2. Generate keys for different contexts
sifredb keygen --tenant tenant_a --table users --column email --output ./my-keys
sifredb keygen --tenant tenant_a --table users --column ssn --output ./my-keys
sifredb keygen --tenant tenant_b --table users --column email --output ./my-keys

# 3. List all keys
sifredb list ./my-keys

# 4. Rotate a key
sifredb rotate --tenant tenant_a --table users --column email --from 1 --to 2 --keys ./my-keys

# 5. Validate everything
sifredb validate ./my-keys
```

### Multi-tenant Setup

```bash
# Generate keys for multiple tenants
for tenant in tenant_a tenant_b tenant_c; do
  sifredb keygen --tenant $tenant --table users --column email
  sifredb keygen --tenant $tenant --table users --column ssn
done
```

## Security Notes

- Always restrict access to key directories (chmod 700)
- Store keys separately from encrypted data
- Implement secure backup procedures
- Regularly rotate keys
- Monitor key access logs

## Related Crates

- **[sifredb](https://crates.io/crates/sifredb)**: Core encryption library
- **[sifredb-key-file](https://crates.io/crates/sifredb-key-file)**: File-based key provider
- **[sifredb-kms-aws](https://crates.io/crates/sifredb-kms-aws)**: AWS KMS integration

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
