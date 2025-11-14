# sifredb-kms-aws

[![Crates.io](https://img.shields.io/crates/v/sifredb-kms-aws.svg)](https://crates.io/crates/sifredb-kms-aws)
[![Documentation](https://docs.rs/sifredb-kms-aws/badge.svg)](https://docs.rs/sifredb-kms-aws)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](https://github.com/Tuntii/sifredb)

AWS KMS key provider for [SifreDB](https://crates.io/crates/sifredb).

## Features

- 🔐 AWS KMS integration for key management
- 🔑 Automatic key derivation using HKDF
- ☁️ Cloud-native key storage
- 🔄 Automatic key rotation support
- 🏢 Multi-region support
- 🛡️ Hardware-backed key protection (HSM)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
sifredb = "0.1"
sifredb-kms-aws = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Prerequisites

### Build Dependencies

- **CMake**: Required for building AWS SDK dependencies
- **NASM**: Required for cryptographic operations (Windows)

#### Windows

```powershell
# Install via Chocolatey
choco install cmake nasm

# Or download directly:
# CMake: https://cmake.org/download/
# NASM: https://www.nasm.us/
```

#### Linux

```bash
# Ubuntu/Debian
sudo apt-get install cmake nasm

# Fedora/RHEL
sudo dnf install cmake nasm
```

#### macOS

```bash
brew install cmake nasm
```

### AWS Configuration

Configure AWS credentials using one of these methods:

1. **Environment Variables**:
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1
```

2. **AWS CLI**:
```bash
aws configure
```

3. **IAM Role** (recommended for EC2/ECS/Lambda)

## Usage

### Basic Setup

```rust
use sifredb::prelude::*;
use sifredb_kms_aws::AwsKmsProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create KMS provider with your KMS key ARN
    let kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012";
    let provider = AwsKmsProvider::new(kms_key_arn).await?;
    
    // Use with SifreDB vault
    let vault = DeterministicVault::with_provider(provider);
    
    let context = EncryptionContext::new("users", "email")
        .with_tenant("tenant_a");
    
    let ciphertext = vault.encrypt(b"alice@example.com", &context)?;
    let plaintext = vault.decrypt(&ciphertext, &context)?;
    
    Ok(())
}
```

### Custom AWS Configuration

```rust
use aws_config::BehaviorVersion;
use sifredb_kms_aws::AwsKmsProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Custom AWS config
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region("us-west-2")
        .load()
        .await;
    
    let provider = AwsKmsProvider::with_config(
        "arn:aws:kms:us-west-2:123456789012:key/...",
        config
    ).await?;
    
    // Use provider...
    
    Ok(())
}
```

### Multi-region Setup

```rust
use sifredb_kms_aws::AwsKmsProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Primary region
    let primary_provider = AwsKmsProvider::new(
        "arn:aws:kms:us-east-1:123456789012:key/..."
    ).await?;
    
    // Failover region
    let failover_provider = AwsKmsProvider::new(
        "arn:aws:kms:us-west-2:123456789012:key/..."
    ).await?;
    
    // Implement failover logic
    
    Ok(())
}
```

## IAM Permissions

The AWS credentials need the following KMS permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:Encrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "arn:aws:kms:region:account:key/key-id"
        }
    ]
}
```

## Key Derivation

The provider uses HKDF-SHA256 to derive encryption keys from KMS data keys:

1. Request data key from AWS KMS
2. Derive tenant-specific keys using HKDF
3. Mix encryption context into derivation
4. Cache keys for performance (optional)

## Performance Considerations

- **Key Caching**: Consider caching derived keys to reduce KMS API calls
- **Batch Operations**: Minimize KMS API calls by batching where possible
- **Regional Latency**: Use KMS keys in the same region as your application
- **Rate Limits**: AWS KMS has API rate limits - implement exponential backoff

## Security Best Practices

1. **Use IAM Roles**: Don't hardcode credentials
2. **Enable Key Rotation**: Use AWS KMS automatic key rotation
3. **Key Policies**: Restrict KMS key access using key policies
4. **Audit Logging**: Enable CloudTrail for KMS API calls
5. **Multi-Region Keys**: Use multi-region keys for disaster recovery
6. **Least Privilege**: Grant minimum required KMS permissions

## Cost Optimization

- Cache derived keys to reduce KMS API calls
- Use data keys instead of direct encryption
- Consider using envelope encryption patterns
- Monitor KMS API usage with CloudWatch

## Troubleshooting

### "Access Denied" Error

Check IAM permissions and KMS key policy.

### "Build Failed" Error

Ensure CMake and NASM are installed and in PATH.

### "Region Mismatch" Error

Verify AWS_REGION matches KMS key region.

## Related Crates

- **[sifredb](https://crates.io/crates/sifredb)**: Core encryption library
- **[sifredb-key-file](https://crates.io/crates/sifredb-key-file)**: File-based key provider
- **[sifredb-cli](https://crates.io/crates/sifredb-cli)**: Command-line tool

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE))
- MIT License ([LICENSE-MIT](../LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
