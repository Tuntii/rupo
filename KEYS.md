# Key Management Guide

This document provides comprehensive guidance on managing encryption keys in SifreDB.

## Table of Contents

- [Key Hierarchy](#key-hierarchy)
- [Key Providers](#key-providers)
- [Key Generation](#key-generation)
- [Key Rotation](#key-rotation)
- [Key Backup](#key-backup)
- [Key Deletion](#key-deletion)
- [Production Setup](#production-setup)
- [Disaster Recovery](#disaster-recovery)

## Key Hierarchy

SifreDB uses a three-tier key hierarchy:

```
┌─────────────────────────────────────────┐
│  Key Encryption Key (KEK)               │
│  - Stored in KMS/HSM/File               │
│  - 256-bit AES key                      │
│  - Versioned (kek_v1, kek_v2, ...)      │
└────────────┬────────────────────────────┘
             │ wraps
             ▼
┌─────────────────────────────────────────┐
│  Data Encryption Key (DEK)               │
│  - Random per encryption (AEAD)          │
│  - Derived from context (deterministic)  │
│  - 256-bit ChaCha20/AES key              │
│  - Never stored unwrapped                │
└────────────┬────────────────────────────┘
             │ encrypts
             ▼
┌─────────────────────────────────────────┐
│  Plaintext Data                          │
│  - Sensitive database fields             │
│  - PII, financial data, credentials      │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│  Pepper (Separate Key)                   │
│  - Used for blind indexes                │
│  - 256-bit random value                  │
│  - Stored separately from KEK            │
└─────────────────────────────────────────┘
```

## Key Providers

### File-Based Provider (Development)

**Use Case**: Local development, testing

**Storage Structure**:
```
./keys/
├── kek_v1.key           # First KEK version (32 bytes)
├── kek_v2.key           # Rotated KEK (32 bytes)
├── pepper.key           # Blind index pepper (32 bytes)
└── current -> kek_v2.key # Symlink to active KEK
```

**Initialization**:
```rust
use sifredb_key_file::FileKeyProvider;

// Create key directory and generate first KEK
let provider = FileKeyProvider::new("./keys")?;
```

**Security**:
- Keys stored as raw bytes on filesystem
- Requires proper file permissions (chmod 600)
- **Not suitable for production use**

### AWS KMS Provider (Production)

**Use Case**: Production deployments, enterprise applications

**Setup**:
```rust
use sifredb_kms_aws::AwsKmsProvider;

// Use default AWS configuration
let provider = AwsKmsProvider::new().await?;

// Or specify KMS key
let provider = AwsKmsProvider::with_key_id(
    "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
).await?;

// Or use alias
let provider = AwsKmsProvider::with_key_id("alias/sifredb-kek").await?;
```

**Benefits**:
- Hardware-backed security (HSM)
- Automatic backups and multi-region replication
- Fine-grained IAM access control
- CloudTrail audit logging
- Built-in key rotation

## Key Generation

### Creating KEKs

#### File-Based

```rust
use sifredb_key_file::FileKeyProvider;

// Initialize creates first KEK automatically
let provider = FileKeyProvider::new("./keys")?;

// Or create manually
let kek_id = provider.create_kek().await?;
println!("Created KEK: {}", kek_id); // e.g., "kek_v2"
```

#### AWS KMS

```bash
# Create KMS key with AWS CLI
aws kms create-key \
  --description "SifreDB KEK for production" \
  --key-usage ENCRYPT_DECRYPT \
  --origin AWS_KMS

# Create alias for easier reference
aws kms create-alias \
  --alias-name alias/sifredb-kek \
  --target-key-id 12345678-1234-1234-1234-123456789012
```

### Pepper Generation

The pepper is automatically generated during provider initialization:

```rust
// File-based: stored in pepper.key
let provider = FileKeyProvider::new("./keys")?;

// AWS KMS: generated and stored separately (not in KMS)
let provider = AwsKmsProvider::new().await?;
```

**Important**: Pepper must be backed up separately as it's required for blind index queries.

## Key Rotation

Key rotation limits the amount of data encrypted with a single key and is required for compliance.

### Rotation Frequency

**Recommended Schedule**:
- **High-security environments**: Every 30 days
- **Standard environments**: Every 90 days
- **Low-risk data**: Every 365 days

**Triggers for Emergency Rotation**:
- Suspected key compromise
- Employee with key access leaves
- Security vulnerability discovered
- Compliance requirement

### Rotation Process

#### 1. Create New KEK

```rust
// File-based
let new_kek_id = provider.create_kek().await?;
println!("New KEK: {}", new_kek_id); // kek_v2

// AWS KMS
# aws kms create-key --description "SifreDB KEK v2"
```

#### 2. Configure as Current

```rust
// File-based (automatic via symlink)
// No code change needed - symlink updated automatically

// AWS KMS
provider.set_current_key_id("arn:aws:kms:...").await;
```

#### 3. Re-encrypt Data

**Option A: Online Re-encryption** (Gradual)
```rust
// On read: if old KEK, decrypt and re-encrypt with new KEK
async fn migrate_on_read(
    vault: &Vault,
    old_ciphertext: &[u8],
    context: &EncryptionContext,
) -> Result<Vec<u8>, Error> {
    // Decrypt with old KEK
    let plaintext = vault.decrypt(old_ciphertext, context)?;
    
    // Encrypt with new KEK
    let new_ciphertext = vault.encrypt(&plaintext, context)?;
    
    // Update database with new ciphertext
    Ok(new_ciphertext)
}
```

**Option B: Batch Re-encryption** (Immediate)
```sql
-- Example for PostgreSQL
UPDATE users
SET email_encrypted = sifredb_reencrypt(email_encrypted, 'kek_v2')
WHERE email_encrypted IS NOT NULL;
```

**Option C: CLI Tool** (Recommended)
```bash
# Re-encrypt all data using CLI tool
sifredb-cli rotate \
  --provider file \
  --old-kek kek_v1 \
  --new-kek kek_v2 \
  --database "postgresql://localhost/mydb" \
  --table users \
  --column email_encrypted
```

#### 4. Verify Migration

```sql
-- Check for remaining old-KEK ciphertexts
SELECT COUNT(*) FROM users 
WHERE email_encrypted LIKE 'kek_v1%';
```

#### 5. Decommission Old KEK

**Wait Period**: 30 days after full migration

```rust
// File-based: backup and delete
// Backup first!
cp keys/kek_v1.key keys/archive/kek_v1.key.backup
rm keys/kek_v1.key

// AWS KMS: schedule deletion
aws kms schedule-key-deletion \
  --key-id 12345678-1234-1234-1234-123456789012 \
  --pending-window-in-days 30
```

### Rotation Metrics

Track these metrics during rotation:

```rust
#[derive(Debug)]
struct RotationMetrics {
    total_records: usize,
    migrated: usize,
    failed: usize,
    duration: Duration,
}

// Calculate progress
let progress = (metrics.migrated as f64 / metrics.total_records as f64) * 100.0;
println!("Rotation progress: {:.2}%", progress);
```

## Key Backup

### File-Based Provider

```bash
#!/bin/bash
# Backup script for file-based keys

BACKUP_DIR="/secure/backups/sifredb"
KEY_DIR="./keys"
DATE=$(date +%Y%m%d-%H%M%S)

# Create encrypted backup
tar czf - "$KEY_DIR" | \
  gpg --encrypt --recipient backup@company.com \
  > "$BACKUP_DIR/keys-$DATE.tar.gz.gpg"

# Verify backup
gpg --decrypt "$BACKUP_DIR/keys-$DATE.tar.gz.gpg" | \
  tar tzf - > /dev/null && echo "Backup verified"

# Keep last 30 days
find "$BACKUP_DIR" -name "keys-*.tar.gz.gpg" -mtime +30 -delete
```

**Storage Locations**:
- Primary: Encrypted filesystem
- Secondary: Offline storage (USB drive in safe)
- Tertiary: Offsite backup (different physical location)

### AWS KMS Provider

**Automatic Backups**:
- KMS keys automatically backed up by AWS
- Multi-region replication available
- No manual backup needed for KMS keys

**Pepper Backup** (Still Required):
```bash
# Backup pepper separately
aws s3 cp pepper.key s3://company-secrets/sifredb/pepper.key \
  --sse aws:kms \
  --sse-kms-key-id alias/backup-encryption
```

### Backup Testing

**Schedule**: Quarterly

```bash
# Restore test
1. Restore backup to isolated environment
2. Decrypt sample ciphertext
3. Verify plaintext matches expected
4. Document results
```

## Key Deletion

### Secure Deletion Process

1. **Verification**: Ensure no data uses this KEK
2. **Backup**: Archive key before deletion
3. **Grace Period**: 30-day waiting period
4. **Deletion**: Securely erase key material
5. **Audit**: Log deletion event

### File-Based

```bash
# Secure deletion using shred (Linux)
shred -vfz -n 10 keys/kek_v1.key

# Or using srm (more thorough)
srm -v keys/kek_v1.key
```

### AWS KMS

```bash
# Schedule deletion (7-30 day waiting period)
aws kms schedule-key-deletion \
  --key-id alias/old-sifredb-kek \
  --pending-window-in-days 30

# Cancel if needed
aws kms cancel-key-deletion \
  --key-id alias/old-sifredb-kek

# Check deletion status
aws kms describe-key --key-id alias/old-sifredb-kek
```

## Production Setup

### AWS KMS Production Deployment

#### 1. Create KMS Key with CloudFormation

```yaml
Resources:
  SifreDBKEK:
    Type: AWS::KMS::Key
    Properties:
      Description: SifreDB Key Encryption Key
      KeyPolicy:
        Version: '2012-10-17'
        Statement:
          - Sid: Enable IAM policies
            Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'
            Action: 'kms:*'
            Resource: '*'
          - Sid: Allow application role
            Effect: Allow
            Principal:
              AWS: !GetAtt SifreDBAppRole.Arn
            Action:
              - 'kms:Encrypt'
              - 'kms:Decrypt'
              - 'kms:DescribeKey'
            Resource: '*'
      EnableKeyRotation: true

  SifreDBKEKAlias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: alias/sifredb-kek
      TargetKeyId: !Ref SifreDBKEK

  SifreDBAppRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: 'sts:AssumeRole'
      ManagedPolicyArns:
        - !Ref SifreDBKMSPolicy

  SifreDBKMSPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - 'kms:Encrypt'
              - 'kms:Decrypt'
              - 'kms:DescribeKey'
            Resource: !GetAtt SifreDBKEK.Arn
```

#### 2. Application Configuration

```rust
// Load KMS provider in application
use sifredb_kms_aws::AwsKmsProvider;
use sifredb::vault::Vault;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize provider with alias
    let provider = Arc::new(
        AwsKmsProvider::with_key_id("alias/sifredb-kek").await?
    );
    
    // Create vault
    let vault = Vault::new(provider.clone(), CipherMode::default());
    
    // Use in application
    let context = EncryptionContext::new("users", "email")
        .with_tenant("prod");
    let ciphertext = vault.encrypt(b"sensitive@data.com", &context)?;
    
    Ok(())
}
```

#### 3. Monitoring

```rust
// Add metrics collection
use prometheus::{Counter, Histogram};

lazy_static! {
    static ref ENCRYPTION_TOTAL: Counter = 
        Counter::new("sifredb_encryptions_total", "Total encryptions").unwrap();
    
    static ref ENCRYPTION_DURATION: Histogram =
        Histogram::new("sifredb_encryption_duration_seconds", "Encryption duration").unwrap();
}

// Instrument operations
let timer = ENCRYPTION_DURATION.start_timer();
let ciphertext = vault.encrypt(data, &context)?;
timer.observe_duration();
ENCRYPTION_TOTAL.inc();
```

#### 4. CloudWatch Alarms

```yaml
KMSKeyDisabled:
  Type: AWS::CloudWatch::Alarm
  Properties:
    AlarmDescription: SifreDB KMS key has been disabled
    MetricName: KeyState
    Namespace: AWS/KMS
    Statistic: Average
    Period: 60
    EvaluationPeriods: 1
    Threshold: 0
    ComparisonOperator: LessThanThreshold
    AlarmActions:
      - !Ref AlertTopic

HighKMSThrottling:
  Type: AWS::CloudWatch::Alarm
  Properties:
    AlarmDescription: High KMS throttling rate
    MetricName: UserErrorCount
    Namespace: AWS/KMS
    Statistic: Sum
    Period: 300
    EvaluationPeriods: 2
    Threshold: 10
    ComparisonOperator: GreaterThanThreshold
```

## Disaster Recovery

### Scenarios

#### 1. Key Provider Unavailable

**Problem**: KMS service down, file storage inaccessible

**Mitigation**:
```rust
// Implement fallback key provider
use std::sync::Arc;

struct FallbackProvider {
    primary: Arc<dyn KeyProvider>,
    fallback: Arc<dyn KeyProvider>,
}

impl FallbackProvider {
    async fn wrap_dek(&self, dek: &SecretVec<u8>, kek_id: &str) 
        -> Result<WrappedDek, KeyProviderError> 
    {
        match self.primary.wrap_dek(dek, kek_id).await {
            Ok(wrapped) => Ok(wrapped),
            Err(_) => {
                log::warn!("Primary provider failed, using fallback");
                self.fallback.wrap_dek(dek, kek_id).await
            }
        }
    }
}
```

#### 2. KEK Compromise

**Immediate Actions**:
1. Revoke compromised KEK
2. Generate new KEK
3. Begin emergency rotation
4. Notify security team
5. Investigate compromise vector

**Recovery**:
```bash
# Emergency rotation script
sifredb-cli emergency-rotate \
  --compromised-kek kek_v5 \
  --new-kek kek_v6 \
  --priority high \
  --parallel-workers 10
```

#### 3. Data Recovery

**Scenario**: Need to recover encrypted data after key loss

**Prevention**:
- Regular key backups (see [Key Backup](#key-backup))
- Key escrow for critical systems
- Multi-region KMS key replication

**Recovery Process**:
```bash
# 1. Restore KEK from backup
gpg --decrypt keys-backup.tar.gz.gpg | tar xzf -

# 2. Verify key integrity
sha256sum kek_v1.key
# Compare with documented hash

# 3. Test decryption
sifredb-cli test-decrypt \
  --key-file keys/kek_v1.key \
  --test-ciphertext "base64-encoded-ct"

# 4. Restore to production
cp -a keys-restored/ /production/keys/
```

## Key Management Checklist

### Initial Setup
- [ ] Choose key provider (file/KMS)
- [ ] Generate initial KEK
- [ ] Generate pepper
- [ ] Configure backup strategy
- [ ] Set file permissions (if file-based)
- [ ] Document key locations
- [ ] Test encryption/decryption

### Regular Maintenance
- [ ] Rotate KEKs per schedule
- [ ] Verify backups monthly
- [ ] Review access logs
- [ ] Update documentation
- [ ] Test disaster recovery quarterly

### Before Key Deletion
- [ ] Verify no data uses key
- [ ] Create final backup
- [ ] Wait grace period (30 days)
- [ ] Document deletion reason
- [ ] Archive in audit log

### Emergency Procedures
- [ ] Document key compromise process
- [ ] Prepare emergency rotation script
- [ ] Maintain emergency contact list
- [ ] Practice incident response drills

## References

- [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) - Key Management Recommendations
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)

## Last Updated

November 9, 2025
