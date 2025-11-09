# Security Policy

## Threat Model

### Assets Protected

SifreDB is designed to protect:

1. **Plaintext Data** - Sensitive database fields (PII, financial data, credentials)
2. **Data Encryption Keys (DEKs)** - Used for encrypting individual records
3. **Key Encryption Keys (KEKs)** - Used for wrapping DEKs
4. **Blind Index Pepper** - Secret value used in blind index generation

### Adversary Model

We consider the following threat scenarios:

#### ✅ Protected Against

- **Database Breach**: Attacker gains read access to encrypted database
  - *Mitigation*: All sensitive data is encrypted with AEAD
  - *Result*: Ciphertexts are useless without DEKs

- **SQL Injection**: Attacker can read/modify encrypted fields
  - *Mitigation*: Authenticated encryption prevents tampering
  - *Result*: Modified ciphertexts fail authentication

- **Application Log Exposure**: Logs accidentally contain sensitive data
  - *Mitigation*: Use `SecretVec` and `zeroize` for all sensitive values
  - *Result*: Keys are never logged in plaintext

- **Multi-tenant Data Leakage**: Tenant A accesses Tenant B's data
  - *Mitigation*: Context-based domain separation
  - *Result*: Different tenants produce different ciphertexts

- **Passive Network Monitoring**: Attacker observes network traffic
  - *Mitigation*: TLS for KMS communication, keys never in transit
  - *Result*: No keys exposed over network

#### ⚠️ Partially Protected

- **Side-Channel Attacks**: Timing attacks on cryptographic operations
  - *Status*: We use constant-time implementations where available
  - *Limitation*: Full protection requires hardware support

- **Memory Scraping**: Attacker dumps process memory
  - *Status*: Keys are zeroized after use
  - *Limitation*: Keys must exist in memory during operations

#### ❌ Not Protected Against

- **Application Compromise**: Attacker executes code in application process
  - *Reason*: Application has legitimate access to decrypt data
  - *Mitigation*: Strong application security practices required

- **Key Provider Compromise**: Attacker gains access to KEK storage
  - *Reason*: KEKs are required for DEK unwrapping
  - *Mitigation*: Use HSM-backed KMS providers (AWS KMS, etc.)

- **Frequency Analysis**: Attacker analyzes deterministic ciphertext patterns
  - *Reason*: Deterministic encryption enables equality queries
  - *Mitigation*: Use only for necessary fields, AEAD for others

## Cryptographic Primitives

### AEAD Encryption

**Algorithm**: ChaCha20-Poly1305 (default)

**Properties**:
- Confidentiality: 256-bit security
- Authenticity: 128-bit tag
- Nonce: 96-bit random (collision probability: ~2^-48 after 2^48 operations)

**Security Considerations**:
- Random nonce ensures different ciphertexts for same plaintext
- Context used as Additional Authenticated Data (AAD)
- Safe for billions of operations with 256-bit keys

**Alternatives**: AES-GCM (when hardware acceleration available)

### Deterministic Encryption

**Algorithm**: AES-256-SIV (Synthetic IV)

**Properties**:
- Deterministic: Same input → same output
- Misuse-resistant: Safe even with nonce reuse
- Authenticity: Built-in authentication
- Key size: 512 bits (two 256-bit keys)

**Security Considerations**:
- ⚠️ **Reveals equality patterns** - use only for fields requiring equality queries
- Context as AAD prevents cross-context attacks
- Not suitable for high-entropy data (reveals duplicates)

### Key Derivation

**Algorithm**: HKDF-SHA256

**Purpose**: Derive domain-specific keys from master KEK

**Domain Separation**:
```
info = tenant_id | table_name | column_name | version
```

**Security Considerations**:
- Different contexts produce cryptographically independent keys
- Version support enables key rotation
- Tenant isolation prevents cross-tenant attacks

### Blind Indexes

**Algorithm**: HMAC-SHA256 with pepper

**Construction**:
```
blind_index = HMAC-SHA256(pepper, plaintext || context)
```

**Output**: 16 bytes (128 bits)

**Security Considerations**:
- Pepper must be kept secret (stored separately from encrypted data)
- Context binds index to specific tenant/table/column
- Truncation to 16 bytes provides adequate collision resistance
- ⚠️ **Not semantically secure** - enables equality testing by design

## Key Management

### Key Hierarchy

```
KEK (Key Encryption Key)
  ├── Stored in KMS/HSM/File
  └── Wraps DEKs

DEK (Data Encryption Key)
  ├── Generated per encryption (AEAD mode)
  ├── Derived from context (deterministic mode)
  └── Never stored unwrapped

Pepper
  ├── Stored separately from KEK
  └── Used for blind index generation
```

### KEK Storage

#### File-based (Development/Testing)
```
./keys/
├── kek_v1.key    # 32 bytes, 256-bit key
├── kek_v2.key    # New key version
├── pepper.key    # 32 bytes, for blind indexes
└── current -> kek_v2.key  # Symlink to active KEK
```

**Security**:
- ✅ Simple for development
- ❌ Keys in filesystem
- ⚠️ Use only for non-production environments

**Permissions**: `chmod 600` on all key files

#### AWS KMS (Production)
- ✅ Hardware-backed security (HSM)
- ✅ Automatic backups and replication
- ✅ Fine-grained IAM access control
- ✅ CloudTrail audit logging
- ✅ Key rotation with re-encryption

**IAM Policy Example**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:region:account:key/key-id"
    }
  ]
}
```

### Key Rotation

**Process**:
1. Create new KEK (v2) while keeping old KEK (v1)
2. Configure v2 as current KEK for new encryptions
3. Re-wrap existing DEKs: decrypt with v1, encrypt with v2
4. Update ciphertext headers to reference v2
5. Decommission v1 after all data re-encrypted

**Frequency**: Recommended every 90 days

**Benefits**:
- Limits data exposure per key
- Compliance with key rotation policies
- Gradual migration without downtime

## Best Practices

### ✅ Do

1. **Use AEAD for Most Fields**
   ```rust
   let vault = Vault::new(provider, CipherMode::ChaCha20Poly1305);
   ```

2. **Limit Deterministic Encryption**
   ```rust
   // Only for fields requiring equality queries
   let det_vault = DeterministicVault::new(key)?;
   ```

3. **Always Provide Context**
   ```rust
   let context = EncryptionContext::new("users", "email")
       .with_tenant("tenant_123");
   ```

4. **Rotate Keys Regularly**
   ```bash
   sifredb-cli rotate-key --old kek_v1 --new kek_v2
   ```

5. **Use KMS in Production**
   ```rust
   let provider = AwsKmsProvider::with_key_id("alias/sifredb-kek").await?;
   ```

6. **Zeroize Sensitive Data**
   ```rust
   use secrecy::{SecretVec, ExposeSecret};
   let secret = SecretVec::new(sensitive_data);
   // Use secret.expose_secret() only when needed
   ```

7. **Enable Audit Logging**
   - CloudTrail for AWS KMS
   - Application-level logs for key access

### ❌ Don't

1. **Never Log Keys or Plaintexts**
   ```rust
   // ❌ WRONG
   log::info!("Key: {:?}", key);
   
   // ✅ RIGHT
   log::info!("Key operation completed");
   ```

2. **Don't Reuse Context Across Domains**
   ```rust
   // ❌ WRONG - same context for different columns
   let ctx = EncryptionContext::new("users", "data");
   
   // ✅ RIGHT - specific context per column
   let email_ctx = EncryptionContext::new("users", "email");
   let phone_ctx = EncryptionContext::new("users", "phone");
   ```

3. **Don't Store KEKs in Database**
   - KEKs must be stored separately from encrypted data

4. **Don't Use Deterministic for High-Cardinality Data**
   ```rust
   // ❌ WRONG - reveals patterns
   det_vault.encrypt(&uuid, &context)?;
   
   // ✅ RIGHT - use AEAD for unique values
   vault.encrypt(&uuid, &context)?;
   ```

5. **Don't Share Pepper with Application**
   - Pepper should only be accessible to key provider

6. **Don't Skip Context AAD**
   ```rust
   // ❌ WRONG - reduces security
   vault.encrypt(data, &EncryptionContext::new("", ""))?;
   
   // ✅ RIGHT - proper context
   vault.encrypt(data, &context)?;
   ```

## Compliance

### Standards Supported

- **FIPS 140-2/3**: Use AWS KMS with FIPS endpoints
- **GDPR**: Right to be forgotten (delete KEK)
- **HIPAA**: PHI encryption in transit and at rest
- **PCI DSS**: Cardholder data encryption

### Audit Capabilities

1. **Key Usage Tracking**
   - CloudTrail logs all KMS operations
   - Timestamp, principal, operation type

2. **Data Access Logs**
   - Application-level logging of decrypt operations
   - Link to user, session, query

3. **Key Rotation History**
   - Track KEK versions and rotation dates
   - Maintain audit trail of re-encryption operations

## Incident Response

### Data Breach Response

1. **Assess Scope**: Determine which data was accessed
2. **Verify Encryption**: Confirm all sensitive fields encrypted
3. **Check Key Security**: Ensure KEKs not compromised
4. **Rotate Keys**: Create new KEK and re-encrypt as precaution
5. **Notify**: Follow breach notification requirements

### Key Compromise Response

1. **Immediate**: Revoke compromised KEK in KMS
2. **Generate**: Create new KEK (emergency rotation)
3. **Re-encrypt**: Rewrap all DEKs with new KEK
4. **Investigate**: Determine compromise vector
5. **Remediate**: Fix security gap

### Recovery

- **Backup Strategy**: Store encrypted backups with separate KEK
- **Key Escrow**: Consider split-key or M-of-N schemes for KEK recovery
- **Testing**: Regularly test recovery procedures

## Security Updates

**Reporting Vulnerabilities**: security@yourcompany.com

**Response Timeline**:
- Acknowledgment: 24 hours
- Initial assessment: 72 hours
- Fix timeline: Based on severity (Critical: 7 days, High: 30 days)

**Supported Versions**: Only latest minor version receives security updates

## Cryptographic Review

This library has **not** been audited by a third-party security firm. 

**Recommendation**: Before production use in high-security environments, obtain:
1. Independent cryptographic audit
2. Penetration testing
3. Code review by security team

## References

- [NIST SP 800-175B](https://csrc.nist.gov/publications/detail/sp/800-175b/rev-1/final) - Key Management Guidelines
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [RFC 5869](https://tools.ietf.org/html/rfc5869) - HKDF
- [RFC 5297](https://tools.ietf.org/html/rfc5297) - AES-SIV
- [RFC 8439](https://tools.ietf.org/html/rfc8439) - ChaCha20-Poly1305

## Last Updated

November 9, 2025
