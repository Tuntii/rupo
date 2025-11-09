//! Example demonstrating deterministic encryption with AES-SIV
//!
//! This example shows how to use deterministic encryption for equality queries
//! while maintaining security through context-based domain separation.

use secrecy::SecretVec;
use sifredb::{context::EncryptionContext, deterministic::DeterministicVault};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("SifreDB Deterministic Encryption Example");
    println!("=========================================\n");

    // Create a 64-byte key for AES-256-SIV
    let key = SecretVec::new(vec![0x42; 64]);
    let vault = DeterministicVault::new(key)?;
    println!("✓ DeterministicVault created with AES-256-SIV");

    // Define encryption context for an email field
    let email_context = EncryptionContext::new("users", "email")
        .with_tenant("tenant_123")
        .with_version(1);
    println!("✓ Context: {}\n", email_context);

    // Example 1: Deterministic property
    println!("Example 1: Deterministic Encryption");
    println!("-----------------------------------");
    let email = b"alice@example.com";
    
    let ct1 = vault.encrypt(email, &email_context)?;
    let ct2 = vault.encrypt(email, &email_context)?;
    
    println!("Email: {}", String::from_utf8_lossy(email));
    println!("Ciphertext 1: {} bytes", ct1.len());
    println!("Ciphertext 2: {} bytes", ct2.len());
    println!("Deterministic: {}", if ct1 == ct2 { "✓ YES" } else { "✗ NO" });
    println!("→ Same plaintext + context produces identical ciphertext\n");

    // Example 2: Database equality queries
    println!("Example 2: Database Equality Queries");
    println!("------------------------------------");
    
    // Encrypt multiple emails
    let emails: Vec<&[u8]> = vec![
        b"alice@example.com",
        b"bob@example.com",
        b"alice@example.com", // Duplicate
    ];
    
    let mut ciphertexts = Vec::new();
    for email in &emails {
        let ct = vault.encrypt(*email, &email_context)?;
        ciphertexts.push(ct);
        println!("Encrypted: {}", String::from_utf8_lossy(email));
    }
    
    // Simulate database query: find all "alice@example.com"
    let search_email = b"alice@example.com";
    let search_ct = vault.encrypt(search_email, &email_context)?;
    
    println!("\nSearching for: {}", String::from_utf8_lossy(search_email));
    let matches: Vec<_> = ciphertexts.iter()
        .enumerate()
        .filter(|(_, ct)| *ct == &search_ct)
        .collect();
    
    println!("Found {} match(es) at indices: {:?}", matches.len(), 
        matches.iter().map(|(i, _)| i).collect::<Vec<_>>());
    println!("→ Equality queries work on encrypted data!\n");

    // Example 3: Context isolation
    println!("Example 3: Context-Based Isolation");
    println!("----------------------------------");
    
    let email = b"alice@example.com";
    
    // Different contexts produce different ciphertexts
    let ctx_tenant1 = EncryptionContext::new("users", "email")
        .with_tenant("tenant_1");
    let ctx_tenant2 = EncryptionContext::new("users", "email")
        .with_tenant("tenant_2");
    let ctx_phone = EncryptionContext::new("users", "phone")
        .with_tenant("tenant_1");
    
    let ct_t1 = vault.encrypt(email, &ctx_tenant1)?;
    let ct_t2 = vault.encrypt(email, &ctx_tenant2)?;
    let ct_phone = vault.encrypt(email, &ctx_phone)?;
    
    println!("Same plaintext, different contexts:");
    println!("  Tenant 1 email: {} bytes", ct_t1.len());
    println!("  Tenant 2 email: {} bytes", ct_t2.len());
    println!("  Tenant 1 phone: {} bytes", ct_phone.len());
    println!("  All different: {}", 
        if ct_t1 != ct_t2 && ct_t2 != ct_phone && ct_t1 != ct_phone { "✓ YES" } else { "✗ NO" });
    println!("→ Context prevents cross-domain attacks\n");

    // Example 4: Authentication with context
    println!("Example 4: Context Authentication");
    println!("---------------------------------");
    
    let email = b"alice@example.com";
    let ctx_correct = EncryptionContext::new("users", "email");
    let ctx_wrong = EncryptionContext::new("users", "phone");
    
    let ciphertext = vault.encrypt(email, &ctx_correct)?;
    println!("Encrypted with context: {}", ctx_correct);
    
    // Try to decrypt with correct context
    match vault.decrypt(&ciphertext, &ctx_correct) {
        Ok(plaintext) => {
            println!("✓ Decryption with correct context: SUCCESS");
            println!("  Plaintext: {}", String::from_utf8_lossy(&plaintext));
        }
        Err(e) => println!("✗ Decryption failed: {}", e),
    }
    
    // Try to decrypt with wrong context
    match vault.decrypt(&ciphertext, &ctx_wrong) {
        Ok(_) => println!("✗ Decryption with wrong context: UNEXPECTED SUCCESS"),
        Err(_) => println!("✓ Decryption with wrong context: FAILED (as expected)"),
    }
    println!("→ Context acts as Additional Authenticated Data\n");

    // Example 5: Round-trip verification
    println!("Example 5: Round-Trip Verification");
    println!("----------------------------------");
    
    let test_emails: Vec<&[u8]> = vec![
        b"alice@example.com",
        b"bob@corporate.io",
        b"charlie@startup.dev",
    ];
    
    let context = EncryptionContext::new("users", "email")
        .with_tenant("test");
    
    let mut all_success = true;
    for email in &test_emails {
        let ciphertext = vault.encrypt(*email, &context)?;
        let decrypted = vault.decrypt(&ciphertext, &context)?;
        
        let success = decrypted == *email;
        all_success = all_success && success;
        
        println!("  {} -> {} bytes -> {}",
            String::from_utf8_lossy(email),
            ciphertext.len(),
            if success { "✓" } else { "✗" }
        );
    }
    
    println!("\nAll round-trips: {}", if all_success { "✓ SUCCESS" } else { "✗ FAILED" });

    // Security warnings
    println!("\n⚠️  Security Considerations:");
    println!("   1. Deterministic encryption reveals equality patterns");
    println!("   2. Use only for fields requiring equality queries");
    println!("   3. Not suitable for high-cardinality unique data (UUIDs, etc.)");
    println!("   4. Always use proper context for domain separation");
    println!("   5. Consider using AEAD (ChaCha20-Poly1305) for other fields");

    println!("\n✓ All examples completed successfully!");
    
    Ok(())
}
