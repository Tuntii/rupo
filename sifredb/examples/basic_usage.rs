//! Basic usage example for `SifreDB`.

use sifredb::prelude::*;

fn main() {
    println!("SifreDB Basic Usage Example");
    println!("============================\n");

    // Create an encryption context
    let context =
        EncryptionContext::new("users", "email").with_tenant("tenant_123").with_version(1);

    println!("Encryption Context: {context}");
    println!("  - Tenant: {:?}", context.tenant_id());
    println!("  - Table: {}", context.table_name());
    println!("  - Column: {}", context.column_name());
    println!("  - Version: {}", context.version());

    // Create an index context
    let index_context = IndexContext::from(&context);
    println!("\nIndex Context: {index_context}");

    println!("\n✓ Context creation successful!");
    println!("\nNote: Full encryption functionality will be available in upcoming tasks.");
}
