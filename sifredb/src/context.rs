//! Context types for encryption and indexing operations.

use std::fmt;

/// Context for encryption operations, used for key derivation and domain separation.
///
/// The context ensures that:
/// - Different tenants produce different ciphertexts
/// - Different tables/columns produce different ciphertexts
/// - Key rotation is supported via versioning
///
/// # Example
///
/// ```
/// use sifredb::context::EncryptionContext;
///
/// let ctx = EncryptionContext::new("users", "email")
///     .with_tenant("tenant_123")
///     .with_version(1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionContext {
    tenant_id: Option<String>,
    table_name: String,
    column_name: String,
    version: u32,
}

impl EncryptionContext {
    /// Creates a new encryption context.
    ///
    /// # Arguments
    ///
    /// * `table_name` - Database table name
    /// * `column_name` - Database column name
    #[must_use]
    pub fn new(table_name: impl Into<String>, column_name: impl Into<String>) -> Self {
        Self {
            tenant_id: None,
            table_name: table_name.into(),
            column_name: column_name.into(),
            version: 1,
        }
    }

    /// Sets the tenant ID for multi-tenant applications.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Sets the version for key rotation support.
    #[must_use]
    pub const fn with_version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Returns the tenant ID, if set.
    #[must_use]
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    /// Returns the table name.
    #[must_use]
    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    /// Returns the column name.
    #[must_use]
    pub fn column_name(&self) -> &str {
        &self.column_name
    }

    /// Returns the version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
}

impl fmt::Display for EncryptionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}|{}|{}|v{}",
            self.tenant_id.as_deref().unwrap_or("default"),
            self.table_name,
            self.column_name,
            self.version
        )
    }
}

/// Context for blind index generation.
///
/// Similar to `EncryptionContext` but without versioning (indexes are immutable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexContext {
    tenant_id: Option<String>,
    table_name: String,
    column_name: String,
}

impl IndexContext {
    /// Creates a new index context.
    #[must_use]
    pub fn new(table_name: impl Into<String>, column_name: impl Into<String>) -> Self {
        Self { tenant_id: None, table_name: table_name.into(), column_name: column_name.into() }
    }

    /// Sets the tenant ID.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Returns the tenant ID, if set.
    #[must_use]
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    /// Returns the table name.
    #[must_use]
    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    /// Returns the column name.
    #[must_use]
    pub fn column_name(&self) -> &str {
        &self.column_name
    }
}

impl fmt::Display for IndexContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}|{}|{}",
            self.tenant_id.as_deref().unwrap_or("default"),
            self.table_name,
            self.column_name
        )
    }
}

impl From<&EncryptionContext> for IndexContext {
    fn from(ctx: &EncryptionContext) -> Self {
        Self {
            tenant_id: ctx.tenant_id.clone(),
            table_name: ctx.table_name.clone(),
            column_name: ctx.column_name.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_context_display() {
        let ctx =
            EncryptionContext::new("users", "email").with_tenant("tenant_123").with_version(2);

        assert_eq!(ctx.to_string(), "tenant_123|users|email|v2");
    }

    #[test]
    fn test_encryption_context_display_no_tenant() {
        let ctx = EncryptionContext::new("users", "email");
        assert_eq!(ctx.to_string(), "default|users|email|v1");
    }

    #[test]
    fn test_index_context_display() {
        let ctx = IndexContext::new("users", "email").with_tenant("tenant_123");
        assert_eq!(ctx.to_string(), "tenant_123|users|email");
    }

    #[test]
    fn test_index_context_from_encryption_context() {
        let enc_ctx =
            EncryptionContext::new("users", "email").with_tenant("tenant_123").with_version(2);

        let idx_ctx = IndexContext::from(&enc_ctx);
        assert_eq!(idx_ctx.tenant_id(), Some("tenant_123"));
        assert_eq!(idx_ctx.table_name(), "users");
        assert_eq!(idx_ctx.column_name(), "email");
    }
}
