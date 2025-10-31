//! Derive macros for `SifreDB`.
//!
//! This crate provides procedural macros for automatic encryption/decryption
//! of struct fields.

#![warn(clippy::pedantic, clippy::nursery)]

use proc_macro::TokenStream;

/// Derive macro for automatic field encryption.
///
/// # Example
///
/// ```rust,ignore
/// use sifredb_derive::Encryptable;
///
/// #[derive(Encryptable)]
/// struct User {
///     #[enc(mode = "aead")]
///     name: String,
///     #[enc(mode = "deterministic", indexed = true)]
///     email: String,
/// }
/// ```
#[proc_macro_derive(Encryptable, attributes(enc))]
pub fn derive_encryptable(_input: TokenStream) -> TokenStream {
    // Placeholder implementation
    // Will be implemented in future tasks
    TokenStream::new()
}
