//! Encryption header format for ciphertext.
//!
//! The header contains metadata needed for decryption:
//! - Protocol version
//! - KEK identifier
//! - Wrapped DEK
//! - Flags
//! - Nonce

use crate::error::Error;

/// Protocol version for the encryption format.
pub const PROTOCOL_VERSION: u8 = 1;

/// Header flags for encryption options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderFlags(u8);

impl HeaderFlags {
    /// Creates empty flags.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Checks if deterministic mode is enabled.
    #[must_use]
    pub const fn is_deterministic(self) -> bool {
        (self.0 & 0x01) != 0
    }

    /// Sets deterministic mode flag.
    #[must_use]
    pub const fn with_deterministic(mut self) -> Self {
        self.0 |= 0x01;
        self
    }

    /// Returns the raw flags value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Creates flags from a raw value.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        Self(value)
    }
}

/// Encryption header containing metadata for decryption.
///
/// Format:
/// ```text
/// [version:1][kek_id_len:1][kek_id:N][wrapped_dek_len:2][wrapped_dek:M][flags:1][nonce_len:1][nonce:L]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionHeader {
    version: u8,
    kek_id: String,
    wrapped_dek: Vec<u8>,
    flags: HeaderFlags,
    nonce: Vec<u8>,
}

impl EncryptionHeader {
    /// Creates a new encryption header.
    ///
    /// # Arguments
    ///
    /// * `kek_id` - Identifier of the KEK used to wrap the DEK
    /// * `wrapped_dek` - The wrapped (encrypted) DEK
    /// * `flags` - Encryption flags
    /// * `nonce` - Random nonce for AEAD encryption
    #[must_use]
    pub fn new(
        kek_id: impl Into<String>,
        wrapped_dek: Vec<u8>,
        flags: HeaderFlags,
        nonce: Vec<u8>,
    ) -> Self {
        Self { version: PROTOCOL_VERSION, kek_id: kek_id.into(), wrapped_dek, flags, nonce }
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns the KEK identifier.
    #[must_use]
    pub fn kek_id(&self) -> &str {
        &self.kek_id
    }

    /// Returns the wrapped DEK.
    #[must_use]
    pub fn wrapped_dek(&self) -> &[u8] {
        &self.wrapped_dek
    }

    /// Returns the header flags.
    #[must_use]
    pub const fn flags(&self) -> HeaderFlags {
        self.flags
    }

    /// Returns the nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Serializes the header to bytes.
    ///
    /// # Errors
    ///
    /// Returns error if the KEK ID is too long (> 255 bytes) or if
    /// the wrapped DEK is too long (> 65535 bytes).
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        // Validate lengths
        if self.kek_id.len() > 255 {
            return Err(Error::InvalidHeader(format!(
                "KEK ID too long: {} bytes (max: 255)",
                self.kek_id.len()
            )));
        }

        if self.wrapped_dek.len() > 65535 {
            return Err(Error::InvalidHeader(format!(
                "Wrapped DEK too long: {} bytes (max: 65535)",
                self.wrapped_dek.len()
            )));
        }

        if self.nonce.len() > 255 {
            return Err(Error::InvalidHeader(format!(
                "Nonce too long: {} bytes (max: 255)",
                self.nonce.len()
            )));
        }

        let mut bytes = Vec::new();

        // Version (1 byte)
        bytes.push(self.version);

        // KEK ID length (1 byte) + KEK ID
        // Safe cast: length validated above (line 124-128, max 255)
        #[allow(clippy::cast_possible_truncation)]
        let kek_id_len = self.kek_id.len() as u8;
        bytes.push(kek_id_len);
        bytes.extend_from_slice(self.kek_id.as_bytes());

        // Wrapped DEK length (2 bytes, big-endian) + wrapped DEK
        // Safe cast: length validated above (line 130-135, max 65535)
        #[allow(clippy::cast_possible_truncation)]
        let wrapped_dek_len = self.wrapped_dek.len() as u16;
        bytes.extend_from_slice(&wrapped_dek_len.to_be_bytes());
        bytes.extend_from_slice(&self.wrapped_dek);

        // Flags (1 byte)
        bytes.push(self.flags.as_u8());

        // Nonce length (1 byte) + nonce
        // Safe cast: length validated above (line 137-142, max 255)
        #[allow(clippy::cast_possible_truncation)]
        let nonce_len = self.nonce.len() as u8;
        bytes.push(nonce_len);
        bytes.extend_from_slice(&self.nonce);

        Ok(bytes)
    }

    /// Deserializes a header from bytes.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - The data is too short
    /// - The version is not supported
    /// - The data is malformed
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.is_empty() {
            return Err(Error::InvalidHeader("Empty header data".to_string()));
        }

        let mut pos = 0;

        // Version
        let version = data[pos];
        pos += 1;

        if version != PROTOCOL_VERSION {
            return Err(Error::UnsupportedVersion {
                version,
                supported: PROTOCOL_VERSION.to_string(),
            });
        }

        // KEK ID
        if pos >= data.len() {
            return Err(Error::InvalidHeader("Missing KEK ID length".to_string()));
        }
        let kek_id_len = data[pos] as usize;
        pos += 1;

        if pos + kek_id_len > data.len() {
            return Err(Error::InvalidHeader("KEK ID truncated".to_string()));
        }
        let kek_id = String::from_utf8(data[pos..pos + kek_id_len].to_vec())
            .map_err(|e| Error::InvalidHeader(format!("Invalid KEK ID UTF-8: {e}")))?;
        pos += kek_id_len;

        // Wrapped DEK
        if pos + 2 > data.len() {
            return Err(Error::InvalidHeader("Missing wrapped DEK length".to_string()));
        }
        let wrapped_dek_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + wrapped_dek_len > data.len() {
            return Err(Error::InvalidHeader("Wrapped DEK truncated".to_string()));
        }
        let wrapped_dek = data[pos..pos + wrapped_dek_len].to_vec();
        pos += wrapped_dek_len;

        // Flags
        if pos >= data.len() {
            return Err(Error::InvalidHeader("Missing flags".to_string()));
        }
        let flags = HeaderFlags::from_u8(data[pos]);
        pos += 1;

        // Nonce
        if pos >= data.len() {
            return Err(Error::InvalidHeader("Missing nonce length".to_string()));
        }
        let nonce_len = data[pos] as usize;
        pos += 1;

        if pos + nonce_len > data.len() {
            return Err(Error::InvalidHeader("Nonce truncated".to_string()));
        }
        let nonce = data[pos..pos + nonce_len].to_vec();
        pos += nonce_len;

        let header = Self { version, kek_id, wrapped_dek, flags, nonce };

        Ok((header, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_flags() {
        let flags = HeaderFlags::empty();
        assert!(!flags.is_deterministic());
        assert_eq!(flags.as_u8(), 0);

        let flags = flags.with_deterministic();
        assert!(flags.is_deterministic());
        assert_eq!(flags.as_u8(), 1);
    }

    #[test]
    fn test_header_serialization() {
        let header = EncryptionHeader::new(
            "kek_v1",
            vec![1, 2, 3, 4],
            HeaderFlags::empty(),
            vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        );

        let bytes = header.to_bytes().expect("Failed to serialize header");
        let (parsed, pos) = EncryptionHeader::from_bytes(&bytes).expect("Failed to parse header");

        assert_eq!(parsed, header);
        assert_eq!(pos, bytes.len());
    }

    #[test]
    fn test_header_with_deterministic_flag() {
        let header = EncryptionHeader::new(
            "kek_v2",
            vec![10, 20, 30],
            HeaderFlags::empty().with_deterministic(),
            vec![1; 12],
        );

        let bytes = header.to_bytes().unwrap();
        let (parsed, _) = EncryptionHeader::from_bytes(&bytes).unwrap();

        assert!(parsed.flags().is_deterministic());
        assert_eq!(parsed.kek_id(), "kek_v2");
        assert_eq!(parsed.wrapped_dek(), &[10, 20, 30]);
        assert_eq!(parsed.nonce(), &[1; 12]);
    }

    #[test]
    fn test_header_unsupported_version() {
        let mut bytes = vec![99]; // Unsupported version
        bytes.extend_from_slice(&[6]); // kek_id_len
        bytes.extend_from_slice(b"kek_v1");
        bytes.extend_from_slice(&[0, 4]); // wrapped_dek_len
        bytes.extend_from_slice(&[1, 2, 3, 4]);
        bytes.push(0); // flags
        bytes.push(12); // nonce_len
        bytes.extend_from_slice(&[0; 12]);

        let result = EncryptionHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(Error::UnsupportedVersion { .. })));
    }

    #[test]
    fn test_header_truncated_data() {
        let bytes = vec![1, 6]; // Only version and kek_id_len
        let result = EncryptionHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(Error::InvalidHeader(_))));
    }

    #[test]
    fn test_header_empty_data() {
        let result = EncryptionHeader::from_bytes(&[]);
        assert!(matches!(result, Err(Error::InvalidHeader(_))));
    }

    #[test]
    fn test_header_kek_id_too_long() {
        let long_kek_id = "k".repeat(256);
        let header =
            EncryptionHeader::new(long_kek_id, vec![1, 2, 3], HeaderFlags::empty(), vec![0; 12]);

        let result = header.to_bytes();
        assert!(matches!(result, Err(Error::InvalidHeader(_))));
    }

    #[test]
    fn test_header_round_trip_with_long_data() {
        let header = EncryptionHeader::new(
            "kek_v123",
            vec![42; 100],
            HeaderFlags::empty().with_deterministic(),
            vec![7; 16],
        );

        let bytes = header.to_bytes().expect("Serialization failed");
        let (parsed, pos) = EncryptionHeader::from_bytes(&bytes).expect("Parsing failed");

        assert_eq!(parsed.version(), PROTOCOL_VERSION);
        assert_eq!(parsed.kek_id(), "kek_v123");
        assert_eq!(parsed.wrapped_dek(), &vec![42; 100]);
        assert!(parsed.flags().is_deterministic());
        assert_eq!(parsed.nonce(), &vec![7; 16]);
        assert_eq!(pos, bytes.len());
    }
}
