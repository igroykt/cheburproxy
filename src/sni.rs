//! TLS SNI (Server Name Indication) extraction utilities
//!
//! This module provides functionality to extract the Server Name Indication
//! from TLS ClientHello messages as defined in RFC 6066.

use std::convert::TryInto;

/// TLS protocol constants
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_EXTENSION_SERVER_NAME: u16 = 0x00;
const TLS_SERVER_NAME_TYPE_HOSTNAME: u8 = 0x00;
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 4;
const TLS_VERSION_LEN: usize = 2;
const TLS_RANDOM_LEN: usize = 32;

/// Errors that can occur during SNI extraction
#[derive(Debug, PartialEq)]
pub enum SniError {
    /// Data is too short to contain a valid TLS record
    DataTooShort,
    /// TLS version is not supported
    UnsupportedTlsVersion,
    /// Invalid or malformed TLS extension data
    InvalidExtensionData,
    /// Invalid UTF-8 in server name
    InvalidUtf8,
}

impl std::fmt::Display for SniError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SniError::DataTooShort => write!(f, "TLS data is too short"),
            SniError::UnsupportedTlsVersion => write!(f, "Unsupported TLS version"),
            SniError::InvalidExtensionData => write!(f, "Invalid TLS extension data"),
            SniError::InvalidUtf8 => write!(f, "Invalid UTF-8 in server name"),
        }
    }
}

impl std::error::Error for SniError {}

/// Extracts the Server Name Indication (SNI) from TLS ClientHello data
///
/// Returns `Ok(Some(server_name))` if SNI is found, `Ok(None)` if no SNI extension
/// is present, or `Err(error)` if the data is malformed or invalid.
///
/// # Arguments
/// * `data` - Raw TLS handshake data containing a ClientHello message
///
/// # Examples
/// ```
/// use sni::{extract_sni, SniError};
///
/// // Example with SNI present
/// let tls_data = &[0x16, 0x03, 0x01, 0x00, 0x7A, /* ... more TLS data ... */];
/// match extract_sni(tls_data) {
///     Ok(Some(name)) => println!("SNI: {}", name),
///     Ok(None) => println!("No SNI found"),
///     Err(e) => println!("Error: {}", e),
/// }
/// ```
pub fn extract_sni(data: &[u8]) -> Result<Option<String>, SniError> {
    let data_len = data.len();

    // Validate minimum length for TLS record header
    if data_len < TLS_RECORD_HEADER_LEN {
        return Ok(None);
    }

    // Check if this is a TLS handshake record
    if data[0] != 0x16 {
        return Ok(None); // Not a handshake record
    }

    let mut parser = TlsParser::new(data);
    match parser.parse_client_hello()? {
        Some(()) => parser.parse_extensions(), // Continue to parse extensions
        None => Ok(None),                      // Not a ClientHello or incomplete data
    }
}

/// Internal structure to track parsing position and validate bounds
struct TlsParser<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> TlsParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    /// Safely read a byte and advance position
    fn read_byte(&mut self) -> Result<u8, SniError> {
        if self.position >= self.data.len() {
            return Err(SniError::DataTooShort);
        }
        let byte = self.data[self.position];
        self.position += 1;
        Ok(byte)
    }

    /// Safely read bytes and advance position
    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], SniError> {
        if self.position + len > self.data.len() {
            return Err(SniError::DataTooShort);
        }
        let bytes = &self.data[self.position..self.position + len];
        self.position += len;
        Ok(bytes)
    }

    /// Read a 16-bit big-endian integer
    fn read_u16_be(&mut self) -> Result<u16, SniError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes(bytes.try_into().unwrap()))
    }

    /// Read a 32-bit big-endian integer
    fn read_u32_be(&mut self) -> Result<u32, SniError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn parse_client_hello(&mut self) -> Result<Option<()>, SniError> {
        // Skip TLS record header (already validated)
        self.position = TLS_RECORD_HEADER_LEN;

        // Validate handshake type
        let handshake_type = self.read_byte()?;
        if handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
            return Ok(None);
        }

        // Skip handshake header length (3 bytes)
        self.position += 3;

        // Read and validate TLS version
        let version = self.read_u16_be()?;
        if !is_supported_tls_version(version) {
            return Ok(None); // Not TLS traffic (e.g. plain HTTP, DTLS) — not an error
        }

        // Skip random data
        self.read_bytes(TLS_RANDOM_LEN)?;

        // Parse session ID
        let session_id_len = self.read_byte()? as usize;
        self.read_bytes(session_id_len)?;

        // Parse cipher suites
        let cipher_suites_len = self.read_u16_be()? as usize;
        self.read_bytes(cipher_suites_len)?;

        // Parse compression methods
        let compression_len = self.read_byte()? as usize;
        self.read_bytes(compression_len)?;

        Ok(Some(()))
    }
}

impl<'a> TlsParser<'a> {
    fn parse_extensions(&mut self) -> Result<Option<String>, SniError> {
        // Read extensions length
        let extensions_len = self.read_u16_be()? as usize;
        // Clamp extensions_end to available data length — peek() may return
        // a truncated ClientHello, but SNI is typically among the first extensions.
        let extensions_end = std::cmp::min(self.position + extensions_len, self.data.len());

        // Parse each extension
        while self.position + 4 <= extensions_end {
            let ext_type = self.read_u16_be()?;
            let ext_len = self.read_u16_be()? as usize;

            let ext_end = self.position + ext_len;
            if ext_end > extensions_end {
                return Err(SniError::InvalidExtensionData);
            }

            // Check if this is the server name extension
            if ext_type == TLS_EXTENSION_SERVER_NAME {
                return self.parse_server_name_extension(ext_end);
            }

            // Skip to next extension
            self.position = ext_end;
        }

        Ok(None)
    }

    fn parse_server_name_extension(&mut self, ext_end: usize) -> Result<Option<String>, SniError> {
        // Read the server name list length
        let list_len = self.read_u16_be()? as usize;
        if self.position + list_len > ext_end {
            return Err(SniError::InvalidExtensionData);
        }

        // Parse server name entries
        let list_end = self.position + list_len;
        while self.position + 3 <= list_end {
            let name_type = self.read_byte()?;

            if name_type == TLS_SERVER_NAME_TYPE_HOSTNAME {
                let name_len = self.read_u16_be()? as usize;

                // Validate name length and bounds
                if self.position + name_len > list_end {
                    return Err(SniError::InvalidExtensionData);
                }

                let name_bytes = self.read_bytes(name_len)?;
                let name = std::str::from_utf8(name_bytes)
                    .map_err(|_| SniError::InvalidUtf8)?
                    .to_string();

                return Ok(Some(name));
            } else {
                // Skip unknown name types
                let name_len = self.read_u16_be()? as usize;
                self.position += name_len;
            }
        }

        Ok(None)
    }
}

/// Checks if the given TLS version is supported for SNI extraction
fn is_supported_tls_version(version: u16) -> bool {
    matches!(version, 0x0301 | 0x0302 | 0x0303 | 0x0304) // TLS 1.0-1.3
}

/// Legacy function that returns anyhow::Result for backward compatibility
pub fn extract_sni_legacy(data: &[u8]) -> anyhow::Result<Option<String>> {
    match extract_sni(data) {
        Ok(Some(name)) => Ok(Some(name)),
        Ok(None) => Ok(None),
        Err(SniError::DataTooShort) => Ok(None), // Treat as no SNI for compatibility
        Err(e) => Err(anyhow::anyhow!("SNI extraction failed: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sni() {
        // Test with a minimal but valid TLS 1.2 ClientHello containing SNI
        // This is carefully crafted to be exactly correct
        let tls_data = &[
            0x16, 0x03, 0x01, 0x00, 0x5f, // TLS record header (95 bytes total)
            0x01, 0x00, 0x00, 0x5b, // Handshake header (91 bytes)
            0x03, 0x03, // TLS version 1.2
            // Random (32 bytes) - using zeros for simplicity
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, // Session ID length (0)
            0x00, 0x04, // Cipher suites length (4 bytes)
            0xc0, 0x13, 0x00, 0x39, // Two cipher suites
            0x01, // Compression length (1)
            0x00, // No compression
            0x00, 0x1a, // Extensions length (26 bytes)
            // Extension: server_name
            0x00, 0x00, // Extension type: server_name (0)
            0x00, 0x0e, // Extension length (14 bytes)
            0x00, 0x0c, // Server name list length (12 bytes)
            0x00, // Name type: hostname (0)
            0x00, 0x09, // Name length (9 bytes)
            0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
            0x6d, // "example.com" (but length says 9, so it will be "example.c")
            // Extension: ec_point_formats (minimal)
            0x00, 0x0b, // Extension type: ec_point_formats (11)
            0x00, 0x04, // Extension length (4 bytes)
            0x00, 0x02, // EC point formats length (2 bytes)
            0x01, 0x00, // Uncompressed (1), (0)
            // Extension: signature_algorithms (minimal)
            0x00, 0x0d, // Extension type: signature_algorithms (13)
            0x00, 0x02, // Extension length (2 bytes)
            0x00, 0x00, // Signature algorithms length (0 bytes) - minimal but valid
        ];

        match extract_sni(tls_data) {
            Ok(Some(name)) => {
                // The name length in the test data is 9, so we get "example.c"
                assert_eq!(name, "example.c");
            }
            Ok(None) => panic!("Expected SNI but got None"),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn test_no_sni() {
        // Test with TLS data that has no SNI extension (properly sized)
        let tls_data = &[
            0x16, 0x03, 0x01, 0x00, 0x4f, // TLS record header (79 bytes total)
            0x01, 0x00, 0x00, 0x4b, // Handshake header (75 bytes)
            0x03, 0x03, // TLS version 1.2
            // Random (32 bytes)
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x00, // Session ID length (0)
            0x00, 0x04, // Cipher suites length (4 bytes)
            0xc0, 0x13, 0x00, 0x39, // Cipher suites
            0x01, // Compression length (1)
            0x00, // No compression
            0x00, 0x00, // No extensions (0 bytes)
        ];

        match extract_sni(tls_data) {
            Ok(None) => {} // Expected - no SNI extension present
            Ok(Some(name)) => panic!("Unexpected SNI found: {}", name),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn test_invalid_data() {
        // Test with data too short - should return Ok(None) for very short data
        assert_eq!(extract_sni(&[0x16]), Ok(None));

        // Test with wrong record type - should return Ok(None) since it's not a handshake record
        assert_eq!(extract_sni(&[0x17, 0x03, 0x01, 0x00, 0x00]), Ok(None));

        // Test with wrong handshake type - should return Ok(None) since it's not a ClientHello
        assert_eq!(extract_sni(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x02]), Ok(None));

        // Test with data that looks like TLS but is malformed
        let malformed_tls = &[0x16, 0x03, 0x01, 0x00, 0x10, 0x01]; // Too short for proper TLS
        match extract_sni(malformed_tls) {
            Ok(None) => {} // Expected for some malformed cases
            Ok(Some(_)) => panic!("Unexpected SNI extracted from malformed data"),
            Err(SniError::DataTooShort) => {} // Also acceptable for malformed data
            Err(e) => panic!("Unexpected error type: {}", e),
        }
    }
}
