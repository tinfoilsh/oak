//
// Copyright 2025 The Project Oak Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! ACPI table integrity verification against cmdline-specified hash.
//!
//! This module provides functionality to verify that the ACPI tables generated
//! by the VMM match an expected hash specified in the kernel command line.

/// Extracts the `acpi_hash=<hex>` parameter from the kernel command line.
///
/// Returns `Some([u8; 32])` if a valid 64-character hex hash is found,
/// `None` otherwise.
pub fn extract_acpi_hash(cmdline: &str) -> Option<[u8; 32]> {
    for param in cmdline.split_whitespace() {
        if let Some(hash_hex) = param.strip_prefix("acpi_hash=") {
            // Validate length: SHA-256 is 32 bytes = 64 hex characters
            if hash_hex.len() != 64 {
                log::warn!(
                    "acpi_hash parameter has invalid length: {} (expected 64)",
                    hash_hex.len()
                );
                return None;
            }

            let mut hash = [0u8; 32];
            for (i, chunk) in hash_hex.as_bytes().chunks(2).enumerate() {
                let hex_str = match core::str::from_utf8(chunk) {
                    Ok(s) => s,
                    Err(_) => {
                        log::warn!("acpi_hash parameter contains invalid UTF-8");
                        return None;
                    }
                };

                match u8::from_str_radix(hex_str, 16) {
                    Ok(byte) => hash[i] = byte,
                    Err(_) => {
                        log::warn!("acpi_hash parameter contains invalid hex: {}", hex_str);
                        return None;
                    }
                }
            }
            return Some(hash);
        }
    }
    None
}

/// Verifies that the computed ACPI digest matches the expected hash from cmdline.
///
/// # Behavior
/// - If no `acpi_hash` parameter is specified: logs a debug message and returns
///   (backwards compatibility mode)
/// - If `acpi_hash` matches computed digest: logs success and returns
/// - If `acpi_hash` doesn't match: **panics** (security violation - possible VMM tampering)
///
/// # Arguments
/// * `cmdline` - The kernel command line string
/// * `computed_digest` - The SHA-256 digest computed from ACPI tables
pub fn verify_acpi_hash(cmdline: &str, computed_digest: &[u8; 32]) {
    match extract_acpi_hash(cmdline) {
        Some(expected_hash) => {
            if expected_hash != *computed_digest {
                log::error!(
                    "ACPI hash mismatch! Expected: {}, Computed: {}",
                    hex::encode(expected_hash),
                    hex::encode(computed_digest)
                );
                panic!("ACPI table integrity check failed - possible VMM tampering");
            }
            log::info!(
                "ACPI hash verification passed: {}",
                hex::encode(computed_digest)
            );
        }
        None => {
            log::debug!("No acpi_hash parameter in cmdline, skipping ACPI verification");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_acpi_hash_valid() {
        let cmdline = "root=/dev/sda acpi_hash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef quiet";
        let hash = extract_acpi_hash(cmdline);
        assert!(hash.is_some());
        let hash = hash.unwrap();
        assert_eq!(hash[0], 0x01);
        assert_eq!(hash[1], 0x23);
        assert_eq!(hash[31], 0xef);
    }

    #[test]
    fn test_extract_acpi_hash_missing() {
        let cmdline = "root=/dev/sda quiet";
        assert!(extract_acpi_hash(cmdline).is_none());
    }

    #[test]
    fn test_extract_acpi_hash_wrong_length() {
        let cmdline = "acpi_hash=0123456789abcdef";
        assert!(extract_acpi_hash(cmdline).is_none());
    }

    #[test]
    fn test_extract_acpi_hash_invalid_hex() {
        let cmdline = "acpi_hash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcXYZ";
        assert!(extract_acpi_hash(cmdline).is_none());
    }

    #[test]
    fn test_verify_acpi_hash_match() {
        let cmdline = "acpi_hash=0000000000000000000000000000000000000000000000000000000000000000";
        let digest = [0u8; 32];
        // Should not panic
        verify_acpi_hash(cmdline, &digest);
    }

    #[test]
    fn test_verify_acpi_hash_no_param() {
        let cmdline = "root=/dev/sda";
        let digest = [0u8; 32];
        // Should not panic - backwards compatibility
        verify_acpi_hash(cmdline, &digest);
    }

    #[test]
    #[should_panic(expected = "ACPI table integrity check failed")]
    fn test_verify_acpi_hash_mismatch() {
        let cmdline = "acpi_hash=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let digest = [0u8; 32];
        verify_acpi_hash(cmdline, &digest);
    }
}

