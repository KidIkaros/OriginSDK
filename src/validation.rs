// SPDX-License-Identifier: OPL-1.1

//! Input validation for domain strings, info strings, and identifiers.
//!
//! Used by the identity layer to ensure domain strings are well-formed
//! before key derivation.

/// Validate an info/domain string for key derivation.
///
/// Rules:
/// - Non-empty
/// - Length between 1 and 255 characters
/// - Only printable ASCII characters (no control chars)
/// - No leading/trailing whitespace
///
/// Returns Ok(()) if valid, Err(reason) if invalid.
pub fn validate_info_string(info: &str) -> Result<(), String> {
    if info.is_empty() {
        return Err("Info string is empty".to_string());
    }

    if info.len() > 255 {
        return Err(format!(
            "Info string too long: {} chars (max 255)",
            info.len()
        ));
    }

    if info != info.trim() {
        return Err("Info string has leading or trailing whitespace".to_string());
    }

    for (i, ch) in info.char_indices() {
        if !ch.is_ascii_graphic() && ch != ' ' {
            return Err(format!(
                "Invalid character '{}' at position {} (only printable ASCII allowed)",
                ch, i
            ));
        }
    }

    Ok(())
}

/// Validate a DID string format.
///
/// Expected format: did:origin:<identifier>
/// where identifier is alphanumeric + hyphens, 1-64 chars.
pub fn validate_did(did: &str) -> Result<(), String> {
    if !did.starts_with("did:origin:") {
        return Err("DID must start with 'did:origin:'".to_string());
    }

    let identifier = &did[11..];
    if identifier.is_empty() || identifier.len() > 64 {
        return Err(format!(
            "DID identifier length {} invalid (must be 1-64)",
            identifier.len()
        ));
    }

    for ch in identifier.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
            return Err(format!(
                "Invalid character '{}' in DID identifier (only alphanumeric, -, _)",
                ch
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_info_string_valid() {
        assert!(validate_info_string("signing").is_ok());
        assert!(validate_info_string("did:origin:abc123").is_ok());
        assert!(validate_info_string("my-domain.com").is_ok());
    }

    #[test]
    fn test_validate_info_string_empty() {
        assert!(validate_info_string("").is_err());
    }

    #[test]
    fn test_validate_info_string_too_long() {
        let long = "a".repeat(256);
        assert!(validate_info_string(&long).is_err());
    }

    #[test]
    fn test_validate_info_string_whitespace() {
        assert!(validate_info_string(" hello").is_err());
        assert!(validate_info_string("hello ").is_err());
    }

    #[test]
    fn test_validate_info_string_control_chars() {
        assert!(validate_info_string("hello\tworld").is_err());
        assert!(validate_info_string("hello\nworld").is_err());
    }

    #[test]
    fn test_validate_did_valid() {
        assert!(validate_did("did:origin:abc123").is_ok());
        assert!(validate_did("did:origin:my-identity").is_ok());
        assert!(validate_did("did:origin:a").is_ok());
    }

    #[test]
    fn test_validate_did_invalid() {
        assert!(validate_did("did:other:abc").is_err());
        assert!(validate_did("did:origin:").is_err());
        assert!(validate_did("did:origin:abc!def").is_err());
        assert!(validate_did(&format!("did:origin:{}", "a".repeat(65))).is_err());
    }
}
