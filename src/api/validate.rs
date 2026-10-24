//! Input validation shared by the API handlers.

use passbox_core::encoding;
use passbox_core::id::is_valid_id;
use passbox_core::kdf::{KdfParams, SALT_LEN};

use crate::error::{ApiError, ApiResult};

/// Upper bound for a single encrypted item (Base64url characters).
pub const MAX_ITEM_LEN: usize = 512 * 1024;
/// Upper bound for keys, metadata and protocol messages.
pub const MAX_SMALL_LEN: usize = 16 * 1024;

/// Normalizes an email address (trimmed, lowercase) and checks its basic shape.
pub fn email(input: &str) -> ApiResult<String> {
    let email = input.trim().to_lowercase();
    let valid = email.len() <= 254
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
        })
        && !email.chars().any(char::is_whitespace);
    if valid {
        Ok(email)
    } else {
        Err(ApiError::bad_request("invalid email address"))
    }
}

pub fn id(field: &str, value: &str) -> ApiResult<()> {
    if is_valid_id(value) {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!("invalid {field}")))
    }
}

/// Checks that `value` is Base64url of at most `max_len` characters and returns the bytes.
pub fn base64(field: &str, value: &str, max_len: usize) -> ApiResult<Vec<u8>> {
    if value.is_empty() || value.len() > max_len {
        return Err(ApiError::bad_request(format!(
            "{field} has an invalid length"
        )));
    }
    encoding::decode(value)
        .map_err(|_| ApiError::bad_request(format!("{field} is not valid Base64url")))
}

pub fn kdf(salt: &str, params: &KdfParams) -> ApiResult<()> {
    if base64("kdfSalt", salt, 64)?.len() != SALT_LEN {
        return Err(ApiError::bad_request("kdfSalt must be 16 bytes"));
    }
    params
        .ensure_minimum()
        .map_err(|_| ApiError::bad_request("kdfParams are below the minimum"))?;
    // Upper bounds keep clients from being locked out by absurd parameters.
    if params.memory_kib > 4 * 1024 * 1024 || params.iterations > 64 || params.parallelism > 64 {
        return Err(ApiError::bad_request("kdfParams are too large"));
    }
    Ok(())
}

pub fn revision(value: i64) -> ApiResult<()> {
    if value >= 1 {
        Ok(())
    } else {
        Err(ApiError::bad_request("revision must be at least 1"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_normalized() {
        assert_eq!(email("  Jane@Example.COM ").unwrap(), "jane@example.com");
        for bad in [
            "",
            "jane",
            "@example.com",
            "jane@localhost",
            "ja ne@example.com",
            "jane@.com",
        ] {
            assert!(email(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn kdf_bounds() {
        let salt = encoding::encode(&[0; 16]);
        assert!(kdf(&salt, &KdfParams::DEFAULT).is_ok());
        assert!(kdf(&encoding::encode(&[0; 8]), &KdfParams::DEFAULT).is_err());
        let weak = KdfParams {
            memory_kib: 1024,
            ..KdfParams::DEFAULT
        };
        assert!(kdf(&salt, &weak).is_err());
    }
}
