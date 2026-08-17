use domain_auth::DomainError;

use crate::error::HttpError;
use crate::validation::*;

#[test]
fn test_validate_text_valid() {
    let result = validate_text("valid text", "Field");
    assert!(result.is_ok());
}

#[test]
fn test_validate_text_with_whitespace() {
    let result = validate_text("  valid text  ", "Field");
    assert!(result.is_ok());
}

#[test]
fn test_validate_text_empty() {
    let result = validate_text("", "Field");
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Field cannot be empty");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_validate_text_only_whitespace() {
    let result = validate_text("   ", "Field");
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Field cannot be empty");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_decode_credential_id_roundtrip() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let raw: Vec<u8> = (0u8..=31).collect();
    let encoded = URL_SAFE_NO_PAD.encode(&raw);
    assert_eq!(decode_credential_id(&encoded).unwrap(), raw);
}

#[test]
fn test_decode_credential_id_rejects_padded_standard_base64() {
    // Standard base64 uses '+' and '/' which are illegal in URLs; the
    // decoder must refuse them rather than silently misdecode.
    assert!(decode_credential_id("AQIDBA==").is_err());
}

#[test]
fn test_decode_credential_id_rejects_garbage() {
    assert!(decode_credential_id("!!!not-base64!!!").is_err());
    assert!(decode_credential_id("").is_err());
}

#[test]
fn test_validate_credential_name_valid() {
    assert!(validate_credential_name("iPhone 15").is_ok());
    assert!(validate_credential_name("MacBook Pro (work)").is_ok());
}

#[test]
fn test_validate_credential_name_rejects_empty() {
    assert!(validate_credential_name("").is_err());
    assert!(validate_credential_name("   ").is_err());
}

#[test]
fn test_validate_credential_name_rejects_too_long() {
    let long = "x".repeat(65);
    assert!(validate_credential_name(&long).is_err());
}

#[test]
fn test_validate_credential_name_accepts_max_length() {
    let max = "x".repeat(64);
    assert!(validate_credential_name(&max).is_ok());
}

#[test]
fn test_validate_username_valid() {
    let result = validate_username("john_doe");
    assert!(result.is_ok());
}

#[test]
fn test_validate_username_valid_minimum_length() {
    let result = validate_username("abc");
    assert!(result.is_ok());
}

#[test]
fn test_validate_username_too_short() {
    let result = validate_username("ab");
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Username must be at least 3 characters");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_validate_username_empty() {
    let result = validate_username("");
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Username cannot be empty");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_validate_username_only_whitespace() {
    let result = validate_username("   ");
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Username cannot be empty");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_validate_username_three_chars_with_spaces() {
    let result = validate_username("  a  ");
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Username must be at least 3 characters");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_validate_json_credentials_valid_object() {
    let credentials = serde_json::json!({
        "id": "test_id",
        "type": "public-key"
    });
    let result = validate_json_credentials(&credentials);
    assert!(result.is_ok());
}

#[test]
fn test_validate_json_credentials_null() {
    let credentials = serde_json::json!(null);
    let result = validate_json_credentials(&credentials);
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Invalid credentials");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_validate_json_credentials_not_object() {
    let credentials = serde_json::json!("string_value");
    let result = validate_json_credentials(&credentials);
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Invalid credentials");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_validate_json_credentials_array() {
    let credentials = serde_json::json!([1, 2, 3]);
    let result = validate_json_credentials(&credentials);
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Invalid credentials");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_validate_json_credentials_empty_object() {
    let credentials = serde_json::json!({});
    let result = validate_json_credentials(&credentials);
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Invalid credentials");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_validate_json_credentials_number() {
    let credentials = serde_json::json!(42);
    let result = validate_json_credentials(&credentials);
    assert!(result.is_err());
}

#[test]
fn test_validate_json_credentials_boolean() {
    let credentials = serde_json::json!(true);
    let result = validate_json_credentials(&credentials);
    assert!(result.is_err());
}
