use crate::{app::AppError, utils::validation::*};

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
        Err(AppError::BadRequest(msg)) => {
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
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(msg, "Field cannot be empty");
        }
        _ => panic!("Expected BadRequest error"),
    }
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
        Err(AppError::BadRequest(msg)) => {
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
        Err(AppError::BadRequest(msg)) => {
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
        Err(AppError::BadRequest(msg)) => {
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
        Err(AppError::BadRequest(msg)) => {
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
        Err(AppError::BadRequest(msg)) => {
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
        Err(AppError::BadRequest(msg)) => {
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
        Err(AppError::BadRequest(msg)) => {
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
        Err(AppError::BadRequest(msg)) => {
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
