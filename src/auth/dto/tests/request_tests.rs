use crate::{
    app::AppError,
    auth::dto::{BeginRequest, FinishRequest},
    utils::Validatable,
};

#[test]
fn test_begin_request_valid() {
    let request = BeginRequest {
        username: "john_doe".to_string(),
        role: Some("admin".to_string()),
    };
    let result = request.validate();
    assert!(result.is_ok());
}

#[test]
fn test_begin_request_valid_without_role() {
    let request = BeginRequest {
        username: "john_doe".to_string(),
        role: None,
    };
    let result = request.validate();
    assert!(result.is_ok());
}

#[test]
fn test_begin_request_valid_minimum_username() {
    let request = BeginRequest {
        username: "abc".to_string(),
        role: None,
    };
    let result = request.validate();
    assert!(result.is_ok());
}

#[test]
fn test_begin_request_username_too_short() {
    let request = BeginRequest {
        username: "ab".to_string(),
        role: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(msg, "Username must be at least 3 characters");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_begin_request_username_empty() {
    let request = BeginRequest {
        username: String::new(),
        role: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(msg, "Username cannot be empty");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_begin_request_username_only_whitespace() {
    let request = BeginRequest {
        username: "   ".to_string(),
        role: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(msg, "Username cannot be empty");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_finish_request_valid() {
    let credentials = serde_json::json!({
        "id": "AQIDBAUGBwgJCgsMDQ4PEA",
        "rawId": "AQIDBAUGBwgJCgsMDQ4PEA",
        "type": "public-key"
    });

    let request = FinishRequest {
        username: "john_doe".to_string(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        credentials,
    };

    let result = request.validate();
    assert!(result.is_ok());
}

#[test]
fn test_finish_request_username_empty() {
    let credentials = serde_json::json!({
        "id": "test_id",
        "type": "public-key"
    });

    let request = FinishRequest {
        username: String::new(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        credentials,
    };

    let result = request.validate();
    assert!(result.is_err());
}

#[test]
fn test_finish_request_username_too_short() {
    let credentials = serde_json::json!({
        "id": "test_id",
        "type": "public-key"
    });

    let request = FinishRequest {
        username: "ab".to_string(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        credentials,
    };

    let result = request.validate();
    assert!(result.is_err());
}

#[test]
fn test_finish_request_session_id_empty() {
    let credentials = serde_json::json!({
        "id": "test_id",
        "type": "public-key"
    });

    let request = FinishRequest {
        username: "john_doe".to_string(),
        session_id: String::new(),
        credentials,
    };

    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(msg, "Session ID cannot be empty");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_finish_request_session_id_whitespace() {
    let credentials = serde_json::json!({
        "id": "test_id",
        "type": "public-key"
    });

    let request = FinishRequest {
        username: "john_doe".to_string(),
        session_id: "   ".to_string(),
        credentials,
    };

    let result = request.validate();
    assert!(result.is_err());
}

#[test]
fn test_finish_request_credentials_null() {
    let request = FinishRequest {
        username: "john_doe".to_string(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        credentials: serde_json::json!(null),
    };

    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(msg, "Invalid credentials");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_finish_request_credentials_not_object() {
    let request = FinishRequest {
        username: "john_doe".to_string(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        credentials: serde_json::json!("not_an_object"),
    };

    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(msg, "Invalid credentials");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_finish_request_credentials_empty_object() {
    let request = FinishRequest {
        username: "john_doe".to_string(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        credentials: serde_json::json!({}),
    };

    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(msg, "Invalid credentials");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_finish_request_credentials_array() {
    let request = FinishRequest {
        username: "john_doe".to_string(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        credentials: serde_json::json!([1, 2, 3]),
    };

    let result = request.validate();
    assert!(result.is_err());
}

#[test]
fn test_finish_request_all_fields_invalid() {
    let request = FinishRequest {
        username: String::new(),
        session_id: String::new(),
        credentials: serde_json::json!(null),
    };

    let result = request.validate();
    assert!(result.is_err());
}
