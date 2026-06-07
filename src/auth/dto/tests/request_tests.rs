use crate::{
    app::AppError,
    auth::dto::{BeginRequest, FinishRequest},
    utils::Validatable,
};

#[test]
fn test_begin_request_valid() {
    let request = BeginRequest {
        username: "john_doe".into(),
        role: Some("admin".into()),
    };
    let result = request.validate();
    assert!(result.is_ok());
}

#[test]
fn test_begin_request_valid_without_role() {
    let request = BeginRequest {
        username: "john_doe".into(),
        role: None,
    };
    let result = request.validate();
    assert!(result.is_ok());
}

#[test]
fn test_begin_request_valid_minimum_username() {
    let request = BeginRequest {
        username: "abc".into(),
        role: None,
    };
    let result = request.validate();
    assert!(result.is_ok());
}

#[test]
fn test_begin_request_username_too_short() {
    let request = BeginRequest {
        username: "ab".into(),
        role: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(&*msg, "Username must be at least 3 characters");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_begin_request_username_empty() {
    let request = BeginRequest {
        username: "".into(),
        role: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(&*msg, "Username cannot be empty");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_begin_request_username_only_whitespace() {
    let request = BeginRequest {
        username: "   ".into(),
        role: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(&*msg, "Username cannot be empty");
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
        username: "john_doe".into(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
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
        username: "".into(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
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
        username: "ab".into(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
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
        username: "john_doe".into(),
        session_id: "".into(),
        credentials,
    };

    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(&*msg, "Session ID cannot be empty");
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
        username: "john_doe".into(),
        session_id: "   ".into(),
        credentials,
    };

    let result = request.validate();
    assert!(result.is_err());
}

#[test]
fn test_finish_request_credentials_null() {
    let request = FinishRequest {
        username: "john_doe".into(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        credentials: serde_json::json!(null),
    };

    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(&*msg, "Invalid credentials");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_finish_request_credentials_not_object() {
    let request = FinishRequest {
        username: "john_doe".into(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        credentials: serde_json::json!("not_an_object"),
    };

    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(&*msg, "Invalid credentials");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_finish_request_credentials_empty_object() {
    let request = FinishRequest {
        username: "john_doe".into(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        credentials: serde_json::json!({}),
    };

    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(AppError::BadRequest(msg)) => {
            assert_eq!(&*msg, "Invalid credentials");
        }
        _ => panic!("Expected BadRequest error"),
    }
}

#[test]
fn test_finish_request_credentials_array() {
    let request = FinishRequest {
        username: "john_doe".into(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        credentials: serde_json::json!([1, 2, 3]),
    };

    let result = request.validate();
    assert!(result.is_err());
}

#[test]
fn test_finish_request_all_fields_invalid() {
    let request = FinishRequest {
        username: "".into(),
        session_id: "".into(),
        credentials: serde_json::json!(null),
    };

    let result = request.validate();
    assert!(result.is_err());
}

// --- Username max length ---

#[test]
fn test_begin_request_username_too_long() {
    let request = BeginRequest {
        username: "a".repeat(65).into(),
        role: None,
    };
    match request.validate() {
        Err(AppError::BadRequest(msg)) => assert!(msg.contains("at most 64")),
        _ => panic!("Expected BadRequest"),
    }
}

#[test]
fn test_begin_request_username_at_max_length() {
    let request = BeginRequest {
        username: "a".repeat(64).into(),
        role: None,
    };
    assert!(request.validate().is_ok());
}

// --- Username charset ---

#[test]
fn test_begin_request_username_html_chars_rejected() {
    let request = BeginRequest {
        username: "<script>".into(),
        role: None,
    };
    match request.validate() {
        Err(AppError::BadRequest(msg)) => assert!(msg.contains("invalid characters")),
        _ => panic!("Expected BadRequest"),
    }
}

#[test]
fn test_begin_request_username_space_rejected() {
    let request = BeginRequest {
        username: "john doe".into(),
        role: None,
    };
    match request.validate() {
        Err(AppError::BadRequest(msg)) => assert!(msg.contains("invalid characters")),
        _ => panic!("Expected BadRequest"),
    }
}

#[test]
fn test_begin_request_username_valid_chars() {
    for username in ["john_doe", "John-Doe", "user123", "a-b_c"] {
        let request = BeginRequest { username: (*username).into(), role: None };
        assert!(request.validate().is_ok(), "Expected valid: {username}");
    }
}

// --- Role validation ---

#[test]
fn test_begin_request_role_valid() {
    let request = BeginRequest {
        username: "alice".into(),
        role: Some("admin".into()),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_begin_request_role_none_valid() {
    let request = BeginRequest {
        username: "alice".into(),
        role: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_begin_request_role_too_long() {
    let request = BeginRequest {
        username: "alice".into(),
        role: Some("a".repeat(33).into()),
    };
    match request.validate() {
        Err(AppError::BadRequest(msg)) => assert!(msg.contains("at most 32")),
        _ => panic!("Expected BadRequest"),
    }
}

#[test]
fn test_begin_request_role_invalid_chars() {
    let request = BeginRequest {
        username: "alice".into(),
        role: Some("admin@root".into()),
    };
    match request.validate() {
        Err(AppError::BadRequest(msg)) => assert!(msg.contains("invalid characters")),
        _ => panic!("Expected BadRequest"),
    }
}

#[test]
fn test_begin_request_role_empty_string_rejected() {
    let request = BeginRequest {
        username: "alice".into(),
        role: Some("".into()),
    };
    assert!(request.validate().is_err());
}

// --- Unknown fields rejected (serde deny_unknown_fields) ---

#[test]
fn test_begin_request_unknown_field_rejected() {
    let json = r#"{"username":"alice","role":"user","extra":"field"}"#;
    assert!(serde_json::from_str::<BeginRequest>(json).is_err());
}

#[test]
fn test_finish_request_unknown_field_rejected() {
    let json = r#"{"username":"alice","session_id":"550e8400-e29b-41d4-a716-446655440000","credentials":{"id":"x"},"extra":"field"}"#;
    assert!(serde_json::from_str::<FinishRequest>(json).is_err());
}
