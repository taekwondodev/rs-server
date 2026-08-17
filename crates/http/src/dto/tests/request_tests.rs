use domain_auth::DomainError;

use crate::{
    dto::{BeginRequest, FinishCredentialRequest, FinishRequest, RecoveryVerifyRequest},
    error::HttpError,
    validation::Validatable,
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
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Username must be at least 3 characters");
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
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Username cannot be empty");
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
        Err(HttpError(DomainError::BadRequest(msg))) => {
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
        username: "john_doe".into(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        credentials,
        name: None,
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
        name: None,
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
        name: None,
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
        name: None,
    };

    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
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
        username: "john_doe".into(),
        session_id: "   ".into(),
        credentials,
        name: None,
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
        name: None,
    };

    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Invalid credentials");
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
        name: None,
    };

    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Invalid credentials");
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
        name: None,
    };

    let result = request.validate();
    assert!(result.is_err());
    match result {
        Err(HttpError(DomainError::BadRequest(msg))) => {
            assert_eq!(msg, "Invalid credentials");
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
        name: None,
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
        name: None,
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
        Err(HttpError(DomainError::BadRequest(msg))) => assert!(msg.contains("at most 64")),
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
        Err(HttpError(DomainError::BadRequest(msg))) => assert!(msg.contains("invalid characters")),
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
        Err(HttpError(DomainError::BadRequest(msg))) => assert!(msg.contains("invalid characters")),
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
        Err(HttpError(DomainError::BadRequest(msg))) => assert!(msg.contains("at most 32")),
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
        Err(HttpError(DomainError::BadRequest(msg))) => assert!(msg.contains("invalid characters")),
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

// ---------------------------------------------------------------------------
// FinishCredentialRequest (add-passkey ceremony)
// ---------------------------------------------------------------------------

fn finish_credential_request(body: serde_json::Value) -> FinishCredentialRequest {
    serde_json::from_value(body).expect("valid JSON body")
}

#[test]
fn test_finish_credential_request_valid_without_name() {
    let req = finish_credential_request(serde_json::json!({
        "session_id": "550e8400-e29b-41d4-a716-446655440000",
        "credentials": {"id": "AQID", "rawId": "AQID", "type": "public-key"}
    }));
    assert!(req.validate().is_ok());
}

#[test]
fn test_finish_credential_request_valid_with_name() {
    let req = finish_credential_request(serde_json::json!({
        "session_id": "550e8400-e29b-41d4-a716-446655440000",
        "credentials": {"id": "AQID", "rawId": "AQID", "type": "public-key"},
        "name": "MacBook Pro"
    }));
    assert!(req.validate().is_ok());
}

#[test]
fn test_finish_credential_request_rejects_missing_session_id() {
    // A missing required field fails at deserialization, before validation.
    let result = serde_json::from_value::<FinishCredentialRequest>(serde_json::json!({
        "credentials": {"id": "AQID", "rawId": "AQID", "type": "public-key"}
    }));
    assert!(result.is_err());
}

#[test]
fn test_finish_credential_request_rejects_empty_name() {
    let req = finish_credential_request(serde_json::json!({
        "session_id": "550e8400-e29b-41d4-a716-446655440000",
        "credentials": {"id": "AQID", "rawId": "AQID", "type": "public-key"},
        "name": "  "
    }));
    assert!(matches!(req.validate(), Err(HttpError(DomainError::BadRequest(_)))));
}

#[test]
fn test_finish_credential_request_rejects_too_long_name() {
    let req = finish_credential_request(serde_json::json!({
        "session_id": "550e8400-e29b-41d4-a716-446655440000",
        "credentials": {"id": "AQID", "rawId": "AQID", "type": "public-key"},
        "name": "x".repeat(65)
    }));
    assert!(matches!(req.validate(), Err(HttpError(DomainError::BadRequest(_)))));
}

#[test]
fn test_finish_credential_request_rejects_unknown_fields() {
    // deny_unknown_fields: a username here would mean the client is trying
    // to bind the ceremony to a different account than the Bearer token.
    let result = serde_json::from_value::<FinishCredentialRequest>(serde_json::json!({
        "username": "mallory",
        "session_id": "550e8400-e29b-41d4-a716-446655440000",
        "credentials": {"id": "AQID", "rawId": "AQID", "type": "public-key"}
    }));
    assert!(result.is_err());
}

#[test]
fn test_finish_request_with_name_valid() {
    let request = FinishRequest {
        username: "john_doe".into(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        credentials: serde_json::json!({"id": "AQID", "rawId": "AQID", "type": "public-key"}),
        name: Some("iPhone".into()),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_finish_request_with_invalid_name_rejected() {
    let request = FinishRequest {
        username: "john_doe".into(),
        session_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        credentials: serde_json::json!({"id": "AQID", "rawId": "AQID", "type": "public-key"}),
        name: Some("x".repeat(65).into()),
    };
    assert!(matches!(request.validate(), Err(HttpError(DomainError::BadRequest(_)))));
}

#[test]
fn test_recovery_verify_request_valid() {
    let request = RecoveryVerifyRequest {
        username: "john_doe".into(),
        recovery_code: "7WkP2s9fB4qXcD6e".into(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_recovery_verify_request_rejects_wrong_code_length() {
    // Recovery codes are exactly 16 chars — anything else is malformed.
    for bad in ["short", "7WkP2s9fB4qXcD6eA7WkP2s"] {
        let request = RecoveryVerifyRequest {
            username: "john_doe".into(),
            recovery_code: bad.into(),
        };
        assert!(matches!(request.validate(), Err(HttpError(DomainError::BadRequest(_)))));
    }
}

#[test]
fn test_recovery_verify_request_rejects_invalid_characters() {
    // Ambiguous/forbidden chars (0/O/1/I/l) are not in the recovery alphabet.
    let request = RecoveryVerifyRequest {
        username: "john_doe".into(),
        recovery_code: "0O1Il2s9fB4qXcD6".into(),
    };
    assert!(matches!(request.validate(), Err(HttpError(DomainError::BadRequest(_)))));
}

#[test]
fn test_recovery_verify_request_rejects_bad_username() {
    let request = RecoveryVerifyRequest {
        username: "jo".into(), // < 3 chars
        recovery_code: "7WkP2s9fB4qXcD6e".into(),
    };
    assert!(matches!(request.validate(), Err(HttpError(DomainError::BadRequest(_)))));
}

#[test]
fn test_recovery_verify_request_rejects_unknown_fields() {
    // deny_unknown_fields: no extraneous keys on the recovery surface.
    let result = serde_json::from_value::<RecoveryVerifyRequest>(serde_json::json!({
        "username": "john_doe",
        "recovery_code": "7WkP2s9fB4qXcD6e",
        "role": "admin"
    }));
    assert!(result.is_err());
}
