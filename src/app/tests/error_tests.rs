use axum::body::to_bytes;
use axum::response::IntoResponse;

use crate::app::error::{AppError, ErrorResponse};

async fn extract_message(err: AppError) -> String {
    let response = err.into_response();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice::<ErrorResponse>(&bytes).unwrap().message.to_string()
}

async fn extract_status(err: AppError) -> u16 {
    err.into_response().status().as_u16()
}

// --- OWASP OTG-ERR-001: sensitive detail never reaches HTTP body ---

#[tokio::test]
async fn internal_server_hides_detail() {
    let detail = "postgres: password authentication failed for user 'admin'";
    let msg = extract_message(AppError::InternalServer(detail.into())).await;
    assert_eq!(msg, "Internal server error");
    assert!(!msg.contains("postgres"));
    assert!(!msg.contains("password"));
    assert!(!msg.contains("admin"));
}

#[tokio::test]
async fn unauthorized_hides_jwt_detail() {
    let detail = "ExpiredSignature: token expired at 2024-01-01T00:00:00Z";
    let msg = extract_message(AppError::Unauthorized(detail)).await;
    assert_eq!(msg, "Unauthorized");
    assert!(!msg.contains("ExpiredSignature"));
    assert!(!msg.contains("2024"));
}

#[tokio::test]
async fn service_unavailable_hides_infra_detail() {
    let detail = "Database: connection refused at 10.0.0.5:5432";
    let msg = extract_message(AppError::ServiceUnavailable(detail.into())).await;
    assert_eq!(msg, "Service temporarily unavailable");
    assert!(!msg.contains("10.0.0.5"));
    assert!(!msg.contains("5432"));
}

#[tokio::test]
async fn circuit_breaker_open_hides_detail() {
    let msg = extract_message(AppError::CircuitBreakerOpen("redis-pool".into())).await;
    assert_eq!(msg, "Service temporarily unavailable");
    assert!(!msg.contains("redis-pool"));
}

// --- OWASP OTG-ERR-002: safe domain messages pass through unchanged ---

#[tokio::test]
async fn not_found_passes_safe_message() {
    let msg = extract_message(AppError::NotFound("user not found")).await;
    assert_eq!(msg, "user not found");
}

#[tokio::test]
async fn already_exists_passes_safe_message() {
    let msg = extract_message(AppError::AlreadyExists("username already taken")).await;
    assert_eq!(msg, "username already taken");
}

#[tokio::test]
async fn bad_request_passes_safe_message() {
    let msg = extract_message(AppError::BadRequest("username must be at least 3 characters".into())).await;
    assert_eq!(msg, "username must be at least 3 characters");
}

// --- From<uuid::Error>: no parse internals in 400 body ---

#[tokio::test]
async fn uuid_error_gives_safe_bad_request() {
    let uuid_err = uuid::Uuid::try_parse("not-a-uuid").unwrap_err();
    let app_err = AppError::from(uuid_err);
    let msg = extract_message(app_err).await;
    assert_eq!(msg, "Invalid identifier format");
    assert!(!msg.contains("invalid"));
    assert!(!msg.contains("UUID"));
}

// --- HTTP status codes ---

#[tokio::test]
async fn status_codes_correct() {
    assert_eq!(extract_status(AppError::InternalServer("x".into())).await, 500);
    assert_eq!(extract_status(AppError::NotFound("x")).await, 404);
    assert_eq!(extract_status(AppError::AlreadyExists("x")).await, 409);
    assert_eq!(extract_status(AppError::Unauthorized("x")).await, 401);
    assert_eq!(extract_status(AppError::BadRequest("x".into())).await, 400);
    assert_eq!(extract_status(AppError::ServiceUnavailable("x".into())).await, 503);
    assert_eq!(extract_status(AppError::CircuitBreakerOpen("x".into())).await, 503);
}
