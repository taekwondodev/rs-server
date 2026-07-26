use axum::body::to_bytes;
use axum::response::IntoResponse;
use domain_auth::DomainError;

use crate::error::{ErrorResponse, HttpError};

async fn extract_message(err: HttpError) -> String {
    let response = err.into_response();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice::<ErrorResponse>(&bytes).unwrap().message.to_string()
}

async fn extract_status(err: HttpError) -> u16 {
    err.into_response().status().as_u16()
}

// --- OWASP OTG-ERR-001: sensitive detail never reaches HTTP body ---

#[tokio::test]
async fn internal_server_hides_detail() {
    let detail = "postgres: password authentication failed for user 'admin'";
    let msg = extract_message(HttpError::from(DomainError::Internal(anyhow::anyhow!(detail)))).await;
    assert_eq!(msg, "Internal server error");
    assert!(!msg.contains("postgres"));
    assert!(!msg.contains("password"));
    assert!(!msg.contains("admin"));
}

#[tokio::test]
async fn unauthorized_hides_jwt_detail() {
    let detail = "ExpiredSignature: token expired at 2024-01-01T00:00:00Z";
    let msg = extract_message(HttpError::unauthorized(detail)).await;
    assert_eq!(msg, "Unauthorized");
    assert!(!msg.contains("ExpiredSignature"));
    assert!(!msg.contains("2024"));
}

#[tokio::test]
async fn service_unavailable_hides_infra_detail() {
    let detail = "Database: connection refused at 10.0.0.5:5432";
    let msg = extract_message(HttpError::from(DomainError::ServiceUnavailable(detail.into()))).await;
    assert_eq!(msg, "Service temporarily unavailable");
    assert!(!msg.contains("10.0.0.5"));
    assert!(!msg.contains("5432"));
}

#[tokio::test]
async fn circuit_breaker_open_hides_detail() {
    // Circuit-breaker-open is classified into `DomainError::ServiceUnavailable`
    // at the infra boundary (see infra_postgres/infra_jwt's classify_repo_error) —
    // same 503 + generic message as any other degraded-dependency condition.
    let msg = extract_message(HttpError::from(DomainError::ServiceUnavailable("redis-pool".into()))).await;
    assert_eq!(msg, "Service temporarily unavailable");
    assert!(!msg.contains("redis-pool"));
}

// --- OWASP OTG-ERR-002: safe domain messages pass through unchanged ---

#[tokio::test]
async fn not_found_passes_safe_message() {
    let msg = extract_message(HttpError::not_found("user not found")).await;
    assert_eq!(msg, "user not found");
}

#[tokio::test]
async fn already_exists_passes_safe_message() {
    let msg = extract_message(HttpError::from(DomainError::Conflict("username already taken"))).await;
    assert_eq!(msg, "username already taken");
}

#[tokio::test]
async fn bad_request_passes_safe_message() {
    let msg = extract_message(HttpError::bad_request("username must be at least 3 characters")).await;
    assert_eq!(msg, "username must be at least 3 characters");
}

// --- Invalid session-id uuid: no parse internals in 400 body (see
// domain_auth::AuthService::get_user_and_session, which constructs this variant
// explicitly on Uuid::try_parse failure) ---

#[tokio::test]
async fn uuid_error_gives_safe_bad_request() {
    let msg = extract_message(HttpError::bad_request("Invalid identifier format")).await;
    assert_eq!(msg, "Invalid identifier format");
    assert!(!msg.contains("invalid"));
    assert!(!msg.contains("UUID"));
}

// --- HTTP status codes ---

#[tokio::test]
async fn status_codes_correct() {
    assert_eq!(extract_status(HttpError::from(DomainError::Internal(anyhow::anyhow!("x")))).await, 500);
    assert_eq!(extract_status(HttpError::not_found("x")).await, 404);
    assert_eq!(extract_status(HttpError::from(DomainError::Conflict("x"))).await, 409);
    assert_eq!(extract_status(HttpError::unauthorized("x")).await, 401);
    assert_eq!(extract_status(HttpError::bad_request("x")).await, 400);
    assert_eq!(extract_status(HttpError::from(DomainError::ServiceUnavailable("x".into()))).await, 503);
}
