use std::fmt::{self};

use axum::{Json, http::StatusCode, response::IntoResponse};

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    #[schema(example = "username must be at least 3 characters")]
    pub message: String,
}

#[derive(Debug)]
pub enum AppError {
    InternalServer(String),
    NotFound(String),
    AlreadyExists(String),
    Unauthorized(String),
    BadRequest(String),
    ServiceUnavailable(String),
    CircuitBreakerOpen(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::InternalServer(msg) => write!(f, "internal server error: {}", msg),
            AppError::NotFound(msg) => write!(f, "not found: {}", msg),
            AppError::AlreadyExists(msg) => write!(f, "already exists: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "unauthorized: {}", msg),
            AppError::BadRequest(msg) => write!(f, "bad request: {}", msg),
            AppError::ServiceUnavailable(msg) => write!(f, "service unavailable: {}", msg),
            AppError::CircuitBreakerOpen(msg) => write!(f, "circuit breaker open: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AppError::InternalServer(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::AlreadyExists(_) => (StatusCode::CONFLICT, self.to_string()),
            AppError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::ServiceUnavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            AppError::CircuitBreakerOpen(_) => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
        };

        let body = Json(ErrorResponse { message });

        (status, body).into_response()
    }
}

impl From<deadpool_postgres::PoolError> for AppError {
    fn from(value: deadpool_postgres::PoolError) -> Self {
        AppError::InternalServer(value.to_string())
    }
}

impl From<tokio_postgres::Error> for AppError {
    fn from(value: tokio_postgres::Error) -> Self {
        AppError::InternalServer(value.to_string())
    }
}

impl From<redis::RedisError> for AppError {
    fn from(value: redis::RedisError) -> Self {
        AppError::InternalServer(value.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        AppError::InternalServer(value.to_string())
    }
}

impl From<webauthn_rs::prelude::WebauthnError> for AppError {
    fn from(value: webauthn_rs::prelude::WebauthnError) -> Self {
        AppError::InternalServer(value.to_string())
    }
}

impl From<uuid::Error> for AppError {
    fn from(value: uuid::Error) -> Self {
        AppError::BadRequest(value.to_string())
    }
}

impl From<axum::extract::rejection::JsonRejection> for AppError {
    fn from(value: axum::extract::rejection::JsonRejection) -> Self {
        AppError::BadRequest(value.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        AppError::Unauthorized(value.to_string())
    }
}
