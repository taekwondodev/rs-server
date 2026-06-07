use std::fmt::{self};

use axum::{Json, http::StatusCode, response::IntoResponse};

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    #[schema(example = "username must be at least 3 characters")]
    pub message: Box<str>,
}

#[derive(Debug)]
pub enum AppError {
    InternalServer(Box<str>),
    NotFound(&'static str),
    AlreadyExists(&'static str),
    Unauthorized(&'static str),
    BadRequest(Box<str>),
    ServiceUnavailable(Box<str>),
    CircuitBreakerOpen(Box<str>),
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
        let (status, client_message): (StatusCode, &str) = match &self {
            AppError::InternalServer(_) => {
                tracing::error!(error = %self, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::ServiceUnavailable(_) | AppError::CircuitBreakerOpen(_) => {
                tracing::warn!(error = %self, "service degraded");
                (StatusCode::SERVICE_UNAVAILABLE, "Service temporarily unavailable")
            }
            AppError::Unauthorized(_) => {
                tracing::warn!(error = %self, "unauthorized");
                (StatusCode::UNAUTHORIZED, "Unauthorized")
            }
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, *msg),
            AppError::AlreadyExists(msg) => (StatusCode::CONFLICT, *msg),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.as_ref()),
        };
        (status, Json(ErrorResponse { message: client_message.into() })).into_response()
    }
}

impl From<deadpool_postgres::PoolError> for AppError {
    fn from(value: deadpool_postgres::PoolError) -> Self {
        AppError::InternalServer(value.to_string().into())
    }
}

impl From<tokio_postgres::Error> for AppError {
    fn from(value: tokio_postgres::Error) -> Self {
        AppError::InternalServer(value.to_string().into())
    }
}

impl From<redis::RedisError> for AppError {
    fn from(value: redis::RedisError) -> Self {
        AppError::InternalServer(value.to_string().into())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        AppError::InternalServer(value.to_string().into())
    }
}

impl From<webauthn_rs::prelude::WebauthnError> for AppError {
    fn from(value: webauthn_rs::prelude::WebauthnError) -> Self {
        AppError::InternalServer(value.to_string().into())
    }
}

impl From<uuid::Error> for AppError {
    fn from(_: uuid::Error) -> Self {
        AppError::BadRequest("Invalid identifier format".into())
    }
}

impl From<axum::extract::rejection::JsonRejection> for AppError {
    fn from(_: axum::extract::rejection::JsonRejection) -> Self {
        AppError::BadRequest("Malformed request body".into())
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(_: jsonwebtoken::errors::Error) -> Self {
        AppError::Unauthorized("Invalid token")
    }
}

impl From<rs_repository_utils::RepositoryError> for AppError {
    fn from(e: rs_repository_utils::RepositoryError) -> Self {
        match e {
            rs_repository_utils::RepositoryError::InvalidQuery(_) => {
                AppError::BadRequest("Invalid query parameters".into())
            }
            rs_repository_utils::RepositoryError::CircuitBreakerOpen(msg) => {
                AppError::CircuitBreakerOpen(msg.into())
            }
            _ => AppError::InternalServer(e.to_string().into()),
        }
    }
}
