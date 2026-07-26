use axum::{Json, http::StatusCode, response::IntoResponse};
use domain_auth::DomainError;

#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ErrorResponse {
    #[cfg_attr(feature = "openapi", schema(example = "username must be at least 3 characters"))]
    pub message: Box<str>,
}

/// The only place `IntoResponse` is implemented for an error type. Wraps
/// `DomainError` so http-native failures (malformed JSON, missing cookie,
/// field validation) and domain-originated failures share one status-code
/// table and one response shape.
#[derive(Debug)]
pub struct HttpError(pub(crate) DomainError);

impl HttpError {
    pub fn not_found(msg: &'static str) -> Self {
        Self(DomainError::NotFound(msg))
    }

    pub fn unauthorized(msg: &'static str) -> Self {
        Self(DomainError::Unauthorized(msg))
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self(DomainError::BadRequest(msg.into()))
    }
}

impl From<DomainError> for HttpError {
    fn from(value: DomainError) -> Self {
        Self(value)
    }
}

impl From<axum::extract::rejection::JsonRejection> for HttpError {
    fn from(_: axum::extract::rejection::JsonRejection) -> Self {
        Self::bad_request("Malformed request body")
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> axum::response::Response {
        let (status, client_message): (StatusCode, Box<str>) = match self.0 {
            DomainError::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".into())
            }
            DomainError::ServiceUnavailable(msg) => {
                tracing::warn!(error = %msg, "service degraded");
                (StatusCode::SERVICE_UNAVAILABLE, "Service temporarily unavailable".into())
            }
            DomainError::Unauthorized(msg) => {
                tracing::warn!(error = %msg, "unauthorized");
                (StatusCode::UNAUTHORIZED, "Unauthorized".into())
            }
            DomainError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.into()),
            DomainError::Conflict(msg) => (StatusCode::CONFLICT, msg.into()),
            DomainError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.into_boxed_str()),
        };
        (status, Json(ErrorResponse { message: client_message })).into_response()
    }
}
