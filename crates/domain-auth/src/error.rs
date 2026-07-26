/// Domain-level error. Ports (`AuthRepository`, `JwtService`) and `AuthService`
/// return this type — it carries no HTTP/axum concepts at all.
///
/// Note: in addition to the literal set named in the refactor spec (NotFound,
/// Conflict, Unauthorized, BadRequest, Internal) this also keeps a
/// `ServiceUnavailable` variant. Judgment call: without it, circuit-breaker-open
/// and degraded-dependency conditions would collapse into `Internal` and the
/// HTTP layer would lose the ability to reproduce the existing 503 status code
/// (see `app/tests/error_tests.rs::circuit_breaker_open_hides_detail` /
/// `service_unavailable_hides_infra_detail` in the pre-refactor code, migrated
/// to `http`'s error tests). Preserving that externally-observable behavior and
/// test coverage took priority over the literal variant list.
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("not found: {0}")]
    NotFound(&'static str),
    #[error("already exists: {0}")]
    Conflict(&'static str),
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<serde_json::Error> for DomainError {
    fn from(value: serde_json::Error) -> Self {
        DomainError::Internal(value.into())
    }
}

impl From<webauthn_rs::prelude::WebauthnError> for DomainError {
    fn from(value: webauthn_rs::prelude::WebauthnError) -> Self {
        DomainError::Internal(value.into())
    }
}
