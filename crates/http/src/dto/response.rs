use std::borrow::Cow;

use axum::{Json, response::IntoResponse};
use serde::Serialize;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct BeginResponse {
    #[cfg_attr(
        feature = "openapi",
        schema(example = json!({"challenge": "Y2hhbGxlbmdl", "rp": {"name": "Example", "id": "example.com"}}))
    )]
    pub options: serde_json::Value,
    #[cfg_attr(feature = "openapi", schema(example = "550e8400-e29b-41d4-a716-446655440000"))]
    pub session_id: Box<str>,
}

impl From<domain_auth::BeginResult> for BeginResponse {
    fn from(r: domain_auth::BeginResult) -> Self {
        Self { options: r.options, session_id: r.session_id }
    }
}

impl IntoResponse for BeginResponse {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct MessageResponse {
    #[cfg_attr(feature = "openapi", schema(example = "Operation completed successfully"))]
    pub message: Cow<'static, str>,
}

impl From<domain_auth::MessageResult> for MessageResponse {
    fn from(r: domain_auth::MessageResult) -> Self {
        Self { message: r.message }
    }
}

impl IntoResponse for MessageResponse {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct TokenResponse {
    #[cfg_attr(feature = "openapi", schema(example = "Login completed successfully"))]
    pub message: Cow<'static, str>,
    #[cfg_attr(
        feature = "openapi",
        schema(example = "v4.public.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ")
    )]
    pub access_token: Box<str>,
}

impl From<domain_auth::TokenResult> for TokenResponse {
    fn from(r: domain_auth::TokenResult) -> Self {
        Self { message: r.message, access_token: r.access_token }
    }
}

impl IntoResponse for TokenResponse {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HealthResponse {
    #[cfg_attr(feature = "openapi", schema(example = "2024-01-01T12:00:00Z"))]
    pub timestamp: Box<str>,
    pub checks: HealthChecks,
}

/// Fixed two-field shape on purpose: the `/healthz` wire contract is
/// deliberately explicit rather than mirroring `HealthReport`'s open
/// `BTreeMap` — external monitors want a stable schema, not one that grows a
/// field silently whenever a new `HealthIndicator` is registered. Adding an
/// indicator that should be surfaced over HTTP means adding a field here by
/// hand; that's a feature, not friction.
///
/// Not a `From` impl: `rs_repository_utils::HealthReport` deliberately carries
/// no timestamp (that's a presentation concern, not something the aggregation
/// library should need a time-formatting dependency for), so this stamps one
/// at the point the response is actually built.
impl HealthResponse {
    pub fn from_report(mut r: rs_repository_utils::HealthReport) -> Self {
        fn missing() -> rs_repository_utils::ServiceHealth {
            rs_repository_utils::ServiceHealth {
                status: rs_repository_utils::HealthStatus::Unhealthy,
                message: "indicator not registered".into(),
                response_time_ms: None,
            }
        }

        let database = r.checks.remove("database").unwrap_or_else(missing);
        let redis = r.checks.remove("redis").unwrap_or_else(missing);

        Self {
            timestamp: chrono::Utc::now().to_rfc3339().into_boxed_str(),
            checks: HealthChecks { database: database.into(), redis: redis.into() },
        }
    }
}

impl IntoResponse for HealthResponse {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HealthChecks {
    pub database: ServiceHealth,
    pub redis: ServiceHealth,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServiceHealth {
    #[cfg_attr(feature = "openapi", schema(example = "healthy"))]
    pub status: HealthStatus,
    #[cfg_attr(feature = "openapi", schema(example = "Connected successfully"))]
    pub message: Box<str>,
    #[cfg_attr(feature = "openapi", schema(example = 150))]
    pub response_time_ms: Option<u64>,
}

impl From<rs_repository_utils::ServiceHealth> for ServiceHealth {
    fn from(s: rs_repository_utils::ServiceHealth) -> Self {
        Self { status: s.status.into(), message: s.message, response_time_ms: s.response_time_ms }
    }
}

#[derive(Debug, Serialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
}

impl From<rs_repository_utils::HealthStatus> for HealthStatus {
    fn from(s: rs_repository_utils::HealthStatus) -> Self {
        match s {
            rs_repository_utils::HealthStatus::Healthy => Self::Healthy,
            rs_repository_utils::HealthStatus::Unhealthy => Self::Unhealthy,
        }
    }
}
