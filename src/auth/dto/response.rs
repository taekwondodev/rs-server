use axum::{response::IntoResponse, Json};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct BeginResponse {
    #[schema(example = json!({"challenge": "Y2hhbGxlbmdl", "rp": {"name": "Example", "id": "example.com"}}))]
    pub options: serde_json::Value,
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub session_id: String,
}

impl IntoResponse for BeginResponse {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse {
    #[schema(example = "Operation completed successfully")]
    pub message: String,
}

impl IntoResponse for MessageResponse {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    #[schema(example = "Login completed successfully")]
    pub message: String,
    #[schema(
        example = "v4.public.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    )]
    pub access_token: String,
}

impl IntoResponse for TokenResponse {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    #[schema(example = "2024-01-01T12:00:00Z")]
    pub timestamp: String,
    pub checks: HealthChecks,
}

impl IntoResponse for HealthResponse {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct HealthChecks {
    pub database: ServiceHealth,
    pub redis: ServiceHealth,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ServiceHealth {
    #[schema(example = "healthy")]
    pub status: HealthStatus,
    #[schema(example = "Connected successfully")]
    pub message: String,
    #[schema(example = 150)]
    pub response_time_ms: Option<u64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema, PartialEq)]
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

impl From<rs_repository_utils::ServiceHealth> for ServiceHealth {
    fn from(s: rs_repository_utils::ServiceHealth) -> Self {
        Self {
            status: s.status.into(),
            message: s.message,
            response_time_ms: s.response_time_ms,
        }
    }
}
