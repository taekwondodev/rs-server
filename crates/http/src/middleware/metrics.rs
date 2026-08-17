//! Business/HTTP-facing Prometheus counters + the `/metrics` axum handler and
//! `axum_prometheus` layer. Low-level infra counters (db/redis timing, circuit
//! breaker state) live in `domain_auth::metrics` instead — see that module's docs.
use std::sync::LazyLock;

use axum::{http::StatusCode, response::IntoResponse};
use axum_prometheus::PrometheusMetricLayer;

pub static REGISTRATION_ATTEMPTS: LazyLock<prometheus::CounterVec> = LazyLock::new(|| {
    prometheus::register_counter_vec!(
        "webauthn_registration_attempts_total",
        "Total number of WebAuthn registration attempts",
        &["status"]
    )
    .unwrap()
});

pub static LOGIN_ATTEMPTS: LazyLock<prometheus::CounterVec> = LazyLock::new(|| {
    prometheus::register_counter_vec!(
        "webauthn_login_attempts_total",
        "Total number of WebAuthn login attempts",
        &["status"]
    )
    .unwrap()
});

pub static TOKEN_OPERATIONS: LazyLock<prometheus::CounterVec> = LazyLock::new(|| {
    prometheus::register_counter_vec!(
        "jwt_token_operations_total",
        "Total number of JWT token operations",
        &["operation", "status"]
    )
    .unwrap()
});

pub static REGISTRATION_CONFLICTS: LazyLock<prometheus::CounterVec> = LazyLock::new(|| {
    prometheus::register_counter_vec!(
        "webauthn_username_conflict_total",
        "Registration attempts hitting an existing username: taken (active user) or resumed (incomplete registration)",
        &["outcome"]
    )
    .unwrap()
});

pub static HEALTH_CHECKS: LazyLock<prometheus::CounterVec> = LazyLock::new(|| {
    prometheus::register_counter_vec!(
        "health_check_requests_total",
        "Total number of health check requests",
        &["status"]
    )
    .unwrap()
});

pub static CREDENTIAL_OPERATIONS: LazyLock<prometheus::CounterVec> = LazyLock::new(|| {
    prometheus::register_counter_vec!(
        "credential_operations_total",
        "Total number of passkey management operations (add_begin, add_finish, list, remove)",
        &["operation", "status"]
    )
    .unwrap()
});

pub static RECOVERY_OPERATIONS: LazyLock<prometheus::CounterVec> = LazyLock::new(|| {
    prometheus::register_counter_vec!(
        "recovery_operations_total",
        "Total number of account-recovery operations (generate, rotate, begin, finish)",
        &["operation", "status"]
    )
    .unwrap()
});

/// Get Prometheus metrics
///
/// Returns all metrics in Prometheus format for scraping by monitoring systems
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/metrics",
    tag = "Monitoring",
    responses(
        (status = 200, description = "Prometheus metrics", content_type = "text/plain"),
        (status = 500, description = "Internal server error")
    )
))]
pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();

    match encoder.encode_to_string(&metric_families) {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, String::from("Failed to encode metrics")),
    }
}

pub fn create_prometheus_layer() -> PrometheusMetricLayer<'static> {
    PrometheusMetricLayer::new()
}

pub fn track_registration_conflict(outcome: &str) {
    REGISTRATION_CONFLICTS.with_label_values(&[outcome]).inc();
}

pub fn track_registration_attempt(success: bool) {
    let status = if success { "success" } else { "failure" };
    REGISTRATION_ATTEMPTS.with_label_values(&[status]).inc();
}

pub fn track_login_attempt(success: bool) {
    let status = if success { "success" } else { "failure" };
    LOGIN_ATTEMPTS.with_label_values(&[status]).inc();
}

pub fn track_token_operation(operation: &str, success: bool) {
    let status = if success { "success" } else { "failure" };
    TOKEN_OPERATIONS.with_label_values(&[operation, status]).inc();
}

pub fn track_health_check(success: bool) {
    let status = if success { "healthy" } else { "unhealthy" };
    HEALTH_CHECKS.with_label_values(&[status]).inc();
}

pub fn track_credential_operation(operation: &str, success: bool) {
    let status = if success { "success" } else { "failure" };
    CREDENTIAL_OPERATIONS.with_label_values(&[operation, status]).inc();
}

pub fn track_recovery_operation(operation: &str, success: bool) {
    let status = if success { "success" } else { "failure" };
    RECOVERY_OPERATIONS.with_label_values(&[operation, status]).inc();
}
