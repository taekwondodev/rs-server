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

pub static HEALTH_CHECKS: LazyLock<prometheus::CounterVec> = LazyLock::new(|| {
    prometheus::register_counter_vec!(
        "health_check_requests_total",
        "Total number of health check requests",
        &["status"]
    )
    .unwrap()
});

pub static DB_QUERY_DURATION: LazyLock<prometheus::HistogramVec> = LazyLock::new(|| {
    prometheus::register_histogram_vec!(
        "db_query_duration_seconds",
        "Database query execution time in seconds",
        &["operation", "table"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .unwrap()
});

pub static DB_POOL_CONNECTIONS: LazyLock<prometheus::GaugeVec> = LazyLock::new(|| {
    prometheus::register_gauge_vec!(
        "db_pool_connections",
        "Number of database pool connections",
        &["state"] // active, idle, max
    )
    .unwrap()
});

pub static DB_ERRORS: LazyLock<prometheus::CounterVec> = LazyLock::new(|| {
    prometheus::register_counter_vec!(
        "db_errors_total",
        "Total number of database errors",
        &["operation", "error_type"]
    )
    .unwrap()
});

pub static REDIS_OPERATION_DURATION: LazyLock<prometheus::HistogramVec> = LazyLock::new(|| {
    prometheus::register_histogram_vec!(
        "redis_operation_duration_seconds",
        "Redis operation execution time in seconds",
        &["operation"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
    )
    .unwrap()
});

pub static REDIS_ERRORS: LazyLock<prometheus::CounterVec> = LazyLock::new(|| {
    prometheus::register_counter_vec!(
        "redis_errors_total",
        "Total number of Redis errors",
        &["operation", "error_type"]
    )
    .unwrap()
});

pub static ERROR_COUNT: LazyLock<prometheus::CounterVec> = LazyLock::new(|| {
    prometheus::register_counter_vec!(
        "app_errors_total",
        "Total number of application errors",
        &["error_type", "endpoint"]
    )
    .unwrap()
});

pub static CIRCUIT_BREAKER_STATE: LazyLock<prometheus::GaugeVec> = LazyLock::new(|| {
    prometheus::register_gauge_vec!(
        "circuit_breaker_state",
        "Circuit breaker state (0=closed, 1=open, 2=half-open)",
        &["service"]
    )
    .unwrap()
});

/// Get Prometheus metrics
///
/// Returns all metrics in Prometheus format for scraping by monitoring systems
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "Monitoring",
    responses(
        (status = 200, description = "Prometheus metrics", content_type = "text/plain"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();

    match encoder.encode_to_string(&metric_families) {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("Failed to encode metrics"),
        ),
    }
}

pub fn create_prometheus_layer() -> PrometheusMetricLayer<'static> {
    PrometheusMetricLayer::new()
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
    TOKEN_OPERATIONS
        .with_label_values(&[operation, status])
        .inc();
}

pub fn track_health_check(success: bool) {
    let status = if success { "healthy" } else { "unhealthy" };
    HEALTH_CHECKS.with_label_values(&[status]).inc();
}

pub fn track_db_query(operation: &str, table: &str, duration_secs: f64) {
    DB_QUERY_DURATION
        .with_label_values(&[operation, table])
        .observe(duration_secs);
}

pub fn track_db_error(operation: &str, error_type: &str) {
    DB_ERRORS.with_label_values(&[operation, error_type]).inc();
}

pub fn update_db_pool_stats(active: usize, idle: usize, max: usize) {
    DB_POOL_CONNECTIONS
        .with_label_values(&["active"])
        .set(active as f64);
    DB_POOL_CONNECTIONS
        .with_label_values(&["idle"])
        .set(idle as f64);
    DB_POOL_CONNECTIONS
        .with_label_values(&["max"])
        .set(max as f64);
}

pub fn track_error(error_type: &str, endpoint: &str) {
    ERROR_COUNT.with_label_values(&[error_type, endpoint]).inc();
}

pub fn update_circuit_breaker_state(service: &str, state: u8) {
    // 0=closed, 1=open, 2=half-open
    CIRCUIT_BREAKER_STATE
        .with_label_values(&[service])
        .set(state as f64);
}

pub fn track_redis_operation(operation: &str, duration_secs: f64) {
    REDIS_OPERATION_DURATION
        .with_label_values(&[operation])
        .observe(duration_secs);
}

pub fn track_redis_error(operation: &str, error_type: &str) {
    REDIS_ERRORS
        .with_label_values(&[operation, error_type])
        .inc();
}
