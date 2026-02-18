use crate::auth::dto::{HealthStatus, ServiceHealth};
use std::future::Future;
use std::time::Duration;
use tokio::time::timeout;

pub async fn perform_health_check<F, Fut, E>(
    check_name: &str,
    timeout_duration: Duration,
    health_check_fn: F,
) -> ServiceHealth
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    let start = std::time::Instant::now();

    let result = timeout(timeout_duration, health_check_fn()).await;
    let response_time = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(())) => ServiceHealth {
            status: HealthStatus::Healthy,
            message: format!("{} connection successful", check_name),
            response_time_ms: Some(response_time),
        },
        Ok(Err(e)) => ServiceHealth {
            status: HealthStatus::Unhealthy,
            message: format!("{} error: {}", check_name, e),
            response_time_ms: Some(response_time),
        },
        Err(_) => ServiceHealth {
            status: HealthStatus::Unhealthy,
            message: format!("{} connection timeout", check_name),
            response_time_ms: None,
        },
    }
}

pub(crate) async fn check_database_health<F, Fut>(health_check_fn: F) -> ServiceHealth
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), crate::app::AppError>>,
{
    perform_health_check("Database", Duration::from_secs(5), health_check_fn).await
}

pub(crate) async fn check_redis_health<F, Fut>(health_check_fn: F) -> ServiceHealth
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), crate::app::AppError>>,
{
    perform_health_check("Redis", Duration::from_secs(5), health_check_fn).await
}
