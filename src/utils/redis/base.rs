use crate::{
    app::AppError, auth::dto::response::ServiceHealth, config::CircuitBreaker,
    utils::health::check_redis_health,
};
use redis::aio::ConnectionManager;
use std::sync::Arc;

pub struct BaseRedisRepository {
    connection_manager: ConnectionManager,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl BaseRedisRepository {
    pub fn new(
        connection_manager: ConnectionManager,
        circuit_breaker: Arc<CircuitBreaker>,
    ) -> Self {
        Self {
            connection_manager,
            circuit_breaker,
        }
    }

    pub async fn execute_with_circuit_breaker<F, Fut, T>(&self, operation: F) -> Result<T, AppError>
    where
        F: FnOnce(ConnectionManager) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T, AppError>> + Send,
        T: Send,
    {
        let conn = self.connection_manager.clone();
        let circuit_breaker = self.circuit_breaker.clone();

        circuit_breaker
            .call(|| async move { operation(conn).await })
            .await
    }

    pub async fn check_redis_health(&self) -> ServiceHealth {
        let conn = self.connection_manager.clone();
        let circuit_breaker = self.circuit_breaker.clone();

        check_redis_health(|| async move {
            circuit_breaker
                .call(|| async move {
                    let mut conn = conn.clone();
                    use redis::AsyncCommands;
                    let _: String = conn.ping().await?;
                    Ok(())
                })
                .await
        })
        .await
    }

    pub fn connection(&self) -> &ConnectionManager {
        &self.connection_manager
    }

    pub fn circuit_breaker(&self) -> &Arc<CircuitBreaker> {
        &self.circuit_breaker
    }
}
