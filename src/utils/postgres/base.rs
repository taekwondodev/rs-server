use crate::{app::AppError, config::CircuitBreaker, utils::check_database_health};
use deadpool_postgres::Pool;
use std::sync::Arc;
use tokio_postgres::types::ToSql;

use super::{metrics::RepositoryMetrics, prepared_cache::PreparedStatementCache};

pub struct BaseRepository {
    db: Pool,
    circuit_breaker: Arc<CircuitBreaker>,
    prepared_cache: PreparedStatementCache,
}

impl BaseRepository {
    pub fn new(db: Pool, circuit_breaker: Arc<CircuitBreaker>) -> Self {
        Self {
            db,
            circuit_breaker,
            prepared_cache: PreparedStatementCache::new(),
        }
    }

    pub async fn execute_with_circuit_breaker<F, Fut, T>(&self, operation: F) -> Result<T, AppError>
    where
        F: FnOnce(Pool) -> Fut + Send,
        Fut: std::future::Future<Output = Result<T, AppError>> + Send,
        T: Send,
    {
        let db = self.db.clone();
        let circuit_breaker = self.circuit_breaker.clone();

        circuit_breaker
            .call(|| async move { operation(db).await })
            .await
    }

    pub async fn check_database_health(&self) -> crate::auth::dto::ServiceHealth {
        let db = self.db.clone();
        let circuit_breaker = self.circuit_breaker.clone();

        check_database_health(|| async move {
            circuit_breaker
                .call(|| async {
                    let client = db.get().await?;
                    client.query_one("SELECT 1 as health_check", &[]).await?;
                    Ok(())
                })
                .await
        })
        .await
    }

    #[cfg_attr(not(feature = "strict"), allow(dead_code))]
    pub async fn execute_prepared(
        &self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<tokio_postgres::Row>, AppError> {
        let client = self.db.get().await?;
        let stmt = self.prepared_cache.get_or_prepare(&client, query).await?;
        Ok(client.query(&stmt, params).await?)
    }

    #[cfg_attr(not(feature = "strict"), allow(dead_code))]
    pub async fn execute_prepared_one(
        &self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<tokio_postgres::Row, AppError> {
        let client = self.db.get().await?;
        let stmt = self.prepared_cache.get_or_prepare(&client, query).await?;
        Ok(client.query_one(&stmt, params).await?)
    }

    pub async fn execute_prepared_opt(
        &self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<tokio_postgres::Row>, AppError> {
        let client = self.db.get().await?;
        let stmt = self.prepared_cache.get_or_prepare(&client, query).await?;
        Ok(client.query_opt(&stmt, params).await?)
    }

    #[cfg_attr(not(feature = "strict"), allow(dead_code))]
    pub async fn execute_prepared_raw(
        &self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, AppError> {
        let client = self.db.get().await?;
        let stmt = self.prepared_cache.get_or_prepare(&client, query).await?;
        Ok(client.execute(&stmt, params).await?)
    }
}

pub trait FromRow: Sized {
    fn from_row(row: &tokio_postgres::Row) -> Result<Self, AppError>;
}

impl RepositoryMetrics for BaseRepository {
    fn update_pool_metrics(&self) {
        let status = self.db.status();

        crate::app::middleware::metrics::update_db_pool_stats(
            status.size,
            status.available,
            status.max_size,
        );
    }
}
