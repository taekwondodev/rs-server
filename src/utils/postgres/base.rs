use crate::{
    app::AppError,
    config::CircuitBreaker,
    utils::{
        health::check_database_health,
        postgres::{metrics::RepositoryMetrics, prepared_cache::PreparedStatementCache},
    },
};
use deadpool_postgres::Pool;
use std::sync::Arc;
use tokio_postgres::types::ToSql;

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

    pub async fn check_database_health(&self) -> crate::auth::dto::response::ServiceHealth {
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

    pub async fn execute_prepared_opt(
        &self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<tokio_postgres::Row>, AppError> {
        let client = self.db.get().await?;
        let stmt = self.prepared_cache.get_or_prepare(&client, query).await?;
        Ok(client.query_opt(&stmt, params).await?)
    }
}

pub trait FromRow: Sized {
    fn from_row(row: &tokio_postgres::Row) -> Result<Self, AppError>;
}

#[allow(dead_code)]
pub struct UpdateQueryBuilder {
    updates: Vec<String>,
    param_idx: i32,
}

#[allow(dead_code)]
impl UpdateQueryBuilder {
    pub fn new() -> Self {
        Self {
            updates: Vec::new(),
            param_idx: 2, // Start from $2 (assuming $1 is the ID)
        }
    }

    pub fn add_field<T>(&mut self, field_name: &str, value: &Option<T>) -> &mut Self {
        if value.is_some() {
            self.updates
                .push(format!("{} = ${}", field_name, self.param_idx));
            self.param_idx += 1;
        }
        self
    }

    pub fn build(&self, table: &str) -> Option<String> {
        if self.updates.is_empty() {
            None
        } else {
            Some(format!(
                "UPDATE {} SET {} WHERE id = $1",
                table,
                self.updates.join(", ")
            ))
        }
    }

    pub fn build_returning(&self, table: &str) -> Option<String> {
        if self.updates.is_empty() {
            None
        } else {
            Some(format!(
                "UPDATE {} SET {} WHERE id = $1 RETURNING *",
                table,
                self.updates.join(", ")
            ))
        }
    }

    pub fn is_empty(&self) -> bool {
        self.updates.is_empty()
    }
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
