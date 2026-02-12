use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::{Arc, RwLock},
};

use tokio_postgres::{Client, Statement};

use crate::app::AppError;

#[derive(Clone)]
pub struct PreparedStatementCache {
    cache: Arc<RwLock<HashMap<QueryKey, Statement>>>,
}

#[derive(Eq, Clone)]
struct QueryKey {
    query: String,
}

impl PartialEq for QueryKey {
    fn eq(&self, other: &Self) -> bool {
        self.query == other.query
    }
}

impl Hash for QueryKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.query.hash(state);
    }
}

impl PreparedStatementCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_or_prepare(
        &self,
        client: &Client,
        query: &str,
    ) -> Result<Statement, AppError> {
        let key = QueryKey {
            query: query.to_string(),
        };

        {
            let cache = self.cache.read().map_err(|_| {
                AppError::InternalServer("Failed to acquire cache read lock".to_string())
            })?;

            if let Some(stmt) = cache.get(&key) {
                return Ok(stmt.clone());
            }
        }

        let stmt = client.prepare(query).await?;

        {
            let mut cache = self.cache.write().map_err(|_| {
                AppError::InternalServer("Failed to acquire cache write lock".to_string())
            })?;

            cache.insert(key, stmt.clone());
        }

        Ok(stmt)
    }

    pub fn clear(&self) -> Result<(), AppError> {
        let mut cache = self.cache.write().map_err(|_| {
            AppError::InternalServer("Failed to acquire cache write lock".to_string())
        })?;

        cache.clear();
        Ok(())
    }

    pub fn size(&self) -> Result<usize, AppError> {
        let cache = self.cache.read().map_err(|_| {
            AppError::InternalServer("Failed to acquire cache read lock".to_string())
        })?;

        Ok(cache.len())
    }
}

impl Default for PreparedStatementCache {
    fn default() -> Self {
        Self::new()
    }
}
