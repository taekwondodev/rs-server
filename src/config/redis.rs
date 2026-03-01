use std::env;

use redis::{Client, aio::ConnectionManager};

#[derive(Debug)]
pub struct RedisConfig {
    pub url: Box<str>,
}

impl RedisConfig {
    pub fn from_env() -> Self {
        Self {
            url: format!(
                "redis://:{}@{}:{}",
                env::var("REDIS_PASSWORD").unwrap(),
                env::var("REDIS_HOST").unwrap(),
                env::var("REDIS_PORT").unwrap()
            )
            .into_boxed_str(),
        }
    }

    pub async fn create_conn_manager(&self) -> ConnectionManager {
        let client = Client::open(&*self.url).unwrap();
        ConnectionManager::new(client).await.unwrap()
    }
}
