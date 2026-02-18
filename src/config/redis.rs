use std::env;

use redis::{Client, aio::ConnectionManager};

#[derive(Debug)]
pub struct RedisConfig {
    pub url: Box<str>,
}

impl RedisConfig {
    pub fn from_env() -> Self {
        let url = env::var("REDIS_URL").unwrap().into_boxed_str();
        Self { url }
    }

    pub async fn create_conn_manager(&self) -> ConnectionManager {
        let client = Client::open(&*self.url).unwrap();
        ConnectionManager::new(client).await.unwrap()
    }
}
