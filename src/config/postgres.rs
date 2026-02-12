use std::{env, time::Duration};

use deadpool_postgres::{Config, ManagerConfig, Pool, Runtime};
use tokio_postgres::NoTls;

const DB_MAX_SIZE: usize = 10;
const DB_CONNECTION_TIMEOUT_SECS: u64 = 10;
const DB_WAIT_TIMEOUT_SECS: u64 = 30;
const DB_RECYCLE_TIMEOUT_SECS: u64 = 60;

#[derive(Debug)]
pub struct DbConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub dbname: String,
    pub max_size: usize,
    pub connection_timeout: Duration,
    pub wait_timeout: Duration,
    pub recycle_timeout: Duration,
}

impl DbConfig {
    pub fn from_env() -> Self {
        let host = env::var("DB_HOST").unwrap();
        let port = env::var("DB_PORT").unwrap().parse().unwrap();
        let user = env::var("POSTGRES_USER").unwrap();
        let password = env::var("POSTGRES_PASSWORD").unwrap();
        let dbname = env::var("POSTGRES_DB").unwrap();

        Self {
            host,
            port,
            user,
            password,
            dbname,
            max_size: DB_MAX_SIZE,
            connection_timeout: Duration::from_secs(DB_CONNECTION_TIMEOUT_SECS),
            wait_timeout: Duration::from_secs(DB_WAIT_TIMEOUT_SECS),
            recycle_timeout: Duration::from_secs(DB_RECYCLE_TIMEOUT_SECS),
        }
    }

    pub fn to_deadpool_config(&self) -> Config {
        let mut cfg = Config::new();
        cfg.host = Some(self.host.clone());
        cfg.port = Some(self.port);
        cfg.user = Some(self.user.clone());
        cfg.password = Some(self.password.clone());
        cfg.dbname = Some(self.dbname.clone());
        let mut pool_config = deadpool_postgres::PoolConfig::new(self.max_size);
        pool_config.timeouts.wait = Some(self.wait_timeout);
        pool_config.timeouts.create = Some(self.connection_timeout);
        pool_config.timeouts.recycle = Some(self.recycle_timeout);
        cfg.pool = Some(pool_config);
        cfg.manager = Some(ManagerConfig {
            recycling_method: deadpool_postgres::RecyclingMethod::Fast,
        });
        cfg
    }

    pub fn create_pool(&self) -> Pool {
        let config = self.to_deadpool_config();
        config.create_pool(Some(Runtime::Tokio1), NoTls).unwrap()
    }
}
