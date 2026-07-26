use std::{env, time::Duration};

use deadpool_postgres::{Config, ManagerConfig, Pool, Runtime};
use tokio_postgres::NoTls;

const DB_MAX_SIZE: usize = 10;
const DB_CONNECTION_TIMEOUT_SECS: u64 = 10;
const DB_WAIT_TIMEOUT_SECS: u64 = 30;
const DB_RECYCLE_TIMEOUT_SECS: u64 = 60;

#[derive(Debug)]
pub struct DbConfig {
    pub host: Box<str>,
    pub port: u16,
    pub user: Box<str>,
    pub password: Box<str>,
    pub dbname: Box<str>,
    pub max_size: usize,
    pub connection_timeout: Duration,
    pub wait_timeout: Duration,
    pub recycle_timeout: Duration,
}

impl DbConfig {
    pub fn from_env() -> Self {
        let host = env::var("DB_HOST").unwrap().into_boxed_str();
        let port = env::var("DB_PORT").unwrap().parse().unwrap();
        let user = env::var("POSTGRES_USER").unwrap().into_boxed_str();
        let password = env::var("POSTGRES_PASSWORD").unwrap().into_boxed_str();
        let dbname = env::var("POSTGRES_DB").unwrap().into_boxed_str();

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
        cfg.host = Some(self.host.to_string());
        cfg.port = Some(self.port);
        cfg.user = Some(self.user.to_string());
        cfg.password = Some(self.password.to_string());
        cfg.dbname = Some(self.dbname.to_string());

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
