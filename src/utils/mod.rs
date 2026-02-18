pub(crate) mod cookie;
pub(crate) mod health;
pub(crate) mod postgres;
pub(crate) mod redis;
pub(crate) mod validation;

pub(crate) use cookie::CookieService;
pub(crate) use health::{check_database_health, check_redis_health};
#[cfg_attr(not(feature = "strict"), allow(unused_imports))]
pub(crate) use postgres::{
    BaseRepository, DeleteBuilder, FromRow, InsertBuilder, RepositoryMetrics, SelectBuilder,
    UpdateBuilder,
};
pub(crate) use redis::BaseRedisRepository;
pub(crate) use validation::{
    Validatable, validate_json_credentials, validate_text, validate_username,
};

#[cfg(test)]
mod tests;
