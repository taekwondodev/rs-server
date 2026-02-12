use std::sync::Arc;

use deadpool_postgres::Pool;
use redis::aio::ConnectionManager;
use webauthn_rs::Webauthn;

use crate::{
    auth::{jwt::Jwt, repo::Repository, service::AuthService},
    config::{circuit_breaker::CircuitBreakerConfig, origin::OriginConfig, CircuitBreaker},
    utils::cookie::CookieService,
};

pub type Service = AuthService<Repository, Jwt>;

pub struct AppState {
    pub auth_service: Arc<Service>,
    pub cookie_service: Arc<CookieService>,
}

impl AppState {
    pub fn new(
        webauthn: Webauthn,
        db: Pool,
        redis_manager: ConnectionManager,
        origin_config: OriginConfig,
        circuit_breaker_config: CircuitBreakerConfig,
    ) -> Arc<Self> {
        let db_circuit_breaker = Arc::new(CircuitBreaker::new(
            "database",
            circuit_breaker_config.clone(),
        ));
        let redis_circuit_breaker = Arc::new(CircuitBreaker::new("redis", circuit_breaker_config));

        let user_repo = Arc::new(Repository::new(db, db_circuit_breaker));
        let jwt_service = Arc::new(Jwt::new(redis_manager, redis_circuit_breaker));
        let auth_service = Arc::new(AuthService::new(webauthn, user_repo, jwt_service));
        let cookie_service = Arc::new(CookieService::new(&origin_config));

        Arc::new(Self {
            auth_service,
            cookie_service,
        })
    }
}
