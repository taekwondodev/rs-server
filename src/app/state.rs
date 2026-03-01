use std::sync::Arc;

use deadpool_postgres::Pool;
use redis::aio::ConnectionManager;
use webauthn_rs::Webauthn;

use crate::{
    auth::{self, jwt::Jwt, service::AuthService},
    config::{
        CircuitBreaker, CircuitBreakerConfig, DbConfig, JwtConfig, OriginConfig, RedisConfig,
        WebAuthnConfig,
    },
    utils::CookieService,
};

pub struct AppConfig {
    pub webauthn: Webauthn,
    pub db: Pool,
    pub redis_manager: ConnectionManager,
    pub jwt_config: JwtConfig,
    pub origin_config: OriginConfig,
    pub circuit_breaker_config: CircuitBreakerConfig,
}

impl AppConfig {
    pub async fn from_env() -> Self {
        let db_config = DbConfig::from_env();
        let db = db_config.create_pool();

        let origin_config = OriginConfig::from_env();
        let webauthn_config = WebAuthnConfig::from_env();
        let webauthn = webauthn_config.create_webauthn(&origin_config);

        let redis_config = RedisConfig::from_env();
        let redis_manager = redis_config.create_conn_manager().await;

        let jwt_config = JwtConfig::from_env();

        let circuit_breaker_config = CircuitBreakerConfig::default();

        Self {
            webauthn,
            db,
            redis_manager,
            jwt_config,
            origin_config,
            circuit_breaker_config,
        }
    }
}

pub struct AppState {
    pub auth_service: Arc<AuthService<auth::Repository, Jwt>>,
    pub jwt_service: Arc<Jwt>,
    pub cookie_service: Arc<CookieService>,
}

impl AppState {
    pub fn new(params: AppConfig) -> Arc<Self> {
        let db_circuit_breaker = Arc::new(CircuitBreaker::new(
            "database",
            params.circuit_breaker_config,
        ));
        let redis_circuit_breaker =
            Arc::new(CircuitBreaker::new("redis", params.circuit_breaker_config));

        let user_repo = Arc::new(auth::Repository::new(params.db, db_circuit_breaker));
        let jwt_service = Arc::new(Jwt::new(
            &params.jwt_config,
            params.redis_manager,
            redis_circuit_breaker,
        ));
        let auth_service = Arc::new(AuthService::new(
            params.webauthn,
            user_repo,
            Arc::clone(&jwt_service),
        ));
        let cookie_service = Arc::new(CookieService::new(&params.origin_config));

        Arc::new(Self {
            auth_service,
            jwt_service,
            cookie_service,
        })
    }
}
