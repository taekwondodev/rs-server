use std::sync::Arc;

use infra_jwt::{Jwt, JwtConfig, RedisConfig};
use infra_postgres::{DbConfig, Repository};
use rs_repository_utils::{CircuitBreaker, CircuitBreakerConfig};

mod server;
mod tracing_init;
mod webauthn;

#[tokio::main]
async fn main() {
    tracing_init::init_tracing();

    // --- infra-postgres: db pool + circuit breaker ---
    let db_config = DbConfig::from_env();
    let db = db_config.create_pool();

    // --- http: CORS + rp_id (also feeds WebAuthn's rp_id/rp_origin below) ---
    // CORS — browser-only enforcement. Remove if backend is consumed by mobile or non-browser clients.
    let origin_config = http::OriginConfig::from_env();
    let cors_layer = origin_config.create_cors_layer();

    // --- Webauthn: wired here since it fits neither infra crate cleanly ---
    let webauthn_config = webauthn::WebAuthnConfig::from_env();
    let webauthn = webauthn_config.create_webauthn(origin_config.rp_id(), origin_config.rp_origin());

    // --- infra-jwt: redis connection manager + jwt secret/issuer/audience ---
    let redis_config = RedisConfig::from_env();
    let redis_manager = redis_config.create_conn_manager().await;
    let jwt_config = JwtConfig::from_env();

    let circuit_breaker_config = CircuitBreakerConfig::default();
    let db_circuit_breaker = Arc::new(CircuitBreaker::new("database", circuit_breaker_config));
    let redis_circuit_breaker = Arc::new(CircuitBreaker::new("redis", circuit_breaker_config));

    // --- composition root: pick concrete R=Repository, J=Jwt and monomorphize ---
    let auth_repo = Arc::new(Repository::new(db, db_circuit_breaker));
    let jwt_service = Arc::new(Jwt::new(&jwt_config, redis_manager, redis_circuit_breaker));
    let auth_service = Arc::new(domain_auth::AuthService::new(
        webauthn,
        Arc::clone(&auth_repo),
        Arc::clone(&jwt_service),
    ));
    let cookie_service = Arc::new(http::CookieService::new(&origin_config));

    // Same underlying Repository/Jwt instances double as health indicators —
    // no separate connection/pool, just another trait implemented on them.
    let health_indicators: Vec<Arc<dyn rs_repository_utils::HealthIndicator>> = vec![
        Arc::clone(&auth_repo) as Arc<dyn rs_repository_utils::HealthIndicator>,
        Arc::clone(&jwt_service) as Arc<dyn rs_repository_utils::HealthIndicator>,
    ];

    let state = http::AppState {
        auth_service,
        jwt_service,
        cookie_service,
        health_indicators,
    };

    let app = http::create_router(state).layer(cors_layer);

    let server_config = server::ServerConfig::default();
    server::start_server(app, &server_config.bind_addr).await
}
