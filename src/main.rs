use crate::{
    app::{
        AppState, init_tracing,
        router::create_router,
        server::{ServerConfig, start_server},
    },
    config::{
        circuit_breaker::CircuitBreakerConfig, origin::OriginConfig, postgres::DbConfig,
        redis::RedisConfig, webauthn::WebAuthnConfig,
    },
};

mod app;
mod auth;
mod config;
mod utils;

#[tokio::main]
async fn main() {
    init_tracing();

    let db_config = DbConfig::from_env();
    let db_pool = db_config.create_pool();

    let origin_config = OriginConfig::from_env();
    let webauthn_config = WebAuthnConfig::from_env();
    let webauthn = webauthn_config.create_webauthn(&origin_config);
    let cors_layer = origin_config.create_cors_layer();

    let redis_config = RedisConfig::from_env();
    let manager = redis_config.create_conn_manager().await;
    let circuit_breaker_config = CircuitBreakerConfig::default();

    let state = AppState::new(
        webauthn,
        db_pool,
        manager,
        origin_config,
        circuit_breaker_config,
    );
    let app = create_router(state).layer(cors_layer);

    let server_config = ServerConfig::default();
    start_server(app, &server_config.bind_addr).await
}
