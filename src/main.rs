use crate::app::{AppConfig, AppState, ServerConfig, create_router, init_tracing, start_server};

mod app;
mod auth;
mod config;
mod utils;

#[tokio::main]
async fn main() {
    init_tracing();

    let params = AppConfig::from_env().await;
    let cors_layer = params.origin_config.create_cors_layer();

    let state = AppState::new(params);
    let app = create_router(state).layer(cors_layer);

    let server_config = ServerConfig::default();
    start_server(app, &server_config.bind_addr).await
}
