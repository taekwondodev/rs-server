//! Pure process bootstrap — starts the axum servers and handles graceful
//! shutdown. Doesn't touch any of `http`'s internal types (just `axum::Router`),
//! so it stays in the `rs-server` bin crate rather than in `http` itself.
use std::env;

use axum::Router;
use tokio::net::TcpListener;

pub struct ServerConfig {
    pub bind_addr: Box<str>,
    pub internal_bind_addr: Box<str>,
}

impl ServerConfig {
    pub fn from_env() -> Self {
        let server_port: u16 = env::var("SERVER_PORT").unwrap().parse().unwrap();
        let internal_port: u16 = env::var("INTERNAL_PORT").unwrap().parse().unwrap();

        Self {
            bind_addr: format!("0.0.0.0:{server_port}").into_boxed_str(),
            internal_bind_addr: format!("0.0.0.0:{internal_port}").into_boxed_str(),
        }
    }
}

/// Runs the public router and the internal (`/healthz` + `/metrics`) router
/// on two separate listeners concurrently. `internal_bind_addr` must stay
/// unpublished in `compose.yaml`'s `ports:` — that's what keeps it off the
/// public internet while still reachable container-to-container (e.g. by
/// Prometheus).
pub async fn start_servers(public_app: Router, internal_app: Router, config: &ServerConfig) {
    let public_listener = TcpListener::bind(&*config.bind_addr).await.unwrap();
    let internal_listener = TcpListener::bind(&*config.internal_bind_addr).await.unwrap();

    tracing::info!("Server listening on http://{}", config.bind_addr);

    let public_serve = axum::serve(
        public_listener,
        public_app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal());
    let internal_serve =
        axum::serve(internal_listener, internal_app).with_graceful_shutdown(shutdown_signal());

    let (public_result, internal_result) = tokio::join!(public_serve, internal_serve);
    public_result.unwrap();
    internal_result.unwrap();

    tracing::info!("Server shutdown completed");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown...");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown...");
        },
    }

    tracing::info!("Waiting for ongoing requests to complete...");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}
