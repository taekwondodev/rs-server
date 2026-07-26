//! Pure process bootstrap — no axum/routing concerns, so it lives in the bin
//! crate rather than `http` (which only keeps the `http_trace_layer!` macro).
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer().json().with_filter(
                tracing_subscriber::filter::Targets::new()
                    .with_target("tower_http::trace", tracing::Level::INFO)
                    .with_target("rs_passkey_auth", tracing::Level::INFO)
                    .with_default(tracing::Level::INFO),
            ),
        )
        .init();
}
