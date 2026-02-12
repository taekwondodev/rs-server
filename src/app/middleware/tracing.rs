use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

pub fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer().with_filter(
                tracing_subscriber::filter::Targets::new()
                    .with_target("tower_http::trace", tracing::Level::INFO)
                    .with_target("rs_passkey_auth", tracing::Level::INFO)
                    .with_default(tracing::Level::INFO),
            ),
        )
        .init();
}

#[macro_export]
macro_rules! http_trace_layer {
    () => {
        TraceLayer::new_for_http()
            .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO))
            .on_request(|request: &axum::http::Request<_>, _span: &tracing::Span| {
                tracing::info!("Started {} {}", request.method(), request.uri());
            })
            .on_response(
                |response: &axum::http::Response<_>,
                 latency: std::time::Duration,
                 _span: &tracing::Span| {
                    tracing::info!(
                        "Completed with status {} in {:?}",
                        response.status(),
                        latency
                    );
                },
            )
    };
}
