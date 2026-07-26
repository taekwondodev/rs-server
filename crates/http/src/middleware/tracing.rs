//! `init_tracing()` (pure process bootstrap, no axum) moved to the
//! `rs-server` bin crate. Only the axum/tower-http-touching trace layer macro
//! stays here.
#[macro_export]
macro_rules! http_trace_layer {
    () => {
        tower_http::trace::TraceLayer::new_for_http()
            .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO))
            .on_request(|request: &axum::http::Request<_>, _span: &tracing::Span| {
                tracing::info!("Started {} {}", request.method(), request.uri().path());
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
