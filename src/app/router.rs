use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
#[cfg(feature = "openapi")]
use utoipa::OpenApi;
#[cfg(feature = "openapi")]
use utoipa_axum::router::OpenApiRouter;
#[cfg(feature = "openapi")]
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    app::{AppState, middleware::metrics},
    auth::handler,
    http_trace_layer,
};

#[cfg(feature = "openapi")]
#[derive(OpenApi)]
#[openapi(
    paths(
        handler::begin_register,
        handler::finish_register,
        handler::begin_login,
        handler::finish_login,
        handler::refresh,
        handler::logout,
        handler::healthz,
        metrics::metrics_handler,
    ),
    components(
        schemas(
            crate::auth::dto::BeginRequest,
            crate::auth::dto::FinishRequest,
            crate::auth::dto::BeginResponse,
            crate::auth::dto::MessageResponse,
            crate::auth::dto::TokenResponse,
            crate::app::error::ErrorResponse,
            crate::auth::dto::HealthResponse,
            crate::auth::dto::ServiceHealth,
            crate::auth::dto::HealthChecks,
            crate::auth::dto::HealthStatus,
        )
    ),
    tags(
        (name = "Authentication", description = "WebAuthn-based authentication endpoints"),
         (name = "Monitoring", description = "Prometheus metrics endpoint"),
          (name = "Health", description = "Health check endpoints")
    ),
    info(
        title = "server API",
        description = "A secure service using WebAuthn passkeys and JWT tokens",
        version = "0.1.0",
        license(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT",
        ),
    )
)]
struct ApiDoc;

#[cfg(feature = "openapi")]
pub fn create_router(state: std::sync::Arc<AppState>) -> axum::Router {
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .route("/auth/register/begin", post(handler::begin_register))
        .route("/auth/register/finish", post(handler::finish_register))
        .route("/auth/login/begin", post(handler::begin_login))
        .route("/auth/login/finish", post(handler::finish_login))
        .route("/auth/refresh", post(handler::refresh))
        .route("/auth/logout", post(handler::logout))
        .route("/healthz", get(handler::healthz))
        .with_state(state.clone())
        .split_for_parts();

    let router = router.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api));

    finalize_router(router, state)
}

#[cfg(not(feature = "openapi"))]
pub fn create_router(state: std::sync::Arc<AppState>) -> axum::Router {
    let router = axum::Router::new()
        .route("/auth/register/begin", post(handler::begin_register))
        .route("/auth/register/finish", post(handler::finish_register))
        .route("/auth/login/begin", post(handler::begin_login))
        .route("/auth/login/finish", post(handler::finish_login))
        .route("/auth/refresh", post(handler::refresh))
        .route("/auth/logout", post(handler::logout))
        .route("/healthz", get(handler::healthz))
        .with_state(state.clone());

    finalize_router(router, state)
}

fn finalize_router(router: axum::Router, state: std::sync::Arc<AppState>) -> axum::Router {
    let service_builder = ServiceBuilder::new()
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(http_trace_layer!())
        .layer(metrics::create_prometheus_layer());

    let router = router.route("/metrics", get(metrics::metrics_handler));

    #[cfg(feature = "gateway")]
    let router = router.merge(
        axum::Router::new()
            .route("/*path", axum::routing::any(crate::app::middleware::gateway::proxy_stub))
            .layer(axum::middleware::from_fn_with_state(
                state,
                crate::app::middleware::gateway::inject_user_headers,
            )),
    );
    #[cfg(not(feature = "gateway"))]
    let _ = state;

    router.layer(service_builder)
}
