use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    app::{AppState, error::ErrorResponse, middleware::metrics},
    auth::{
        dto::{
            BeginRequest, BeginResponse, FinishRequest, HealthChecks, HealthResponse, HealthStatus,
            MessageResponse, ServiceHealth, TokenResponse,
        },
        handler,
    },
    http_trace_layer,
};

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
            BeginRequest,
            FinishRequest,
            BeginResponse,
            MessageResponse,
            TokenResponse,
            ErrorResponse,
            HealthResponse,
            ServiceHealth,
            HealthChecks,
            HealthStatus,
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

pub fn create_router(state: std::sync::Arc<AppState>) -> axum::Router {
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .route("/auth/register/begin", post(handler::begin_register))
        .route("/auth/register/finish", post(handler::finish_register))
        .route("/auth/login/begin", post(handler::begin_login))
        .route("/auth/login/finish", post(handler::finish_login))
        .route("/auth/refresh", post(handler::refresh))
        .route("/auth/logout", post(handler::logout))
        .route("/healthz", get(handler::healthz))
        .with_state(state)
        .split_for_parts();

    let service_builder = ServiceBuilder::new()
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(http_trace_layer!())
        .layer(metrics::create_prometheus_layer());

    router
        .route("/metrics", get(metrics::metrics_handler))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api))
        .layer(service_builder)
}
