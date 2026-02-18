use std::sync::Arc;

use axum::extract::State;
use axum_extra::extract::CookieJar;

use crate::{
    app::{AppError, AppState, middleware::metrics},
    auth::dto::{
        BeginRequest, BeginResponse, FinishRequest, HealthResponse, MessageResponse, TokenResponse,
    },
};

/// Begin user registration
///
/// Initiates the WebAuthn registration process for a new user.
/// Returns challenge options that the client needs to use for credential creation.
#[utoipa::path(
    post,
    path = "/auth/register/begin",
    tag = "Authentication",
    request_body = BeginRequest,
    responses(
        (status = 200, description = "Registration process started successfully", body = BeginResponse),
        (status = 400, description = "Invalid request data", body = crate::app::error::ErrorResponse),
        (status = 409, description = "User already exists", body = crate::app::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::app::error::ErrorResponse)
    )
)]
pub async fn begin_register(
    State(state): State<Arc<AppState>>,
    request: BeginRequest,
) -> Result<BeginResponse, AppError> {
    let response = state.auth_service.begin_register(request).await;
    metrics::track_registration_attempt(response.is_ok());
    response
}

/// Finish user registration
///
/// Completes the WebAuthn registration process by verifying the client's credential
/// and storing it in the database.
#[utoipa::path(
    post,
    path = "/auth/register/finish",
    tag = "Authentication",
    request_body = FinishRequest,
    responses(
        (status = 200, description = "Registration completed successfully!", body = MessageResponse),
        (status = 400, description = "Invalid request data or credentials", body = crate::app::error::ErrorResponse),
        (status = 404, description = "Session not found", body = crate::app::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::app::error::ErrorResponse)
    )
)]
pub async fn finish_register(
    State(state): State<Arc<AppState>>,
    request: FinishRequest,
) -> Result<MessageResponse, AppError> {
    let response = state.auth_service.finish_register(request).await;
    metrics::track_registration_attempt(response.is_ok());
    response
}

/// Begin user login
///
/// Initiates the WebAuthn authentication process for an existing user.
/// Returns challenge options for credential verification.
#[utoipa::path(
    post,
    path = "/auth/login/begin",
    tag = "Authentication",
    request_body = BeginRequest,
    responses(
        (status = 200, description = "Login process started successfully", body = BeginResponse),
        (status = 400, description = "Invalid request data", body = crate::app::error::ErrorResponse),
        (status = 404, description = "User not found", body = crate::app::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::app::error::ErrorResponse)
    )
)]
pub async fn begin_login(
    State(state): State<Arc<AppState>>,
    request: BeginRequest,
) -> Result<BeginResponse, AppError> {
    let response = state.auth_service.begin_login(request).await;
    metrics::track_login_attempt(response.is_ok());
    response
}

/// Finish user login
///
/// Completes the WebAuthn authentication process and returns access tokens.
/// Sets a refresh token cookie for subsequent token refresh operations.
#[utoipa::path(
    post,
    path = "/auth/login/finish",
    tag = "Authentication",
    request_body = FinishRequest,
    responses(
        (status = 200, description = "Login completed successfully!", body = TokenResponse),
        (status = 400, description = "Invalid credentials", body = crate::app::error::ErrorResponse),
        (status = 401, description = "Authentication failed", body = crate::app::error::ErrorResponse),
        (status = 404, description = "User or session not found", body = crate::app::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::app::error::ErrorResponse)
    )
)]
pub async fn finish_login(
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
    request: FinishRequest,
) -> Result<(CookieJar, TokenResponse), AppError> {
    let result = state.auth_service.finish_login(request).await;
    metrics::track_login_attempt(result.is_ok());
    let (response, refresh_token) = result?;

    let cookie = state
        .cookie_service
        .create_refresh_token_cookie(&refresh_token);
    let updated_jar = jar.add(cookie);

    Ok((updated_jar, response))
}

/// Refresh access token
///
/// Uses the refresh token from cookies to generate a new access token.
#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "Authentication",
    responses(
        (status = 200, description = "Refresh completed successfully!", body = TokenResponse),
        (status = 401, description = "Invalid or expired refresh token", body = crate::app::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::app::error::ErrorResponse)
    )
)]
pub async fn refresh(
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
) -> Result<(CookieJar, TokenResponse), AppError> {
    let refresh_token = state.cookie_service.get_refresh_token_from_jar(&jar)?;
    let result = state.auth_service.refresh(refresh_token.as_str()).await;
    metrics::track_token_operation("refresh", result.is_ok());
    let (response, new_refresh_token) = result?;

    let cookie = state
        .cookie_service
        .create_refresh_token_cookie(&new_refresh_token);
    let updated_jar = jar.add(cookie);

    Ok((updated_jar, response))
}

/// Logout user
///
/// Invalidates the current refresh token and clears authentication cookies.
#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "Authentication",
    responses(
        (status = 200, description = "Logout completed successfully!", body = MessageResponse),
        (status = 500, description = "Internal server error", body = crate::app::error::ErrorResponse)
    )
)]
pub async fn logout(
    jar: CookieJar,
    State(state): State<Arc<AppState>>,
) -> Result<(CookieJar, MessageResponse), AppError> {
    let refresh_token = state
        .cookie_service
        .get_refresh_token_from_jar(&jar)
        .unwrap_or_default();
    let response = state.auth_service.logout(refresh_token.as_str()).await;
    metrics::track_token_operation("logout", response.is_ok());

    let clear_cookie = state.cookie_service.clear_refresh_token_cookie();
    let updated_jar = jar.add(clear_cookie);

    Ok((updated_jar, response?))
}

/// Comprehensive health check
///
/// Checks the health of all critical services including database, Redis.
/// Returns detailed status information and appropriate HTTP status codes.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "Health",
    responses(
        (status = 200, description = "All services are healthy", body = HealthResponse),
        (status = 503, description = "One or more services are unhealthy", body = HealthResponse),
    )
)]
pub async fn healthz(State(state): State<Arc<AppState>>) -> Result<HealthResponse, AppError> {
    let response = state.auth_service.check_health().await;
    metrics::track_health_check(response.is_ok());
    response
}
