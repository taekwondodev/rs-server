
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum_extra::extract::CookieJar;
use domain_auth::{
    AccessTokenClaims, AuthRepository, ClientContext, DomainError, JwtService, RegistrationKind,
};

use crate::{
    dto::{
        BeginRequest, BeginResponse, CredentialResponse, FinishCredentialRequest, FinishRequest,
        HealthResponse, MessageResponse, TokenResponse,
    },
    error::HttpError,
    middleware::metrics,
    state::AppState,
    validation::decode_credential_id,
};

/// Begin user registration
///
/// Initiates the WebAuthn registration process for a new user.
/// Returns challenge options that the client needs to use for credential creation.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/auth/register/begin",
    tag = "Authentication",
    request_body = BeginRequest,
    responses(
        (status = 200, description = "Registration process started successfully", body = BeginResponse),
        (status = 400, description = "Invalid request data", body = crate::error::ErrorResponse),
        (status = 409, description = "Username already exists", body = crate::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ErrorResponse),
        (status = 503, description = "Service temporarily unavailable", body = crate::error::ErrorResponse)
    )
))]
pub async fn begin_register<R, J>(
    State(state): State<AppState<R, J>>,
    request: BeginRequest,
) -> Result<BeginResponse, HttpError>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    match state.auth_service.begin_register(request.into()).await {
        Ok((result, kind)) => {
            if kind == RegistrationKind::Resumed {
                metrics::track_registration_conflict("resumed");
            }
            metrics::track_registration_attempt(true);
            Ok(result.into())
        }
        Err(e) => {
            if let DomainError::Conflict(_) = e {
                metrics::track_registration_conflict("taken");
            }
            metrics::track_registration_attempt(false);
            Err(e.into())
        }
    }
}

/// Finish user registration
///
/// Completes the WebAuthn registration process by verifying the client's credential
/// and storing it in the database.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/auth/register/finish",
    tag = "Authentication",
    request_body = FinishRequest,
    responses(
        (status = 200, description = "Registration completed successfully!", body = MessageResponse),
        (status = 400, description = "Invalid request data or credentials", body = crate::error::ErrorResponse),
        (status = 404, description = "User or session not found", body = crate::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ErrorResponse),
        (status = 503, description = "Service temporarily unavailable", body = crate::error::ErrorResponse)
    )
))]
pub async fn finish_register<R, J>(
    State(state): State<AppState<R, J>>,
    client: ClientContext,
    request: FinishRequest,
) -> Result<MessageResponse, HttpError>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    let mut cmd: domain_auth::FinishCommand = request.into();
    cmd.client = client;

    let response = state.auth_service.finish_register(cmd).await;
    metrics::track_registration_attempt(response.is_ok());
    Ok(response?.into())
}

/// Begin user login
///
/// Initiates the WebAuthn authentication process for an existing user.
/// Returns challenge options for credential verification.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/auth/login/begin",
    tag = "Authentication",
    request_body = BeginRequest,
    responses(
        (status = 200, description = "Login process started successfully", body = BeginResponse),
        (status = 400, description = "Invalid request data", body = crate::error::ErrorResponse),
        (status = 401, description = "Authentication failed", body = crate::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ErrorResponse),
        (status = 503, description = "Service temporarily unavailable", body = crate::error::ErrorResponse)
    )
))]
pub async fn begin_login<R, J>(
    State(state): State<AppState<R, J>>,
    request: BeginRequest,
) -> Result<BeginResponse, HttpError>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    let response = state.auth_service.begin_login(request.into()).await;
    metrics::track_login_attempt(response.is_ok());
    Ok(response?.into())
}

/// Finish user login
///
/// Completes the WebAuthn authentication process and returns access tokens.
/// Sets a refresh token cookie for subsequent token refresh operations.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/auth/login/finish",
    tag = "Authentication",
    request_body = FinishRequest,
    responses(
        (status = 200, description = "Login completed successfully!", body = TokenResponse),
        (status = 400, description = "Invalid credentials", body = crate::error::ErrorResponse),
        (status = 401, description = "Authentication failed", body = crate::error::ErrorResponse),
        (status = 404, description = "User or session not found", body = crate::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ErrorResponse),
        (status = 503, description = "Service temporarily unavailable", body = crate::error::ErrorResponse)
    )
))]
pub async fn finish_login<R, J>(
    jar: CookieJar,
    State(state): State<AppState<R, J>>,
    client: ClientContext,
    request: FinishRequest,
) -> Result<(CookieJar, TokenResponse), HttpError>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    let mut cmd: domain_auth::FinishCommand = request.into();
    cmd.client = client;

    let result = state.auth_service.finish_login(cmd).await;
    metrics::track_login_attempt(result.is_ok());
    let (response, refresh_token) = result?;

    let cookie = state.cookie_service.create_refresh_token_cookie(&refresh_token);
    let updated_jar = jar.add(cookie);

    Ok((updated_jar, response.into()))
}

/// Begin adding a passkey to the authenticated user's account.
///
/// Starts a WebAuthn registration ceremony scoped to the account identified
/// by the Bearer token. Existing credential ids are returned as
/// `excludeCredentials`, so the same authenticator cannot be enrolled twice.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/auth/credentials/begin",
    tag = "Authentication",
    responses(
        (status = 200, description = "Add-credential ceremony started successfully", body = BeginResponse),
        (status = 400, description = "Invalid request data", body = crate::error::ErrorResponse),
        (status = 401, description = "Authentication failed", body = crate::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ErrorResponse),
        (status = 503, description = "Service temporarily unavailable", body = crate::error::ErrorResponse)
    )
))]
pub async fn begin_add_credential<R, J>(
    State(state): State<AppState<R, J>>,
    claims: AccessTokenClaims,
) -> Result<BeginResponse, HttpError>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    let cmd = domain_auth::AddCredentialCommand {
        user_id: claims.sub,
        username: claims.username,
    };
    let response = state.auth_service.begin_add_credential(cmd).await;
    metrics::track_credential_operation("add_begin", response.is_ok());
    Ok(response?.into())
}

/// Finish adding a passkey to the authenticated user's account.
///
/// Completes the ceremony started by `begin_add_credential` and stores the
/// new passkey (with an optional human-readable name) on the account.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/auth/credentials/finish",
    tag = "Authentication",
    request_body = FinishCredentialRequest,
    responses(
        (status = 200, description = "Credential added successfully!", body = MessageResponse),
        (status = 400, description = "Invalid request data or credentials", body = crate::error::ErrorResponse),
        (status = 401, description = "Authentication failed", body = crate::error::ErrorResponse),
        (status = 404, description = "User or session not found", body = crate::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ErrorResponse),
        (status = 503, description = "Service temporarily unavailable", body = crate::error::ErrorResponse)
    )
))]
pub async fn finish_add_credential<R, J>(
    State(state): State<AppState<R, J>>,
    client: ClientContext,
    claims: AccessTokenClaims,
    request: FinishCredentialRequest,
) -> Result<MessageResponse, HttpError>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    let cmd = domain_auth::FinishAddCredentialCommand {
        user_id: claims.sub,
        session_id: request.session_id,
        credentials: request.credentials,
        name: request.name,
        client,
    };

    let response = state.auth_service.finish_add_credential(cmd).await;
    metrics::track_credential_operation("add_finish", response.is_ok());
    Ok(response?.into())
}

/// List the authenticated user's passkeys.
///
/// Returns the credential ids (base64url-encoded), optional names, and
/// timestamps. No identifier of any other user is ever visible.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/auth/credentials",
    tag = "Authentication",
    responses(
        (status = 200, description = "List of passkeys for the authenticated user", body = Vec<CredentialResponse>),
        (status = 401, description = "Authentication failed", body = crate::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ErrorResponse),
        (status = 503, description = "Service temporarily unavailable", body = crate::error::ErrorResponse)
    )
))]
pub async fn list_credentials<R, J>(
    State(state): State<AppState<R, J>>,
    claims: AccessTokenClaims,
) -> Result<Json<Vec<CredentialResponse>>, HttpError>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    let response = state.auth_service.list_credentials(claims.sub).await;
    metrics::track_credential_operation("list", response.is_ok());
    Ok(Json(response?.into_iter().map(CredentialResponse::from).collect()))
}

/// Remove one of the authenticated user's passkeys.
///
/// Refuses to remove the last remaining credential — that would lock the
/// account out permanently (login needs a credential, re-registration is
/// only possible before activation).
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/auth/credentials/{cred_id}",
    tag = "Authentication",
    params(
        ("cred_id" = String, Path, description = "Base64url-encoded credential id"),
    ),
    responses(
        (status = 200, description = "Credential removed successfully!", body = MessageResponse),
        (status = 400, description = "Invalid credential id", body = crate::error::ErrorResponse),
        (status = 401, description = "Authentication failed", body = crate::error::ErrorResponse),
        (status = 404, description = "Credential not found", body = crate::error::ErrorResponse),
        (status = 409, description = "Cannot remove the last credential", body = crate::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ErrorResponse),
        (status = 503, description = "Service temporarily unavailable", body = crate::error::ErrorResponse)
    )
))]
pub async fn remove_credential<R, J>(
    State(state): State<AppState<R, J>>,
    client: ClientContext,
    claims: AccessTokenClaims,
    Path(encoded_id): Path<String>,
) -> Result<MessageResponse, HttpError>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    let cred_id = decode_credential_id(&encoded_id)?;
    let cmd = domain_auth::RemoveCredentialCommand {
        user_id: claims.sub,
        cred_id,
        client,
    };

    let response = state.auth_service.remove_credential(cmd).await;
    metrics::track_credential_operation("remove", response.is_ok());
    Ok(response?.into())
}

/// Refresh access token
///
/// Uses the refresh token from cookies to generate a new access token.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "Authentication",
    responses(
        (status = 200, description = "Refresh completed successfully!", body = TokenResponse),
        (status = 401, description = "Invalid or expired refresh token", body = crate::error::ErrorResponse),
        (status = 500, description = "Internal server error", body = crate::error::ErrorResponse),
        (status = 503, description = "Service temporarily unavailable", body = crate::error::ErrorResponse)
    )
))]
pub async fn refresh<R, J>(
    jar: CookieJar,
    State(state): State<AppState<R, J>>,
    client: ClientContext,
) -> Result<(CookieJar, TokenResponse), HttpError>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    let refresh_token = state.cookie_service.get_refresh_token_from_jar(&jar)?;
    let result = state.auth_service.refresh(&refresh_token, &client).await;
    metrics::track_token_operation("refresh", result.is_ok());
    let (response, new_refresh_token) = result?;

    let cookie = state.cookie_service.create_refresh_token_cookie(&new_refresh_token);
    let updated_jar = jar.add(cookie);

    Ok((updated_jar, response.into()))
}

/// Logout user
///
/// Invalidates the current refresh token and clears authentication cookies.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/auth/logout",
    tag = "Authentication",
    responses(
        (status = 200, description = "Logout completed successfully!", body = MessageResponse),
        (status = 500, description = "Internal server error", body = crate::error::ErrorResponse),
        (status = 503, description = "Service temporarily unavailable", body = crate::error::ErrorResponse)
    )
))]
pub async fn logout<R, J>(
    jar: CookieJar,
    State(state): State<AppState<R, J>>,
    client: ClientContext,
) -> Result<(CookieJar, MessageResponse), HttpError>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    let refresh_token = state.cookie_service.get_refresh_token_from_jar(&jar).unwrap_or_default();
    let response = state.auth_service.logout(&refresh_token, &client).await;
    metrics::track_token_operation("logout", response.is_ok());

    let clear_cookie = state.cookie_service.clear_refresh_token_cookie();
    let updated_jar = jar.add(clear_cookie);

    Ok((updated_jar, response?.into()))
}

/// Comprehensive health check
///
/// Checks the health of all critical services including database, Redis.
/// Returns detailed status information and appropriate HTTP status codes.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/healthz",
    tag = "Health",
    responses(
        (status = 200, description = "All services are healthy", body = HealthResponse),
        (status = 503, description = "One or more services are unhealthy", body = HealthResponse),
    )
))]
pub async fn healthz<R, J>(State(state): State<AppState<R, J>>) -> impl IntoResponse
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    let report = rs_repository_utils::check_all(&state.health_indicators).await;
    let healthy = report.is_healthy();
    metrics::track_health_check(healthy);

    let status = if healthy { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, HealthResponse::from_report(report))
}
