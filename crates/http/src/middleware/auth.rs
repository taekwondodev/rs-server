use axum::{extract::FromRequestParts, http::request::Parts};
use domain_auth::{AccessTokenClaims, AuthRepository, JwtService, SecurityEvent};

use crate::{error::HttpError, state::AppState};

const UNAUTHORIZED_MESSAGE: &str = "You are unauthorized";
const BEARER_PREFIX: &str = "Bearer ";

impl<R, J> FromRequestParts<AppState<R, J>> for AccessTokenClaims
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<R, J>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = extract_auth_header(parts).inspect_err(|_| {
            SecurityEvent::Unauthorized.emit();
        })?;
        is_bearer_token(auth_header).inspect_err(|_| {
            SecurityEvent::Unauthorized.emit();
        })?;
        let token = extract_token(auth_header);
        let claims = state
            .jwt_service
            .validate_access(token)
            .await
            .inspect_err(|_| {
                SecurityEvent::TokenRejected { reason: "invalid or expired access token" }.emit();
            })?;

        Ok(claims)
    }
}

#[cfg_attr(not(feature = "strict"), allow(dead_code))]
pub struct AdminClaims(pub AccessTokenClaims);

impl<R, J> FromRequestParts<AppState<R, J>> for AdminClaims
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    type Rejection = HttpError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<R, J>,
    ) -> Result<Self, Self::Rejection> {
        let claims = AccessTokenClaims::from_request_parts(parts, state).await?;

        match claims.role() {
            Some("admin") => Ok(AdminClaims(claims)),
            _ => {
                SecurityEvent::AdminDenied { user_id: claims.sub }.emit();
                Err(HttpError::unauthorized("Admin access required"))
            }
        }
    }
}

impl std::ops::Deref for AdminClaims {
    type Target = AccessTokenClaims;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn extract_auth_header(parts: &Parts) -> Result<&str, HttpError> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| HttpError::unauthorized(UNAUTHORIZED_MESSAGE))
}

fn is_bearer_token(auth_header: &str) -> Result<(), HttpError> {
    if !auth_header.starts_with(BEARER_PREFIX) {
        return Err(HttpError::unauthorized(UNAUTHORIZED_MESSAGE));
    }

    Ok(())
}

fn extract_token(auth_header: &str) -> &str {
    auth_header.strip_prefix(BEARER_PREFIX).unwrap()
}
