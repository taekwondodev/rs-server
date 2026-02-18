use std::sync::Arc;

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::{
    app::{AppError, AppState},
    auth::jwt::{AccessTokenClaims, JwtService, claims::JwtClaims},
};

const UNAUTHORIZED_MESSAGE: &str = "You are unauthorized";
const BEARER_PREFIX: &str = "Bearer ";

impl FromRequestParts<Arc<AppState>> for AccessTokenClaims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = extract_auth_header(parts)?;
        is_bearer_token(auth_header)?;
        let token = extract_token(auth_header);
        let claims = state.jwt_service.validate_access(token).await?;

        Ok(claims)
    }
}

#[cfg_attr(not(feature = "strict"), allow(dead_code))]
pub struct AdminClaims(pub AccessTokenClaims);

impl FromRequestParts<Arc<AppState>> for AdminClaims {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let claims = AccessTokenClaims::from_request_parts(parts, state).await?;

        match claims.role() {
            Some(role) if role == "admin" => Ok(AdminClaims(claims)),
            _ => Err(AppError::Unauthorized(String::from(
                "Admin access required",
            ))),
        }
    }
}

impl std::ops::Deref for AdminClaims {
    type Target = AccessTokenClaims;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn extract_auth_header(parts: &Parts) -> Result<&str, AppError> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized(UNAUTHORIZED_MESSAGE.to_string()))
}

fn is_bearer_token(auth_header: &str) -> Result<(), AppError> {
    if !auth_header.starts_with(BEARER_PREFIX) {
        return Err(AppError::Unauthorized(UNAUTHORIZED_MESSAGE.to_string()));
    }

    Ok(())
}

fn extract_token(auth_header: &str) -> &str {
    auth_header.strip_prefix(BEARER_PREFIX).unwrap()
}
