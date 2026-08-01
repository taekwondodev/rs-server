#![cfg_attr(not(feature = "strict"), allow(dead_code))]


use axum::{
    extract::{FromRequestParts, Request, State},
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use domain_auth::{AccessTokenClaims, AuthRepository, ClientContext, JwtService, SecurityEvent};

use crate::{error::HttpError, state::AppState};

pub(crate) async fn proxy_stub() -> impl IntoResponse {
    StatusCode::NOT_IMPLEMENTED
}

const X_USER_ID: &str = "x-user-id";
const X_USER_ROLE: &str = "x-user-role";

fn internal(msg: &'static str) -> HttpError {
    HttpError::from(domain_auth::DomainError::Internal(anyhow::anyhow!(msg)))
}

pub(crate) async fn inject_user_headers<R, J>(
    State(state): State<AppState<R, J>>,
    mut req: Request,
    next: Next,
) -> Result<Response, HttpError>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    strip_forwarded_headers(&mut req);

    let (mut parts, body) = req.into_parts();
    let client = ClientContext::from_request_parts(&mut parts, &state).await.unwrap();
    let claims = AccessTokenClaims::from_request_parts(&mut parts, &state).await?;
    let mut req = Request::from_parts(parts, body);

    inject_identity_headers(&mut req, &claims)?;
    SecurityEvent::GatewayForward { user_id: *claims.sub(), client: &client }.emit();

    Ok(next.run(req).await)
}

pub(crate) fn strip_forwarded_headers(req: &mut Request) {
    req.headers_mut().remove(X_USER_ID);
    req.headers_mut().remove(X_USER_ROLE);
}

pub(crate) fn inject_identity_headers(
    req: &mut Request,
    claims: &AccessTokenClaims,
) -> Result<(), HttpError> {
    req.headers_mut().insert(
        HeaderName::from_static(X_USER_ID),
        HeaderValue::from_str(&claims.sub.to_string())
            .map_err(|_| internal("sub header value invalid"))?,
    );

    if let Some(role) = claims.role() {
        req.headers_mut().insert(
            HeaderName::from_static(X_USER_ROLE),
            HeaderValue::from_str(role).map_err(|_| internal("role header value invalid"))?,
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests;
