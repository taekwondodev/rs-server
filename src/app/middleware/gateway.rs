#![cfg_attr(not(feature = "strict"), allow(dead_code))]

use std::sync::Arc;

use axum::{
    extract::{FromRequestParts, Request, State},
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    app::{AppError, AppState, middleware::security_audit::SecurityEvent},
    auth::jwt::AccessTokenClaims,
};

pub(crate) async fn proxy_stub() -> impl IntoResponse {
    StatusCode::NOT_IMPLEMENTED
}

const X_USER_ID: &str = "x-user-id";
const X_USER_ROLE: &str = "x-user-role";

pub(crate) async fn inject_user_headers(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    strip_forwarded_headers(&mut req);

    let (mut parts, body) = req.into_parts();
    let claims = AccessTokenClaims::from_request_parts(&mut parts, &state).await?;
    let mut req = Request::from_parts(parts, body);

    inject_identity_headers(&mut req, &claims)?;
    SecurityEvent::GatewayForward { user_id: *claims.sub() }.emit();

    Ok(next.run(req).await)
}

pub(crate) fn strip_forwarded_headers(req: &mut Request) {
    req.headers_mut().remove(X_USER_ID);
    req.headers_mut().remove(X_USER_ROLE);
}

pub(crate) fn inject_identity_headers(
    req: &mut Request,
    claims: &AccessTokenClaims,
) -> Result<(), AppError> {
    req.headers_mut().insert(
        HeaderName::from_static(X_USER_ID),
        HeaderValue::from_str(&claims.sub.to_string())
            .map_err(|_| AppError::InternalServer("sub header value invalid".into()))?,
    );

    if let Some(role) = claims.role() {
        req.headers_mut().insert(
            HeaderName::from_static(X_USER_ROLE),
            HeaderValue::from_str(role)
                .map_err(|_| AppError::InternalServer("role header value invalid".into()))?,
        );
    }

    Ok(())
}
