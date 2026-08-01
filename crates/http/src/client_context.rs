use std::convert::Infallible;

use axum::extract::FromRequestParts;
use axum::http::{header, request::Parts};
use domain_auth::{AuthRepository, ClientContext, JwtService};

use crate::state::AppState;

/// `#[cfg(feature = "gateway")]`: this service sits behind a trusted reverse
/// proxy that overwrites `x-real-ip` (nginx `proxy_set_header X-Real-IP
/// $remote_addr;` / Traefik equivalent) — never append-only `X-Forwarded-For`
/// chains, which need a trusted-hop-count to parse safely and this template
/// doesn't assume one. Without the feature, the raw TCP peer address
/// (`ConnectInfo`) is used instead, correct only when this service is
/// directly internet-facing.
impl<R, J> FromRequestParts<AppState<R, J>> for ClientContext
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState<R, J>,
    ) -> Result<Self, Self::Rejection> {
        Ok(ClientContext { ip: extract_ip(parts), user_agent: extract_user_agent(parts) })
    }
}

pub(crate) fn extract_user_agent(parts: &Parts) -> Option<Box<str>> {
    parts.headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(Box::from)
}

#[cfg(feature = "gateway")]
pub(crate) fn extract_ip(parts: &Parts) -> Option<std::net::IpAddr> {
    parts
        .headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
}

#[cfg(not(feature = "gateway"))]
pub(crate) fn extract_ip(parts: &Parts) -> Option<std::net::IpAddr> {
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|ci| ci.0.ip())
}

#[cfg(test)]
mod tests;
