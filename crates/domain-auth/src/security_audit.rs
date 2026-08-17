use std::net::IpAddr;

use domain_shared::UserId;

/// Plain audit metadata attached to `SecurityEvent`s — no infra/HTTP types
/// (just `std::net::IpAddr` and `Box<str>`), so it can be threaded through
/// `domain-auth`'s ports/commands without pulling axum into this crate.
/// `http` is the only place that knows how to extract it from a real request
/// (see `http::client_context`); everywhere else it's just data. `Clone` is
/// for `FinishCommand`'s sake (it derives `Clone`), not `SecurityEvent`'s —
/// `emit()` below borrows it instead.
#[derive(Debug, Clone, Default)]
pub struct ClientContext {
    pub ip: Option<IpAddr>,
    pub user_agent: Option<Box<str>>,
}

/// Pure tracing-based security audit trail. No infra dependency (tracing only),
/// so it lives in `domain-auth` and is shared by both `http` (auth extractors,
/// gateway middleware) and `domain_auth::AuthService` itself.
pub enum SecurityEvent<'a> {
    AuthSuccess { user_id: UserId, event: &'a str, client: &'a ClientContext },
    AuthFailure { user_id: UserId, event: &'a str, reason: &'a str, client: &'a ClientContext },
    TokenRejected { reason: &'a str, client: &'a ClientContext },
    /// A crypto-valid refresh token whose `jti` is missing from the Redis
    /// whitelist — either a harmless resubmit of an already-rotated token, or
    /// a replayed stolen token. Can't tell which from this signal alone, so
    /// `revoke_family` kills the whole chain either way; this event is what
    /// makes that decision visible for forensics.
    TokenReused { user_id: UserId, family_id: &'a str, client: &'a ClientContext },
    Unauthorized { client: &'a ClientContext },
    #[cfg_attr(not(feature = "strict"), allow(dead_code))]
    AdminDenied { user_id: UserId, client: &'a ClientContext },
    /// An authenticated user added a new passkey to their account. Distinct
    /// from `AuthSuccess { event: "registration" }` — this is a credential
    /// management action on an already-active account, not a first registration.
    CredentialAdded { user_id: UserId, client: &'a ClientContext },
    /// An authenticated user removed one of their passkeys.
    CredentialRemoved { user_id: UserId, client: &'a ClientContext },
    #[cfg(feature = "gateway")]
    #[cfg_attr(not(feature = "strict"), allow(dead_code))]
    GatewayForward { user_id: UserId, client: &'a ClientContext },
}

impl SecurityEvent<'_> {
    pub fn emit(&self) {
        match self {
            Self::AuthSuccess { user_id, event, client } => {
                tracing::info!(security = true, %user_id, event, ip = ?client.ip, user_agent = ?client.user_agent, "auth.success")
            }
            Self::AuthFailure { user_id, event, reason, client } => {
                tracing::warn!(security = true, %user_id, event, reason, ip = ?client.ip, user_agent = ?client.user_agent, "auth.failure")
            }
            Self::TokenRejected { reason, client } => {
                tracing::warn!(security = true, reason, ip = ?client.ip, user_agent = ?client.user_agent, "token.rejected")
            }
            Self::TokenReused { user_id, family_id, client } => {
                tracing::error!(security = true, %user_id, family_id, ip = ?client.ip, user_agent = ?client.user_agent, "token.reused")
            }
            Self::Unauthorized { client } => {
                tracing::warn!(security = true, ip = ?client.ip, user_agent = ?client.user_agent, "access.unauthorized")
            }
            Self::AdminDenied { user_id, client } => {
                tracing::warn!(security = true, %user_id, ip = ?client.ip, user_agent = ?client.user_agent, "access.admin_denied")
            }
            Self::CredentialAdded { user_id, client } => {
                tracing::info!(security = true, %user_id, ip = ?client.ip, user_agent = ?client.user_agent, "credential.added")
            }
            Self::CredentialRemoved { user_id, client } => {
                tracing::info!(security = true, %user_id, ip = ?client.ip, user_agent = ?client.user_agent, "credential.removed")
            }
            #[cfg(feature = "gateway")]
            Self::GatewayForward { user_id, client } => {
                tracing::debug!(security = true, %user_id, ip = ?client.ip, user_agent = ?client.user_agent, "gateway.forward")
            }
        }
    }
}
