use domain_shared::UserId;

/// Pure tracing-based security audit trail. No infra dependency (tracing only),
/// so it lives in `domain-auth` and is shared by both `http` (auth extractors,
/// gateway middleware) and `domain_auth::AuthService` itself.
pub enum SecurityEvent<'a> {
    AuthSuccess { user_id: UserId, event: &'a str },
    AuthFailure { user_id: UserId, event: &'a str, reason: &'a str },
    TokenRejected { reason: &'a str },
    Unauthorized,
    #[cfg_attr(not(feature = "strict"), allow(dead_code))]
    AdminDenied { user_id: UserId },
    #[cfg(feature = "gateway")]
    #[cfg_attr(not(feature = "strict"), allow(dead_code))]
    GatewayForward { user_id: UserId },
}

impl SecurityEvent<'_> {
    pub fn emit(&self) {
        match self {
            Self::AuthSuccess { user_id, event } => {
                tracing::info!(security = true, %user_id, event, "auth.success")
            }
            Self::AuthFailure { user_id, event, reason } => {
                tracing::warn!(security = true, %user_id, event, reason, "auth.failure")
            }
            Self::TokenRejected { reason } => {
                tracing::warn!(security = true, reason, "token.rejected")
            }
            Self::Unauthorized => {
                tracing::warn!(security = true, "access.unauthorized")
            }
            Self::AdminDenied { user_id } => {
                tracing::warn!(security = true, %user_id, "access.admin_denied")
            }
            #[cfg(feature = "gateway")]
            Self::GatewayForward { user_id } => {
                tracing::debug!(security = true, %user_id, "gateway.forward")
            }
        }
    }
}
