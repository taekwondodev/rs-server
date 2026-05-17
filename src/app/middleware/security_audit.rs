use uuid::Uuid;

pub enum SecurityEvent<'a> {
    AuthSuccess { user_id: Uuid, event: &'a str },
    AuthFailure { user_id: Uuid, event: &'a str, reason: &'a str },
    TokenRejected { reason: &'a str },
    Unauthorized,
    #[cfg_attr(not(feature = "strict"), allow(dead_code))]
    AdminDenied { user_id: Uuid },
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
        }
    }
}
