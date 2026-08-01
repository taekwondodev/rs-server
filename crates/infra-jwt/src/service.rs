use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::Utc;
use domain_auth::{
    AccessTokenClaims, ClientContext, DomainError, JwtService, RefreshTokenClaims, SecurityEvent,
    TokenPair, UserId,
};
use redis::aio::ConnectionManager;
use rs_repository_utils::{
    BaseRedisRepository, CircuitBreaker, HealthIndicator, RepositoryError, ServiceHealth,
};

use crate::config::JwtConfig;
use crate::crypto::JwtCrypto;
use crate::queries;

/// Single boundary conversion point per public trait method — mirrors
/// `infra_postgres::classify_repo_error`. See `domain_auth::DomainError` docs for
/// why `ServiceUnavailable` exists alongside the literal spec'd variant list.
fn classify_repo_error(e: anyhow::Error) -> DomainError {
    match e.downcast::<RepositoryError>() {
        Ok(RepositoryError::CircuitBreakerOpen(msg)) => {
            DomainError::ServiceUnavailable(msg.to_string())
        }
        Ok(RepositoryError::InvalidQuery(_)) => {
            DomainError::BadRequest("Invalid query parameters".into())
        }
        Ok(other) => DomainError::Internal(anyhow::anyhow!(other)),
        Err(e) => DomainError::Internal(e),
    }
}

pub struct Jwt {
    pub(crate) crypto: JwtCrypto,
    base: BaseRedisRepository,
}

impl Jwt {
    pub fn new(jwt_config: &JwtConfig, conn_manager: ConnectionManager, circuit_breaker: Arc<CircuitBreaker>) -> Self {
        Self {
            crypto: JwtCrypto::from_secret(jwt_config.as_bytes(), jwt_config.issuer(), jwt_config.audience()),
            base: BaseRedisRepository::new(conn_manager, circuit_breaker, domain_auth::metrics::prometheus_observer()),
        }
    }

    fn build_token_pair(
        &self,
        user_id: UserId,
        username: &str,
        role: Option<&str>,
        family_id: Option<String>,
    ) -> TokenPair {
        let access_claims = AccessTokenClaims::new(
            user_id,
            username.to_string(),
            role.map(|s| s.to_string()),
            &self.crypto.issuer,
            &self.crypto.audience,
            self.crypto.access_token_duration,
        );

        let refresh_claims = RefreshTokenClaims::new(
            user_id,
            username.to_string(),
            role.map(|s| s.to_string()),
            family_id,
            &self.crypto.issuer,
            &self.crypto.audience,
            self.crypto.refresh_token_duration,
        );

        let access_token = self.crypto.encode_access(&access_claims);
        let refresh_token = self.crypto.encode_refresh(&refresh_claims);
        let refresh_jti = refresh_claims.jti;
        let refresh_family_id = refresh_claims.family_id;
        let refresh_exp = refresh_claims.exp;

        TokenPair {
            access_token,
            refresh_token,
            refresh_jti,
            refresh_family_id,
            refresh_exp,
        }
    }
}

impl HealthIndicator for Jwt {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn check(&self) -> Pin<Box<dyn Future<Output = ServiceHealth> + Send + '_>> {
        Box::pin(async move {
            let breaker_u8 = match self.base.breaker_state() {
                rs_repository_utils::CircuitBreakerState::Closed => 0,
                rs_repository_utils::CircuitBreakerState::Open => 1,
            };
            domain_auth::metrics::update_circuit_breaker_state("redis", breaker_u8);
            self.base.check_health().await
        })
    }
}

impl JwtService for Jwt {
    fn generate_token_pair(&self, user_id: UserId, username: &str, role: Option<&str>) -> TokenPair {
        self.build_token_pair(user_id, username, role, None)
    }

    fn generate_token_pair_with_family(
        &self,
        user_id: UserId,
        username: &str,
        role: Option<&str>,
        family_id: &str,
    ) -> TokenPair {
        self.build_token_pair(user_id, username, role, Some(family_id.to_owned()))
    }

    async fn validate_refresh(
        &self,
        token: &str,
        client: &ClientContext,
    ) -> Result<RefreshTokenClaims, DomainError> {
        let claims = self.crypto.decode_refresh_unchecked(token).inspect_err(|_| {
            SecurityEvent::TokenRejected { reason: "invalid or expired refresh token", client }.emit();
        })?;

        match self.validate_session(claims.jti()).await {
            Ok(()) => Ok(claims),
            Err(_) => {
                SecurityEvent::TokenReused {
                    user_id: *claims.sub(),
                    family_id: claims.family_id(),
                    client,
                }
                .emit();
                let _ = self.revoke_family(claims.family_id()).await;
                Err(DomainError::Unauthorized("Session not found or token reused"))
            }
        }
    }

    async fn validate_access(&self, token: &str) -> Result<AccessTokenClaims, DomainError> {
        self.crypto.decode_access(token)
    }

    async fn store_session(&self, jti: &str, family_id: &str, exp: i64) -> Result<(), DomainError> {
        let session_key = queries::session::key(jti);
        let family_key = queries::session::family_key(family_id);
        let ttl = (exp - Utc::now().timestamp()).max(1) as u64;
        let jti_owned = jti.to_owned();

        self.base
            .execute_with_circuit_breaker("set", |mut conn| async move {
                use redis::AsyncCommands;
                let _: () = conn.set_ex(&session_key, "1", ttl).await?;
                let _: () = conn.set_ex(&family_key, &jti_owned, ttl).await?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .map_err(classify_repo_error)
    }

    async fn validate_session(&self, jti: &str) -> Result<(), DomainError> {
        let session_key = queries::session::key(jti);

        let exists = self
            .base
            .execute_with_circuit_breaker("exists", |mut conn| async move {
                use redis::AsyncCommands;
                let exists: bool = conn.exists(&session_key).await?;
                Ok::<_, anyhow::Error>(exists)
            })
            .await
            .map_err(classify_repo_error)?;

        if exists {
            Ok(())
        } else {
            Err(DomainError::Unauthorized("Session not found or expired"))
        }
    }

    async fn revoke_session(&self, jti: &str, family_id: &str) -> Result<(), DomainError> {
        let session_key = queries::session::key(jti);
        let family_key = queries::session::family_key(family_id);

        self.base
            .execute_with_circuit_breaker("delete", |mut conn| async move {
                use redis::AsyncCommands;
                let _: () = conn.del(&[&session_key, &family_key]).await?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .map_err(classify_repo_error)
    }

    async fn revoke_family(&self, family_id: &str) -> Result<(), DomainError> {
        let family_key = queries::session::family_key(family_id);

        self.base
            .execute_with_circuit_breaker("delete", |mut conn| async move {
                use redis::AsyncCommands;
                let _: () = conn.del(&family_key).await?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .map_err(classify_repo_error)
    }
}
