use std::borrow::Cow;
use std::sync::Arc;

use uuid::Uuid;
use webauthn_rs::{
    Webauthn,
    prelude::{
        PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
        RegisterPublicKeyCredential,
    },
};

use crate::{
    app::{AppError, middleware::{metrics, security_audit::SecurityEvent}},
    auth::{
        dto::{
            BeginRequest, BeginResponse, FinishRequest, HealthChecks, HealthResponse, HealthStatus,
            MessageResponse, TokenResponse,
        },
        jwt::JwtService,
        model::{RegistrationOutcome, WebAuthnSession},
        traits::AuthRepository,
    },
};

pub struct AuthService<R, J>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    webauthn: Webauthn,
    auth_repo: Arc<R>,
    jwt_service: Arc<J>,
}

impl<R, J> AuthService<R, J>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    pub fn new(webauthn: Webauthn, auth_repo: Arc<R>, jwt_service: Arc<J>) -> Self {
        Self {
            webauthn,
            auth_repo,
            jwt_service,
        }
    }

    pub async fn begin_register(&self, req: BeginRequest) -> Result<BeginResponse, AppError> {
        let user = match self
            .auth_repo
            .create_user(&req.username, req.role.as_deref())
            .await
        {
            Ok(RegistrationOutcome::Created(u)) => u,
            Ok(RegistrationOutcome::Resumed(u)) => {
                tracing::info!(user_id = %u.id, "registration.resumed");
                metrics::track_registration_conflict("resumed");
                u
            }
            Err(e @ AppError::AlreadyExists(_)) => {
                metrics::track_registration_conflict("taken");
                return Err(e);
            }
            Err(e) => return Err(e),
        };

        let (ccr, passkey_registration) = self.webauthn.start_passkey_registration(
            user.id,
            &req.username,
            &req.username,
            None,
        )?;

        let (session_data, opts) = Self::prepare_session_data(passkey_registration, ccr)?;
        self.create_session_response(user.id, session_data, opts, "registration")
            .await
    }

    pub async fn finish_register(&self, req: FinishRequest) -> Result<MessageResponse, AppError> {
        let (session_id, user, session) = self
            .get_user_and_session(&req.session_id, &req.username, "registration")
            .await?;

        let passkey_registration = serde_json::from_value::<PasskeyRegistration>(session.data)?;
        let credentials = serde_json::from_value::<RegisterPublicKeyCredential>(req.credentials)?;

        let passkey = self
            .webauthn
            .finish_passkey_registration(&credentials, &passkey_registration)
            .map_err(|e| {
                SecurityEvent::AuthFailure {
                    user_id: user.id,
                    event: "registration",
                    reason: "credential verification failed",
                }
                .emit();
                AppError::from(e)
            })?;

        self.auth_repo
            .complete_registration(user.id, &user.username, &passkey)
            .await?;
        self.cleanup_session(session_id);

        SecurityEvent::AuthSuccess {
            user_id: user.id,
            event: "registration",
        }
        .emit();

        Ok(MessageResponse {
            message: Cow::Borrowed("Registration completed successfully!"),
        })
    }

    pub async fn begin_login(&self, req: BeginRequest) -> Result<BeginResponse, AppError> {
        let (user, passkey) = self
            .auth_repo
            .get_active_user_with_credential(&req.username)
            .await?;
        let (rcr, passkey_authentication) = self.webauthn.start_passkey_authentication(&passkey)?;

        let (session_data, opts) = Self::prepare_session_data(passkey_authentication, rcr)?;

        self.create_session_response(user.id, session_data, opts, "login")
            .await
    }

    pub async fn finish_login(
        &self,
        req: FinishRequest,
    ) -> Result<(TokenResponse, Box<str>), AppError> {
        let (session_id, user, session) = self
            .get_user_and_session(&req.session_id, &req.username, "login")
            .await?;

        let passkey_authentication = serde_json::from_value::<PasskeyAuthentication>(session.data)?;
        let credentials = serde_json::from_value::<PublicKeyCredential>(req.credentials)?;

        let result = self
            .webauthn
            .finish_passkey_authentication(&credentials, &passkey_authentication)
            .map_err(|e| {
                SecurityEvent::AuthFailure {
                    user_id: user.id,
                    event: "login",
                    reason: "credential verification failed",
                }
                .emit();
                AppError::from(e)
            })?;

        if result.needs_update() {
            self.auth_repo
                .update_credential(result.cred_id(), result.counter())
                .await?;
        }

        self.cleanup_session(session_id);

        let token_pair =
            self.jwt_service
                .generate_token_pair(user.id, &user.username, user.role.as_deref());

        self.jwt_service
            .store_session(
                &token_pair.refresh_jti,
                &token_pair.refresh_family_id,
                token_pair.refresh_exp,
            )
            .await?;

        SecurityEvent::AuthSuccess {
            user_id: user.id,
            event: "login",
        }
        .emit();

        Ok((
            TokenResponse {
                message: Cow::Borrowed("Login completed successfully!"),
                access_token: token_pair.access_token,
            },
            token_pair.refresh_token,
        ))
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<(TokenResponse, Box<str>), AppError> {
        let claims = self.jwt_service.validate_refresh(refresh_token).await?;

        self.jwt_service
            .revoke_session(claims.jti(), claims.family_id())
            .await?;

        let token_pair = self.jwt_service.generate_token_pair_with_family(
            *claims.sub(),
            claims.username(),
            claims.role(),
            claims.family_id(),
        );

        self.jwt_service
            .store_session(
                &token_pair.refresh_jti,
                claims.family_id(),
                token_pair.refresh_exp,
            )
            .await?;

        Ok((
            TokenResponse {
                message: Cow::Borrowed("Refresh completed successfully!"),
                access_token: token_pair.access_token,
            },
            token_pair.refresh_token,
        ))
    }

    pub async fn logout(&self, refresh_token: &str) -> Result<MessageResponse, AppError> {
        if refresh_token.is_empty() {
            return Ok(MessageResponse {
                message: Cow::Borrowed("Logout completed successfully!"),
            });
        }

        match self.jwt_service.validate_refresh(refresh_token).await {
            Ok(claims) => {
                self.jwt_service
                    .revoke_session(claims.jti(), claims.family_id())
                    .await?;
            }
            Err(AppError::Unauthorized(_)) => {}
            Err(e) => return Err(e),
        }

        Ok(MessageResponse {
            message: Cow::Borrowed("Logout completed successfully!"),
        })
    }

    pub async fn check_health(&self) -> Result<HealthResponse, AppError> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let (db_health, redis_health) =
            tokio::join!(self.auth_repo.check_db(), self.jwt_service.check_redis(),);

        if db_health.status == HealthStatus::Unhealthy
            || redis_health.status == HealthStatus::Unhealthy
        {
            let mut error_details = Vec::new();

            if db_health.status == HealthStatus::Unhealthy {
                error_details.push(format!("Database: {}", db_health.message));
            }

            if redis_health.status == HealthStatus::Unhealthy {
                error_details.push(format!("Redis: {}", redis_health.message));
            }

            return Err(AppError::ServiceUnavailable(
                format!("One or more services are unhealthy: {}", error_details.join(", ")).into(),
            ));
        }

        Ok(HealthResponse {
            timestamp: timestamp.into_boxed_str(),
            checks: HealthChecks {
                database: db_health,
                redis: redis_health,
            },
        })
    }

    fn prepare_session_data<T, U>(
        session_obj: T,
        options_obj: U,
    ) -> Result<(serde_json::Value, serde_json::Value), AppError>
    where
        T: serde::Serialize,
        U: serde::Serialize,
    {
        Ok((serde_json::to_value(session_obj)?, serde_json::to_value(options_obj)?))
    }

    async fn create_session_response(
        &self,
        user_id: Uuid,
        session_data: serde_json::Value,
        opts: serde_json::Value,
        session_type: &str,
    ) -> Result<BeginResponse, AppError> {
        let session_id = self
            .auth_repo
            .create_webauthn_session(user_id, session_data, session_type)
            .await?;

        Ok(BeginResponse {
            options: opts,
            session_id: session_id.to_string().into_boxed_str(),
        })
    }

    async fn get_user_and_session(
        &self,
        session_id_str: &str,
        username: &str,
        session_type: &str,
    ) -> Result<(Uuid, crate::auth::model::User, WebAuthnSession), AppError> {
        let session_id = Uuid::try_parse(session_id_str)?;
        let (user, session) = self
            .auth_repo
            .get_user_and_session(session_id, username, session_type)
            .await?;
        Ok((session_id, user, session))
    }

    fn cleanup_session(&self, session_id: Uuid) {
        let auth_repo = Arc::clone(&self.auth_repo);
        tokio::spawn(async move {
            if let Err(e) = auth_repo.delete_webauthn_session(session_id).await {
                tracing::error!("Failed to delete webauthn session {}: {}", session_id, e);
            }
        });
    }
}
