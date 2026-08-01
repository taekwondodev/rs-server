use std::borrow::Cow;
use std::sync::Arc;

use domain_shared::UserId;
use uuid::Uuid;
use webauthn_rs::{
    Webauthn,
    prelude::{
        PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
        RegisterPublicKeyCredential,
    },
};

use crate::{
    commands::{BeginCommand, FinishCommand},
    dto::{BeginResult, MessageResult, RegistrationKind, TokenResult},
    error::DomainError,
    model::{RegistrationOutcome, WebAuthnSession},
    security_audit::{ClientContext, SecurityEvent},
    traits::{AuthRepository, JwtService},
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

    pub async fn begin_register(
        &self,
        cmd: BeginCommand,
    ) -> Result<(BeginResult, RegistrationKind), DomainError> {
        let (user, kind) = match self
            .auth_repo
            .create_user(&cmd.username, cmd.role.as_deref())
            .await?
        {
            RegistrationOutcome::Created(u) => (u, RegistrationKind::Fresh),
            RegistrationOutcome::Resumed(u) => {
                tracing::info!(user_id = %u.id, "registration.resumed");
                (u, RegistrationKind::Resumed)
            }
        };

        let (ccr, passkey_registration) = self.webauthn.start_passkey_registration(
            user.id.into_inner(),
            &cmd.username,
            &cmd.username,
            None,
        )?;

        let (session_data, opts) = Self::prepare_session_data(passkey_registration, ccr)?;
        let result = self
            .create_session_response(user.id, session_data, opts, "registration")
            .await?;
        Ok((result, kind))
    }

    pub async fn finish_register(&self, cmd: FinishCommand) -> Result<MessageResult, DomainError> {
        let (session_id, user, session) = self
            .get_user_and_session(&cmd.session_id, &cmd.username, "registration")
            .await?;

        let passkey_registration = serde_json::from_value::<PasskeyRegistration>(session.data)?;
        let credentials = serde_json::from_value::<RegisterPublicKeyCredential>(cmd.credentials)?;

        let passkey = self
            .webauthn
            .finish_passkey_registration(&credentials, &passkey_registration)
            .map_err(|e| {
                SecurityEvent::AuthFailure {
                    user_id: user.id,
                    event: "registration",
                    reason: "credential verification failed",
                    client: &cmd.client,
                }
                .emit();
                tracing::warn!(error = %e, "registration.credential_verification_failed");
                DomainError::BadRequest("Invalid credentials".into())
            })?;

        self.auth_repo
            .complete_registration(user.id, &user.username, &passkey)
            .await?;
        self.cleanup_session(session_id);

        SecurityEvent::AuthSuccess {
            user_id: user.id,
            event: "registration",
            client: &cmd.client,
        }
        .emit();

        Ok(MessageResult {
            message: Cow::Borrowed("Registration completed successfully!"),
        })
    }

    pub async fn begin_login(&self, cmd: BeginCommand) -> Result<BeginResult, DomainError> {
        let (user, passkey) = self
            .auth_repo
            .get_active_user_with_credential(&cmd.username)
            .await?;
        let (rcr, passkey_authentication) = self.webauthn.start_passkey_authentication(&passkey)?;

        let (session_data, opts) = Self::prepare_session_data(passkey_authentication, rcr)?;

        self.create_session_response(user.id, session_data, opts, "login")
            .await
    }

    pub async fn finish_login(
        &self,
        cmd: FinishCommand,
    ) -> Result<(TokenResult, Box<str>), DomainError> {
        let (session_id, user, session) = self
            .get_user_and_session(&cmd.session_id, &cmd.username, "login")
            .await?;

        let passkey_authentication = serde_json::from_value::<PasskeyAuthentication>(session.data)?;
        let credentials = serde_json::from_value::<PublicKeyCredential>(cmd.credentials)?;

        let result = self
            .webauthn
            .finish_passkey_authentication(&credentials, &passkey_authentication)
            .map_err(|e| {
                SecurityEvent::AuthFailure {
                    user_id: user.id,
                    event: "login",
                    reason: "credential verification failed",
                    client: &cmd.client,
                }
                .emit();
                tracing::warn!(error = %e, "login.credential_verification_failed");
                DomainError::Unauthorized("user or credentials not found")
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
            client: &cmd.client,
        }
        .emit();

        Ok((
            TokenResult {
                message: Cow::Borrowed("Login completed successfully!"),
                access_token: token_pair.access_token,
            },
            token_pair.refresh_token,
        ))
    }

    pub async fn refresh(
        &self,
        refresh_token: &str,
        client: &ClientContext,
    ) -> Result<(TokenResult, Box<str>), DomainError> {
        let claims = self.jwt_service.validate_refresh(refresh_token, client).await?;

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
            TokenResult {
                message: Cow::Borrowed("Refresh completed successfully!"),
                access_token: token_pair.access_token,
            },
            token_pair.refresh_token,
        ))
    }

    pub async fn logout(
        &self,
        refresh_token: &str,
        client: &ClientContext,
    ) -> Result<MessageResult, DomainError> {
        if refresh_token.is_empty() {
            return Ok(MessageResult {
                message: Cow::Borrowed("Logout completed successfully!"),
            });
        }

        match self.jwt_service.validate_refresh(refresh_token, client).await {
            Ok(claims) => {
                self.jwt_service
                    .revoke_session(claims.jti(), claims.family_id())
                    .await?;
            }
            Err(DomainError::Unauthorized(_)) => {}
            Err(e) => return Err(e),
        }

        Ok(MessageResult {
            message: Cow::Borrowed("Logout completed successfully!"),
        })
    }

    fn prepare_session_data<T, U>(
        session_obj: T,
        options_obj: U,
    ) -> Result<(serde_json::Value, serde_json::Value), DomainError>
    where
        T: serde::Serialize,
        U: serde::Serialize,
    {
        Ok((
            serde_json::to_value(session_obj)?,
            serde_json::to_value(options_obj)?,
        ))
    }

    async fn create_session_response(
        &self,
        user_id: UserId,
        session_data: serde_json::Value,
        opts: serde_json::Value,
        session_type: &str,
    ) -> Result<BeginResult, DomainError> {
        let session_id = self
            .auth_repo
            .create_webauthn_session(user_id, session_data, session_type)
            .await?;

        Ok(BeginResult {
            options: opts,
            session_id: session_id.to_string().into_boxed_str(),
        })
    }

    async fn get_user_and_session(
        &self,
        session_id_str: &str,
        username: &str,
        session_type: &str,
    ) -> Result<(Uuid, crate::model::User, WebAuthnSession), DomainError> {
        let session_id = Uuid::try_parse(session_id_str)
            .map_err(|_| DomainError::BadRequest("Invalid identifier format".into()))?;
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
