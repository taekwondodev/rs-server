use std::borrow::Cow;
use std::sync::Arc;

use domain_shared::UserId;
use uuid::Uuid;
use webauthn_rs::{
    Webauthn,
    prelude::{
        CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
        RegisterPublicKeyCredential,
    },
};

use crate::{
    commands::{
        AddCredentialCommand, BeginCommand, FinishAddCredentialCommand, FinishCommand,
        RemoveCredentialCommand,
    },
    dto::{BeginResult, MessageResult, RegistrationKind, TokenResult},
    error::DomainError,
    model::{Credential, RegistrationOutcome, User, WebAuthnSession},
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

        let exclude_credentials = match &kind {
            // A fresh user holds no credentials yet; skip the listing query.
            RegistrationKind::Fresh => Vec::new(),
            RegistrationKind::Resumed => self.existing_credential_ids(user.id).await?,
        };

        let result = self
            .begin_passkey_ceremony(user.id, &cmd.username, "registration", exclude_credentials)
            .await?;
        Ok((result, kind))
    }

    pub async fn finish_register(&self, cmd: FinishCommand) -> Result<MessageResult, DomainError> {
        let (session_id, user, session) = self
            .get_user_and_session(&cmd.session_id, &cmd.username, "registration")
            .await?;

        let passkey = self
            .verify_registration_attestation(&user, session.data, cmd.credentials, "registration", &cmd.client)
            .await?;

        self.auth_repo
            .complete_registration(user.id, &user.username, &passkey, cmd.name.as_deref())
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

    /// Starts the ceremony for adding another passkey to an already-active
    /// account. Identity comes from the authenticated `AddCredentialCommand`
    /// (claims), and the existing credential ids are passed as
    /// `excludeCredentials` so the same authenticator cannot be re-enrolled.
    pub async fn begin_add_credential(
        &self,
        cmd: AddCredentialCommand,
    ) -> Result<BeginResult, DomainError> {
        let exclude_credentials = self.existing_credential_ids(cmd.user_id).await?;
        self.begin_passkey_ceremony(cmd.user_id, &cmd.username, "credential_add", exclude_credentials)
            .await
    }

    pub async fn finish_add_credential(
        &self,
        cmd: FinishAddCredentialCommand,
    ) -> Result<MessageResult, DomainError> {
        let (session_id, user, session) = self
            .get_user_and_session_by_id(&cmd.session_id, cmd.user_id, "credential_add")
            .await?;

        let passkey = self
            .verify_registration_attestation(&user, session.data, cmd.credentials, "credential_add", &cmd.client)
            .await?;

        self.auth_repo
            .store_credential(user.id, &passkey, cmd.name.as_deref())
            .await?;
        self.cleanup_session(session_id);

        SecurityEvent::CredentialAdded {
            user_id: user.id,
            client: &cmd.client,
        }
        .emit();

        Ok(MessageResult {
            message: Cow::Borrowed("Credential added successfully!"),
        })
    }

    pub async fn list_credentials(&self, user_id: UserId) -> Result<Vec<Credential>, DomainError> {
        self.auth_repo.list_credentials(user_id).await
    }

    pub async fn remove_credential(
        &self,
        cmd: RemoveCredentialCommand,
    ) -> Result<MessageResult, DomainError> {
        self.auth_repo
            .remove_credential(cmd.user_id, &cmd.cred_id)
            .await?;

        SecurityEvent::CredentialRemoved {
            user_id: cmd.user_id,
            client: &cmd.client,
        }
        .emit();

        Ok(MessageResult {
            message: Cow::Borrowed("Credential removed successfully!"),
        })
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

    /// The user's registered credential ids, ready to hand to
    /// `start_passkey_registration` as `excludeCredentials`. Empty for users
    /// with no credentials yet.
    async fn existing_credential_ids(
        &self,
        user_id: UserId,
    ) -> Result<Vec<CredentialID>, DomainError> {
        let credentials = self.auth_repo.list_credentials(user_id).await?;
        Ok(credentials
            .iter()
            .map(|c| CredentialID::from(c.id.as_slice()))
            .collect())
    }

    /// The WebAuthn registration ceremony shared by first registration and
    /// add-credential: start the challenge with the user's existing
    /// credentials excluded, persist the server-side state as a session of
    /// the given `purpose`, and hand the client options back.
    async fn begin_passkey_ceremony(
        &self,
        user_id: UserId,
        username: &str,
        purpose: &str,
        exclude_credentials: Vec<CredentialID>,
    ) -> Result<BeginResult, DomainError> {
        let (ccr, passkey_registration) = self.webauthn.start_passkey_registration(
            user_id.into_inner(),
            username,
            username,
            Some(exclude_credentials),
        )?;

        let (session_data, opts) = Self::prepare_session_data(passkey_registration, ccr)?;
        self.create_session_response(user_id, session_data, opts, purpose)
            .await
    }

    /// The attestation-verification step shared by first registration and
    /// add-credential: deserialize the stored ceremony state and the client
    /// credential, verify them, and map verification failure to the same
    /// audit event + `BadRequest` both flows already used.
    async fn verify_registration_attestation(
        &self,
        user: &User,
        session_data: serde_json::Value,
        credentials: serde_json::Value,
        event: &str,
        client: &ClientContext,
    ) -> Result<Passkey, DomainError> {
        let passkey_registration = serde_json::from_value::<PasskeyRegistration>(session_data)?;
        let credentials = serde_json::from_value::<RegisterPublicKeyCredential>(credentials)?;

        self.webauthn
            .finish_passkey_registration(&credentials, &passkey_registration)
            .map_err(|e| {
                SecurityEvent::AuthFailure {
                    user_id: user.id,
                    event,
                    reason: "credential verification failed",
                    client,
                }
                .emit();
                tracing::warn!(error = %e, "credential_verification_failed");
                DomainError::BadRequest("Invalid credentials".into())
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

    async fn get_user_and_session_by_id(
        &self,
        session_id_str: &str,
        user_id: UserId,
        session_type: &str,
    ) -> Result<(Uuid, crate::model::User, WebAuthnSession), DomainError> {
        let session_id = Uuid::try_parse(session_id_str)
            .map_err(|_| DomainError::BadRequest("Invalid identifier format".into()))?;
        let (user, session) = self
            .auth_repo
            .get_user_and_session_by_id(session_id, user_id, session_type)
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