use std::borrow::Cow;
use std::sync::Arc;

use chrono::Utc;
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
        ManageRecoveryCodesCommand, RemoveCredentialCommand, VerifyRecoveryCodeCommand,
    },
    dto::{BeginResult, MessageResult, RecoveryCodesResult, RegistrationKind, TokenResult},
    error::DomainError,
    model::{Credential, RegistrationOutcome, User, WebAuthnSession},
    recovery::crypto::{generate_recovery_codes, generate_salt, hash_code, verify_code},
    recovery::{CODES_PER_BATCH, LOCKOUT_THRESHOLD, RecoveryCodeRecord, RecoveryLockout},
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

    // ---------------------------------------------------------------------
    // Recovery codes — batch management (T2) and verification (T3)
    // ---------------------------------------------------------------------

    /// First-time generation of a recovery-code batch. Refuses if a batch
    /// already exists for the user (`Conflict`) — an authenticated user must
    /// use the rotate path to replace a batch, which enforces the cooldown.
    /// Returns the plaintext codes exactly once; only salted hashes are stored.
    pub async fn generate_recovery_codes(
        &self,
        cmd: ManageRecoveryCodesCommand,
    ) -> Result<RecoveryCodesResult, DomainError> {
        let state = self.auth_repo.get_recovery_state(cmd.user_id).await?;
        if state.is_some() {
            return Err(DomainError::Conflict("Recovery codes already exist"));
        }

        let (codes, records) = Self::make_batch();
        self.auth_repo
            .replace_recovery_batch(cmd.user_id, &records, Utc::now())
            .await?;

        SecurityEvent::RecoveryCodeGenerated {
            user_id: cmd.user_id,
            client: &cmd.client,
        }
        .emit();

        Ok(RecoveryCodesResult {
            codes: codes.into_iter().map(Into::into).collect(),
        })
    }

    /// Rotates the recovery-code batch: generates a fresh one and invalidates
    /// the previous batch. Enforces a 24h cooldown since the last rotation so
    /// a stolen session cannot burn through fresh batches in a loop. Returns
    /// the new plaintext codes exactly once.
    pub async fn rotate_recovery_codes(
        &self,
        cmd: ManageRecoveryCodesCommand,
    ) -> Result<RecoveryCodesResult, DomainError> {
        let state = self.auth_repo.get_recovery_state(cmd.user_id).await?;
        if let Some(state) = state
            && let Some(last) = state.last_rotated_at
            && Utc::now() < last + chrono::Duration::hours(24)
        {
            return Err(DomainError::Conflict(
                "Recovery codes cannot be rotated yet",
            ));
        }

        let (codes, records) = Self::make_batch();
        self.auth_repo
            .replace_recovery_batch(cmd.user_id, &records, Utc::now())
            .await?;

        SecurityEvent::RecoveryCodeGenerated {
            user_id: cmd.user_id,
            client: &cmd.client,
        }
        .emit();

        Ok(RecoveryCodesResult {
            codes: codes.into_iter().map(Into::into).collect(),
        })
    }

    /// Verifies a presented recovery code for a user identified by username
    /// (the one flow without a passkey or token). On success the code is NOT
    /// consumed here — consumption happens atomically in `complete_recovery`
    /// once the re-registration succeeds, so a failed attestation does not burn
    /// a code. On failure the attempt counter grows and trips the lockout after
    /// `LOCKOUT_THRESHOLD` consecutive failures; a locked account rejects
    /// without consulting the hash. Returns the recovered user on success.
    pub async fn verify_recovery_code(
        &self,
        cmd: VerifyRecoveryCodeCommand,
    ) -> Result<User, DomainError> {
        let user = self
            .auth_repo
            .get_active_user_by_username(&cmd.username)
            .await?
            .ok_or(DomainError::Unauthorized("invalid recovery code"))?;

        let state = self
            .auth_repo
            .get_recovery_state(user.id)
            .await?
            .ok_or(DomainError::Unauthorized("invalid recovery code"))?;

        // Locked? Reject without hashing — no oracle, no wasted work.
        if let Some(locked_until) = state.lockout.locked_until
            && Utc::now() < locked_until
        {
            SecurityEvent::RecoveryFailed {
                user_id: user.id,
                reason: "recovery path locked",
                client: &cmd.client,
            }
            .emit();
            return Err(DomainError::Unauthorized("invalid recovery code"));
        }

        let matched = state
            .codes
            .iter()
            .find(|c| !c.used && verify_code(&cmd.code, &c.salt, &c.hash));

        match matched {
            Some(_) => {
                // Success clears the failed-attempt counter. The code itself is
                // consumed only in `complete_recovery`, atomically with the
                // re-registration.
                self.auth_repo
                    .set_recovery_lockout(user.id, &RecoveryLockout::default())
                    .await?;
                Ok(user)
            }
            None => {
                let attempts = state.lockout.attempts + 1;
                let lockout = if attempts >= LOCKOUT_THRESHOLD {
                    RecoveryLockout {
                        attempts,
                        locked_until: Some(Utc::now() + Self::lockout_duration(attempts)),
                    }
                } else {
                    RecoveryLockout {
                        attempts,
                        locked_until: None,
                    }
                };
                self.auth_repo
                    .set_recovery_lockout(user.id, &lockout)
                    .await?;

                SecurityEvent::RecoveryFailed {
                    user_id: user.id,
                    reason: "invalid recovery code",
                    client: &cmd.client,
                }
                .emit();

                Err(DomainError::Unauthorized("invalid recovery code"))
            }
        }
    }

    /// Generates a batch of `CODES_PER_BATCH` codes and their salted-hash
    /// records. Pure — no repo/audit side effects; the caller stores the
    /// records and returns the plaintext.
    fn make_batch() -> (Vec<String>, Vec<RecoveryCodeRecord>) {
        let codes = generate_recovery_codes(CODES_PER_BATCH);
        let records = codes
            .iter()
            .enumerate()
            .map(|(i, code)| {
                let salt = generate_salt();
                RecoveryCodeRecord {
                    position: i as u32,
                    salt: salt.clone(),
                    hash: hash_code(code, &salt),
                    used: false,
                }
            })
            .collect();
        (codes, records)
    }

    /// Growing lockout cooldown: 30s for the first trip past the threshold,
    /// doubling per additional failed attempt, capped at 1h. The `attempts`
    /// counter is not reset while locked, so each extra failure extends the
    /// window instead of re-triggering a flat 30s lock.
    fn lockout_duration(attempts: u32) -> chrono::Duration {
        let beyond_threshold = attempts.saturating_sub(LOCKOUT_THRESHOLD);
        let secs = 30u32.checked_shl(beyond_threshold).unwrap_or(u32::MAX).min(3600);
        chrono::Duration::seconds(secs as i64)
    }

    /// Starts the recovery ceremony: verifies the presented recovery code,
    /// then begins a `recovery`-purpose passkey registration so the user can
    /// re-enroll a fresh authenticator. Returns the registration options and
    /// the recovered user (the finish step needs the user id to complete the
    /// enrollment and invalidate the batch).
    pub async fn begin_recovery(
        &self,
        cmd: VerifyRecoveryCodeCommand,
    ) -> Result<(BeginResult, User), DomainError> {
        let user = self.verify_recovery_code(cmd).await?;
        let exclude_credentials = self.existing_credential_ids(user.id).await?;
        let result = self
            .begin_passkey_ceremony(user.id, &user.username, "recovery", exclude_credentials)
            .await?;
        Ok((result, user))
    }

    /// Completes the recovery ceremony: verifies the re-registration
    /// attestation, then atomically enrolls the fresh passkey and invalidates
    /// the user's entire recovery-code batch (every remaining code is consumed
    /// in the same transaction). The user's recovery state is reset to a clean
    /// slate so they can generate a fresh batch afterwards.
    pub async fn finish_recovery(
        &self,
        cmd: FinishCommand,
    ) -> Result<MessageResult, DomainError> {
        let (session_id, user, session) = self
            .get_user_and_session(&cmd.session_id, &cmd.username, "recovery")
            .await?;

        let passkey = self
            .verify_registration_attestation(&user, session.data, cmd.credentials, "recovery", &cmd.client)
            .await?;

        // Atomic: enroll the passkey + consume every remaining code + reset
        // recovery state in one transaction, so a code is never "half used".
        self.auth_repo
            .complete_recovery(user.id, &user.username, &passkey, cmd.name.as_deref())
            .await?;
        self.cleanup_session(session_id);

        SecurityEvent::RecoveryCodeUsed {
            user_id: user.id,
            client: &cmd.client,
        }
        .emit();

        Ok(MessageResult {
            message: Cow::Borrowed("Account recovery completed successfully!"),
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