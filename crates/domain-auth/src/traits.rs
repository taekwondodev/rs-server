use std::future::Future;
use chrono::{DateTime, Utc};
use domain_shared::UserId;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::{
    claims::{AccessTokenClaims, RefreshTokenClaims},
    error::DomainError,
    model::{Credential, RegistrationOutcome, User, WebAuthnSession},
    recovery::{RecoveryCodeRecord, RecoveryLockout, RecoveryState},
    security_audit::ClientContext,
};

pub trait AuthRepository: Send + Sync {
    fn create_user(
        &self,
        username: &str,
        role: Option<&str>,
    ) -> impl Future<Output = Result<RegistrationOutcome, DomainError>> + Send;
    fn get_user_and_session(
        &self,
        session_id: Uuid,
        username: &str,
        purpose: &str,
    ) -> impl Future<Output = Result<(User, WebAuthnSession), DomainError>> + Send;
    fn get_user_and_session_by_id(
        &self,
        session_id: Uuid,
        user_id: UserId,
        purpose: &str,
    ) -> impl Future<Output = Result<(User, WebAuthnSession), DomainError>> + Send;
    fn get_active_user_with_credential(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<(User, Vec<Passkey>), DomainError>> + Send;

    /// Resolves an active user by username alone — no credentials required.
    /// Used by the recovery flow, the one path where the user presents no
    /// passkey and no token. Returns `None` if the user does not exist or is
    /// not active (the service maps that to a generic `Unauthorized`).
    fn get_active_user_by_username(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<Option<User>, DomainError>> + Send;
    fn list_credentials(
        &self,
        user_id: UserId,
    ) -> impl Future<Output = Result<Vec<Credential>, DomainError>> + Send;
    fn store_credential(
        &self,
        user_id: UserId,
        passkey: &Passkey,
        name: Option<&str>,
    ) -> impl Future<Output = Result<(), DomainError>> + Send;
    fn remove_credential(
        &self,
        user_id: UserId,
        cred_id: &[u8],
    ) -> impl Future<Output = Result<(), DomainError>> + Send;
    fn create_webauthn_session(
        &self,
        user_id: UserId,
        data: serde_json::Value,
        purpose: &str,
    ) -> impl Future<Output = Result<Uuid, DomainError>> + Send;
    fn delete_webauthn_session(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<(), DomainError>> + Send;
    fn update_credential(
        &self,
        cred_id: &[u8],
        new_counter: u32,
    ) -> impl Future<Output = Result<(), DomainError>> + Send;
    fn complete_registration(
        &self,
        user_id: UserId,
        username: &str,
        passkey: &Passkey,
        name: Option<&str>,
    ) -> impl Future<Output = Result<(), DomainError>> + Send;

    // ---------------------------------------------------------------------
    // Recovery codes (ADR: account recovery via recovery codes)
    // ---------------------------------------------------------------------

    /// Replaces the user's recovery-code batch: deletes any existing batch and
    /// inserts `codes` as the new one. Used by both first generation and
    /// rotation — rotation in the service layer first checks the cooldown, so
    /// calling this unconditionally here is safe (the old batch is dropped).
    fn replace_recovery_batch(
        &self,
        user_id: UserId,
        codes: &[RecoveryCodeRecord],
        last_rotated_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<(), DomainError>> + Send;

    /// Fetches the user's recovery-code records and lockout state together.
    /// Returns `None` if the user has no batch stored (or the user does not
    /// exist) — the service maps that to `NotFound`/`Unauthorized` as context
    /// requires.
    fn get_recovery_state(
        &self,
        user_id: UserId,
    ) -> impl Future<Output = Result<Option<RecoveryState>, DomainError>> + Send;

    /// Completes a recovery atomically: enrolls the fresh passkey, invalidates
    /// the user's entire recovery-code batch (every remaining code is consumed),
    /// and resets the recovery state to a clean slate (no lockout, no rotation
    /// cooldown). All in one transaction so a code can never be "half used".
    fn complete_recovery(
        &self,
        user_id: UserId,
        username: &str,
        passkey: &Passkey,
        name: Option<&str>,
    ) -> impl Future<Output = Result<(), DomainError>> + Send;

    /// Persists the user's recovery lockout state (attempt counter + cooldown
    /// deadline). Lives in Postgres so a server restart cannot silently reset
    /// the anti-brute-force protection.
    fn set_recovery_lockout(
        &self,
        user_id: UserId,
        lockout: &RecoveryLockout,
    ) -> impl Future<Output = Result<(), DomainError>> + Send;
}

pub trait JwtService: Send + Sync {
    fn generate_token_pair(&self, user_id: UserId, username: &str, role: Option<&str>) -> TokenPair;

    fn generate_token_pair_with_family(
        &self,
        user_id: UserId,
        username: &str,
        role: Option<&str>,
        family_id: &str,
    ) -> TokenPair;

    fn validate_refresh(
        &self,
        token: &str,
        client: &ClientContext,
    ) -> impl Future<Output = Result<RefreshTokenClaims, DomainError>> + Send;

    fn validate_access(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<AccessTokenClaims, DomainError>> + Send;

    fn store_session(
        &self,
        jti: &str,
        family_id: &str,
        exp: i64,
    ) -> impl Future<Output = Result<(), DomainError>> + Send;

    fn validate_session(&self, jti: &str) -> impl Future<Output = Result<(), DomainError>> + Send;

    fn revoke_session(
        &self,
        jti: &str,
        family_id: &str,
    ) -> impl Future<Output = Result<(), DomainError>> + Send;

    fn revoke_family(&self, family_id: &str) -> impl Future<Output = Result<(), DomainError>> + Send;
}

/// Pure data — the pair of tokens produced by a login/refresh. Owned by
/// `domain` because `AuthService` constructs `TokenResult` directly from it;
/// the actual JWT encoding happens inside `infra_jwt::Jwt::generate_token_pair*`.
#[derive(Debug)]
pub struct TokenPair {
    pub access_token: Box<str>,
    pub refresh_token: Box<str>,
    pub refresh_jti: Box<str>,
    pub refresh_family_id: Box<str>,
    pub refresh_exp: i64,
}
