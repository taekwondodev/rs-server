use std::future::Future;
use domain_shared::UserId;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::{
    claims::{AccessTokenClaims, RefreshTokenClaims},
    error::DomainError,
    model::{RegistrationOutcome, User, WebAuthnSession},
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
    fn get_active_user_with_credential(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<(User, Vec<Passkey>), DomainError>> + Send;
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
