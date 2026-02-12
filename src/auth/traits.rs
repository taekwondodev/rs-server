use std::future::Future;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::{
    app::AppError,
    auth::{
        dto::response::ServiceHealth,
        jwt::{AccessTokenClaims, RefreshTokenClaims, TokenPair},
        model::{User, WebAuthnSession},
    },
};

pub trait AuthRepository: Send + Sync {
    fn check_db(&self) -> impl Future<Output = ServiceHealth> + Send;
    fn create_user(
        &self,
        username: &str,
        role: Option<&str>,
    ) -> impl Future<Output = Result<User, AppError>> + Send;
    fn get_user_by_username(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<User, AppError>> + Send;
    fn get_user_and_session(
        &self,
        session_id: Uuid,
        username: &str,
        purpose: &str,
    ) -> impl Future<Output = Result<(User, WebAuthnSession), AppError>> + Send;
    fn get_active_user_with_credential(
        &self,
        username: &str,
    ) -> impl Future<Output = Result<(User, Vec<Passkey>), AppError>> + Send;
    fn create_webauthn_session(
        &self,
        user_id: Uuid,
        data: serde_json::Value,
        purpose: &str,
    ) -> impl Future<Output = Result<Uuid, AppError>> + Send;
    fn delete_webauthn_session(
        &self,
        id: Uuid,
    ) -> impl Future<Output = Result<(), AppError>> + Send;
    fn update_credential(
        &self,
        cred_id: &[u8],
        new_counter: u32,
    ) -> impl Future<Output = Result<(), AppError>> + Send;
    fn complete_registration(
        &self,
        user_id: Uuid,
        username: &str,
        passkey: &Passkey,
    ) -> impl Future<Output = Result<(), AppError>> + Send;
}

pub trait JwtService: Send + Sync {
    fn check_redis(&self) -> impl Future<Output = ServiceHealth> + Send;
    fn generate_token_pair(&self, user_id: Uuid, username: &str, role: Option<&str>) -> TokenPair;
    fn validate_refresh(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<RefreshTokenClaims, AppError>> + Send;
    fn validate_access(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<AccessTokenClaims, AppError>> + Send;
    fn blacklist(&self, jti: &str, exp: i64) -> impl Future<Output = Result<(), AppError>> + Send;
    fn is_blacklisted(&self, jti: &str) -> impl Future<Output = Result<bool, AppError>> + Send;
}
