use uuid::Uuid;

use crate::{
    app::AppError,
    auth::{
        dto::ServiceHealth,
        jwt::{AccessTokenClaims, RefreshTokenClaims, TokenPair},
    },
};

pub trait JwtService: Send + Sync {
    fn check_redis(&self) -> impl Future<Output = ServiceHealth> + Send;

    fn generate_token_pair(&self, user_id: Uuid, username: &str, role: Option<&str>) -> TokenPair;

    fn generate_token_pair_with_family(
        &self,
        user_id: Uuid,
        username: &str,
        role: Option<&str>,
        family_id: &str,
    ) -> TokenPair;

    fn validate_refresh(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<RefreshTokenClaims, AppError>> + Send;

    fn validate_access(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<AccessTokenClaims, AppError>> + Send;

    fn store_session(
        &self,
        jti: &str,
        family_id: &str,
        exp: i64,
    ) -> impl Future<Output = Result<(), AppError>> + Send;

    fn validate_session(
        &self,
        jti: &str,
    ) -> impl Future<Output = Result<(), AppError>> + Send;

    fn revoke_session(
        &self,
        jti: &str,
        family_id: &str,
    ) -> impl Future<Output = Result<(), AppError>> + Send;

    fn revoke_family(
        &self,
        family_id: &str,
    ) -> impl Future<Output = Result<(), AppError>> + Send;
}
