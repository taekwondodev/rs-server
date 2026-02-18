use uuid::Uuid;

use crate::{
    app::AppError,
    auth::{
        dto::response::ServiceHealth,
        jwt::{AccessTokenClaims, RefreshTokenClaims, TokenPair},
    },
};

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
