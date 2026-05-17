use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use jsonwebtoken::{DecodingKey, EncodingKey};
use redis::aio::ConnectionManager;
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::app::AppError;
use crate::auth::{
    dto::ServiceHealth,
    jwt::{AccessTokenClaims, JwtService, RefreshTokenClaims},
};
use crate::config::{CircuitBreaker, JwtConfig};
use crate::redis_delete;
use crate::redis_exists;
use crate::redis_set;
use crate::utils::BaseRedisRepository;

use super::queries;

const ACCESS_TOKEN_DURATION: Duration = Duration::from_secs(5 * 60);
const REFRESH_TOKEN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub refresh_jti: String,
    pub refresh_family_id: String,
    pub refresh_exp: i64,
}

pub struct Jwt {
    base: BaseRedisRepository,
    access_token_duration: Duration,
    refresh_token_duration: Duration,
    pub issuer: String,
    pub audience: String,
    pub access_encoding_key: EncodingKey,
    pub access_decoding_key: DecodingKey,
    pub refresh_encoding_key: EncodingKey,
    pub refresh_decoding_key: DecodingKey,
}

impl Jwt {
    pub fn new(
        jwt_config: &JwtConfig,
        conn_manager: ConnectionManager,
        circuit_breaker: Arc<CircuitBreaker>,
    ) -> Self {
        let hk = Hkdf::<Sha256>::new(None, jwt_config.as_bytes());

        let mut access_key_bytes = [0u8; 32];
        hk.expand(b"access-token", &mut access_key_bytes)
            .expect("HKDF expand failed for access key");

        let mut refresh_key_bytes = [0u8; 32];
        hk.expand(b"refresh-token", &mut refresh_key_bytes)
            .expect("HKDF expand failed for refresh key");

        let signing_key = SigningKey::from_bytes(&access_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let access_encoding_key = EncodingKey::from_ed_pem(&Self::ed25519_to_pem(&signing_key))
            .expect("Failed to create encoding key from Ed25519 private key");

        let access_decoding_key =
            DecodingKey::from_ed_pem(&Self::ed25519_public_to_pem(&verifying_key))
                .expect("Failed to create decoding key from Ed25519 public key");

        let refresh_encoding_key = EncodingKey::from_secret(&refresh_key_bytes);
        let refresh_decoding_key = DecodingKey::from_secret(&refresh_key_bytes);

        Self {
            base: BaseRedisRepository::new(conn_manager, circuit_breaker),
            issuer: jwt_config.issuer().to_owned(),
            audience: jwt_config.audience().to_owned(),
            access_encoding_key,
            access_decoding_key,
            refresh_encoding_key,
            refresh_decoding_key,
            access_token_duration: ACCESS_TOKEN_DURATION,
            refresh_token_duration: REFRESH_TOKEN_DURATION,
        }
    }

    fn build_token_pair(
        &self,
        user_id: Uuid,
        username: &str,
        role: Option<&str>,
        family_id: Option<String>,
    ) -> TokenPair {
        let access_claims = AccessTokenClaims::new(
            user_id,
            username.to_string(),
            role.map(|s| s.to_string()),
            &self.issuer,
            &self.audience,
            self.access_token_duration,
        );

        let refresh_claims = RefreshTokenClaims::new(
            user_id,
            username.to_string(),
            role.map(|s| s.to_string()),
            family_id,
            &self.issuer,
            &self.audience,
            self.refresh_token_duration,
        );

        let access_token = access_claims.to_token(self);
        let refresh_token = refresh_claims.to_token(self);
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

    fn ed25519_to_pem(signing_key: &SigningKey) -> Vec<u8> {
        let private_key_bytes = signing_key.to_bytes();

        let mut pkcs8 = vec![
            0x30, 0x2e, // SEQUENCE (46 bytes)
            0x02, 0x01, 0x00, // INTEGER (version = 0)
            0x30, 0x05, // SEQUENCE (5 bytes)
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID for Ed25519
            0x04, 0x22, // OCTET STRING (34 bytes)
            0x04, 0x20, // OCTET STRING (32 bytes)
        ];
        pkcs8.extend_from_slice(&private_key_bytes);

        let encoded = BASE64_STANDARD.encode(&pkcs8);

        let mut pem = Vec::new();
        pem.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.extend_from_slice(chunk);
            pem.push(b'\n');
        }
        pem.extend_from_slice(b"-----END PRIVATE KEY-----\n");
        pem
    }

    fn ed25519_public_to_pem(verifying_key: &VerifyingKey) -> Vec<u8> {
        let public_key_bytes = verifying_key.to_bytes();

        let mut spki = vec![
            0x30, 0x2a, // SEQUENCE (42 bytes)
            0x30, 0x05, // SEQUENCE (5 bytes)
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID for Ed25519
            0x03, 0x21, // BIT STRING (33 bytes)
            0x00, // no unused bits
        ];
        spki.extend_from_slice(&public_key_bytes);

        let encoded = BASE64_STANDARD.encode(&spki);

        let mut pem = Vec::new();
        pem.extend_from_slice(b"-----BEGIN PUBLIC KEY-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.extend_from_slice(chunk);
            pem.push(b'\n');
        }
        pem.extend_from_slice(b"-----END PUBLIC KEY-----\n");
        pem
    }
}

impl JwtService for Jwt {
    async fn check_redis(&self) -> ServiceHealth {
        self.base.check_redis_health().await
    }

    fn generate_token_pair(&self, user_id: Uuid, username: &str, role: Option<&str>) -> TokenPair {
        self.build_token_pair(user_id, username, role, None)
    }

    fn generate_token_pair_with_family(
        &self,
        user_id: Uuid,
        username: &str,
        role: Option<&str>,
        family_id: &str,
    ) -> TokenPair {
        self.build_token_pair(user_id, username, role, Some(family_id.to_owned()))
    }

    async fn validate_refresh(&self, token: &str) -> Result<RefreshTokenClaims, AppError> {
        RefreshTokenClaims::validate(self, token).await
    }

    async fn validate_access(&self, token: &str) -> Result<AccessTokenClaims, AppError> {
        AccessTokenClaims::validate(self, token).await
    }

    async fn store_session(&self, jti: &str, family_id: &str, exp: i64) -> Result<(), AppError> {
        let session_key = queries::session::key(jti);
        let family_key = queries::session::family_key(family_id);
        let ttl = (exp - Utc::now().timestamp()).max(1) as u64;
        let jti_owned = jti.to_owned();

        self.base
            .execute_with_circuit_breaker(move |conn| async move {
                let mut conn = conn.clone();
                use redis::AsyncCommands;
                let _: () = redis_set!({ conn.set_ex(&session_key, "1", ttl).await })?;
                let _: () = redis_set!({ conn.set_ex(&family_key, &jti_owned, ttl).await })?;
                Ok(())
            })
            .await
    }

    async fn validate_session(&self, jti: &str) -> Result<(), AppError> {
        let session_key = queries::session::key(jti);

        self.base
            .execute_with_circuit_breaker(move |conn| async move {
                let mut conn = conn.clone();
                use redis::AsyncCommands;
                let exists: bool = redis_exists!({ conn.exists(&session_key).await })?;
                if exists {
                    Ok(())
                } else {
                    Err(AppError::Unauthorized(
                        "Session not found or expired".to_string(),
                    ))
                }
            })
            .await
    }

    async fn revoke_session(&self, jti: &str, family_id: &str) -> Result<(), AppError> {
        let session_key = queries::session::key(jti);
        let family_key = queries::session::family_key(family_id);

        self.base
            .execute_with_circuit_breaker(move |conn| async move {
                let mut conn = conn.clone();
                use redis::AsyncCommands;
                let _: () = redis_delete!({ conn.del(&[&session_key, &family_key]).await })?;
                Ok(())
            })
            .await
    }

    async fn revoke_family(&self, family_id: &str) -> Result<(), AppError> {
        let family_key = queries::session::family_key(family_id);

        self.base
            .execute_with_circuit_breaker(move |conn| async move {
                let mut conn = conn.clone();
                use redis::AsyncCommands;
                let _: () = redis_delete!({ conn.del(&family_key).await })?;
                Ok(())
            })
            .await
    }
}
