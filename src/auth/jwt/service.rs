use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{DecodingKey, EncodingKey};
use redis::aio::ConnectionManager;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::app::AppError;
use crate::auth::dto::response::ServiceHealth;
use crate::auth::jwt::JwtService;
use crate::auth::jwt::{AccessTokenClaims, RefreshTokenClaims};
use crate::config::CircuitBreaker;
use crate::redis_exists;
use crate::redis_set;
use crate::utils::redis::BaseRedisRepository;

use super::queries;

const ACCESS_TOKEN_DURATION: Duration = Duration::from_secs(5 * 60);
const REFRESH_TOKEN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

pub struct Jwt {
    base: BaseRedisRepository,
    access_token_duration: Duration,
    refresh_token_duration: Duration,
    pub access_encoding_key: EncodingKey,
    pub access_decoding_key: DecodingKey,
    pub refresh_encoding_key: EncodingKey,
    pub refresh_decoding_key: DecodingKey,
}

impl Jwt {
    pub fn new(conn_manager: ConnectionManager, circuit_breaker: Arc<CircuitBreaker>) -> Self {
        let secret_key = env::var("JWT_SECRET_KEY").unwrap();
        if secret_key.len() < 32 {
            panic!("JWT_SECRET_KEY must be at least 32 characters");
        }

        let mut symmetric_key = [0u8; 32];
        let key_bytes = secret_key.as_bytes();
        let len = std::cmp::min(key_bytes.len(), 32);
        symmetric_key[..len].copy_from_slice(&key_bytes[..len]);

        let signing_key = SigningKey::from_bytes(&symmetric_key);
        let verifying_key = signing_key.verifying_key();

        let access_encoding_key = EncodingKey::from_ed_pem(&Self::ed25519_to_pem(&signing_key))
            .expect("Failed to create encoding key from Ed25519 private key");

        let access_decoding_key =
            DecodingKey::from_ed_pem(&Self::ed25519_public_to_pem(&verifying_key))
                .expect("Failed to create decoding key from Ed25519 public key");

        let refresh_encoding_key = EncodingKey::from_secret(&symmetric_key);
        let refresh_decoding_key = DecodingKey::from_secret(&symmetric_key);

        Self {
            base: BaseRedisRepository::new(conn_manager, circuit_breaker),
            access_encoding_key,
            access_decoding_key,
            refresh_encoding_key,
            refresh_decoding_key,
            access_token_duration: ACCESS_TOKEN_DURATION,
            refresh_token_duration: REFRESH_TOKEN_DURATION,
        }
    }

    fn ed25519_to_pem(signing_key: &SigningKey) -> Vec<u8> {
        let private_key_bytes = signing_key.to_bytes();

        // PKCS#8 header per Ed25519
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

        // SubjectPublicKeyInfo per Ed25519
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
        let access_claims = AccessTokenClaims::new(
            user_id,
            username.to_string(),
            role.map(|s| s.to_string()),
            self.access_token_duration,
        );

        let refresh_claims = RefreshTokenClaims::new(
            user_id,
            username.to_string(),
            role.map(|s| s.to_string()),
            self.refresh_token_duration,
        );

        TokenPair {
            access_token: access_claims.to_token(self),
            refresh_token: refresh_claims.to_token(self),
        }
    }

    async fn validate_refresh(&self, token: &str) -> Result<RefreshTokenClaims, AppError> {
        RefreshTokenClaims::validate(self, token).await
    }

    async fn validate_access(&self, token: &str) -> Result<AccessTokenClaims, AppError> {
        AccessTokenClaims::validate(self, token).await
    }

    async fn blacklist(&self, jti: &str, exp: i64) -> Result<(), AppError> {
        let redis_key = queries::blacklist::key(jti);
        let now = Utc::now().timestamp();
        let ttl = if exp - now <= 0 { 1 } else { exp };

        self.base
            .execute_with_circuit_breaker(move |conn| async move {
                let mut conn = conn.clone();
                use redis::AsyncCommands;
                let _: () = redis_set!({ conn.set_ex(&redis_key, "1", ttl as u64).await })?;
                Ok(())
            })
            .await
    }

    async fn is_blacklisted(&self, jti: &str) -> Result<bool, AppError> {
        let redis_key = queries::blacklist::key(jti);

        self.base
            .execute_with_circuit_breaker(move |conn| async move {
                let mut conn = conn.clone();
                use redis::AsyncCommands;
                let exists: bool = redis_exists!({ conn.exists(&redis_key).await })?;
                Ok(exists)
            })
            .await
    }
}
