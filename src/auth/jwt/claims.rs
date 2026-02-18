use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app::AppError,
    auth::{jwt::Jwt, jwt::JwtService},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: Uuid,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

impl AccessTokenClaims {
    pub fn new(user_id: Uuid, username: String, role: Option<String>, duration: Duration) -> Self {
        let now = Utc::now();
        let exp = now + chrono::Duration::from_std(duration).unwrap();

        Self {
            sub: user_id,
            username,
            role,
            iat: now.timestamp(),
            exp: exp.timestamp(),
        }
    }

    pub async fn validate(jwt: &Jwt, token: &str) -> Result<Self, AppError> {
        let validation = Validation::new(Algorithm::EdDSA);
        let token_data = decode::<Self>(token, &jwt.access_decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    pub fn to_token(&self, jwt: &Jwt) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("JWT".to_string());

        encode(&header, self, &jwt.access_encoding_key)
            .expect("Invalid token type for access token creation")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: Uuid,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

impl RefreshTokenClaims {
    pub fn new(user_id: Uuid, username: String, role: Option<String>, duration: Duration) -> Self {
        let now = Utc::now();
        let exp = now + chrono::Duration::from_std(duration).unwrap();

        Self {
            sub: user_id,
            username,
            role,
            jti: Self::generate_jti(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
        }
    }

    pub async fn validate(jwt: &Jwt, token: &str) -> Result<Self, AppError> {
        let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        let token_data = decode::<Self>(token, &jwt.refresh_decoding_key, &validation)?;
        let claims = token_data.claims;

        if jwt.is_blacklisted(&claims.jti).await? {
            return Err(AppError::Unauthorized("Token has been revoked".to_string()));
        }

        Ok(claims)
    }

    pub fn to_token(&self, jwt: &Jwt) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("JWT".to_string());

        encode(&header, self, &jwt.refresh_encoding_key).expect("Expected Refresh token claims")
    }

    fn generate_jti() -> String {
        let uuid = Uuid::new_v4();
        BASE64_URL_SAFE_NO_PAD.encode(uuid.as_bytes())
    }
}

pub trait JwtClaims {
    fn sub(&self) -> &Uuid;
    fn username(&self) -> &str;
    fn role(&self) -> Option<&str>;
    fn exp(&self) -> i64;
}

impl JwtClaims for AccessTokenClaims {
    fn sub(&self) -> &Uuid {
        &self.sub
    }

    fn username(&self) -> &str {
        &self.username
    }

    fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }

    fn exp(&self) -> i64 {
        self.exp
    }
}

impl JwtClaims for RefreshTokenClaims {
    fn sub(&self) -> &Uuid {
        &self.sub
    }

    fn username(&self) -> &str {
        &self.username
    }

    fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }

    fn exp(&self) -> i64 {
        self.exp
    }
}

impl RefreshTokenClaims {
    pub fn jti(&self) -> &str {
        &self.jti
    }
}
