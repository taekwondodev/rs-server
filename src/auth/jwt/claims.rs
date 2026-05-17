use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app::AppError,
    auth::jwt::{Jwt, JwtCrypto, JwtService},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub aud: String,
    pub sub: Uuid,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

impl AccessTokenClaims {
    pub fn new(
        user_id: Uuid,
        username: String,
        role: Option<String>,
        issuer: &str,
        audience: &str,
        duration: Duration,
    ) -> Self {
        let now = Utc::now();
        let exp = now + chrono::Duration::from_std(duration).unwrap();

        Self {
            iss: issuer.to_owned(),
            aud: audience.to_owned(),
            sub: user_id,
            username,
            role,
            iat: now.timestamp(),
            exp: exp.timestamp(),
        }
    }

    pub async fn validate(jwt: &JwtCrypto, token: &str) -> Result<Self, AppError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&jwt.issuer]);
        validation.set_audience(&[&jwt.audience]);
        let token_data = decode::<Self>(token, &jwt.access_decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    pub fn to_token(&self, jwt: &JwtCrypto) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("JWT".to_string());

        encode(&header, self, &jwt.access_encoding_key)
            .expect("Invalid token type for access token creation")
    }
}

#[cfg_attr(not(feature = "strict"), allow(dead_code))]
impl AccessTokenClaims {
    pub fn sub(&self) -> &Uuid {
        &self.sub
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub iss: String,
    pub aud: String,
    pub sub: Uuid,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub jti: String,
    pub family_id: String,
    pub iat: i64,
    pub exp: i64,
}

impl RefreshTokenClaims {
    pub fn new(
        user_id: Uuid,
        username: String,
        role: Option<String>,
        family_id: Option<String>,
        issuer: &str,
        audience: &str,
        duration: Duration,
    ) -> Self {
        let now = Utc::now();
        let exp = now + chrono::Duration::from_std(duration).unwrap();

        Self {
            iss: issuer.to_owned(),
            aud: audience.to_owned(),
            sub: user_id,
            username,
            role,
            jti: Self::generate_jti(),
            family_id: family_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            iat: now.timestamp(),
            exp: exp.timestamp(),
        }
    }

    pub async fn validate(jwt: &Jwt, token: &str) -> Result<Self, AppError> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_issuer(&[&jwt.crypto.issuer]);
        validation.set_audience(&[&jwt.crypto.audience]);
        let token_data = decode::<Self>(token, &jwt.crypto.refresh_decoding_key, &validation)?;
        let claims = token_data.claims;

        match jwt.validate_session(claims.jti()).await {
            Ok(()) => Ok(claims),
            Err(_) => {
                let _ = jwt.revoke_family(claims.family_id()).await;
                Err(AppError::Unauthorized(
                    "Session not found or token reused".to_string(),
                ))
            }
        }
    }

    pub fn to_token(&self, jwt: &JwtCrypto) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("JWT".to_string());

        encode(&header, self, &jwt.refresh_encoding_key).expect("Expected Refresh token claims")
    }

    pub fn sub(&self) -> &Uuid {
        &self.sub
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }

    pub fn jti(&self) -> &str {
        &self.jti
    }

    pub fn family_id(&self) -> &str {
        &self.family_id
    }

    fn generate_jti() -> String {
        let uuid = Uuid::new_v4();
        BASE64_URL_SAFE_NO_PAD.encode(uuid.as_bytes())
    }
}
