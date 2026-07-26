use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD};
use chrono::Utc;
use domain_shared::UserId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Plain claim data — no crypto. Encoding/decoding (`to_token`/`validate`) is
/// an inherent method on `infra_jwt::Jwt`/`JwtCrypto` operating on these public
/// fields; this type carries zero jsonwebtoken/JwtCrypto knowledge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: Box<str>,
    pub aud: Box<str>,
    pub sub: UserId,
    pub username: Box<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<Box<str>>,
    pub iat: i64,
    pub exp: i64,
}

impl AccessTokenClaims {
    pub fn new(
        user_id: UserId,
        username: String,
        role: Option<String>,
        issuer: &str,
        audience: &str,
        duration: Duration,
    ) -> Self {
        let now = Utc::now();
        let exp = now + chrono::Duration::from_std(duration).unwrap();

        Self {
            iss: issuer.into(),
            aud: audience.into(),
            sub: user_id,
            username: username.into_boxed_str(),
            role: role.map(String::into_boxed_str),
            iat: now.timestamp(),
            exp: exp.timestamp(),
        }
    }

    #[cfg_attr(not(feature = "strict"), allow(dead_code))]
    pub fn sub(&self) -> &UserId {
        &self.sub
    }

    #[cfg_attr(not(feature = "strict"), allow(dead_code))]
    pub fn username(&self) -> &str {
        &self.username
    }

    #[cfg_attr(not(feature = "strict"), allow(dead_code))]
    pub fn role(&self) -> Option<&str> {
        self.role.as_deref()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub iss: Box<str>,
    pub aud: Box<str>,
    pub sub: UserId,
    pub username: Box<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<Box<str>>,
    pub jti: Box<str>,
    pub family_id: Box<str>,
    pub iat: i64,
    pub exp: i64,
}

impl RefreshTokenClaims {
    pub fn new(
        user_id: UserId,
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
            iss: issuer.into(),
            aud: audience.into(),
            sub: user_id,
            username: username.into_boxed_str(),
            role: role.map(String::into_boxed_str),
            jti: Self::generate_jti(),
            family_id: family_id
                .unwrap_or_else(|| Uuid::new_v4().to_string())
                .into_boxed_str(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
        }
    }

    pub fn sub(&self) -> &UserId {
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

    fn generate_jti() -> Box<str> {
        let uuid = Uuid::new_v4();
        BASE64_URL_SAFE_NO_PAD.encode(uuid.as_bytes()).into_boxed_str()
    }
}
