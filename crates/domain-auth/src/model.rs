use chrono::{DateTime, Utc};
use domain_shared::UserId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Plain domain entity — no row-mapping concerns. See `infra_postgres::UserRow`
/// for the persistence-layer shadow struct that maps into this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub username: Box<str>,
    pub role: Option<Box<str>>,
    pub status: Box<str>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

pub enum RegistrationOutcome {
    Created(User),
    Resumed(User),
}

/// A passkey credential registered to a user. `id` is the raw WebAuthn
/// credential id (binary); the http layer base64url-encodes it on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub id: Vec<u8>,
    pub name: Option<Box<str>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Plain domain entity — no row-mapping concerns. See
/// `infra_postgres::WebAuthnSessionRow` for the persistence-layer shadow struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnSession {
    pub id: Uuid,
    pub user_id: UserId,
    pub data: serde_json::Value,
    pub purpose: Box<str>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
