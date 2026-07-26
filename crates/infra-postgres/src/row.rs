use chrono::{DateTime, Utc};
use domain_auth::{User, WebAuthnSession};
use rs_repository_utils::{FromRow, RepositoryError};
use uuid::Uuid;

/// Shadow struct for the `users` row shape — the postgres-specific mapping
/// concern that used to live directly on `domain_auth::User`. Maps into the plain
/// domain entity via `From`.
pub struct UserRow {
    pub id: Uuid,
    pub username: Box<str>,
    pub role: Option<Box<str>>,
    pub status: Box<str>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

impl FromRow for UserRow {
    fn from_row(row: &tokio_postgres::Row) -> Result<Self, RepositoryError> {
        Ok(UserRow {
            id: row.try_get("id")?,
            username: row.try_get::<_, String>("username")?.into_boxed_str(),
            role: row.try_get::<_, Option<String>>("role")?.map(String::into_boxed_str),
            status: row.try_get::<_, String>("status")?.into_boxed_str(),
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            is_active: row.try_get("is_active")?,
        })
    }
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        User {
            id: row.id.into(),
            username: row.username,
            role: row.role,
            status: row.status,
            created_at: row.created_at,
            updated_at: row.updated_at,
            is_active: row.is_active,
        }
    }
}

/// Shadow struct for the `webauthn_sessions` row shape.
pub struct WebAuthnSessionRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub data: serde_json::Value,
    pub purpose: Box<str>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl FromRow for WebAuthnSessionRow {
    fn from_row(row: &tokio_postgres::Row) -> Result<Self, RepositoryError> {
        Ok(WebAuthnSessionRow {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            data: row.try_get("data")?,
            purpose: row.try_get::<_, String>("purpose")?.into_boxed_str(),
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
        })
    }
}

impl From<WebAuthnSessionRow> for WebAuthnSession {
    fn from(row: WebAuthnSessionRow) -> Self {
        WebAuthnSession {
            id: row.id,
            user_id: row.user_id.into(),
            data: row.data,
            purpose: row.purpose,
            created_at: row.created_at,
            expires_at: row.expires_at,
        }
    }
}
