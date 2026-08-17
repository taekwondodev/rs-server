use chrono::{DateTime, Utc};
use domain_auth::{Credential, RecoveryCodeRecord, RecoveryLockout, RecoveryState, User, WebAuthnSession};
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

/// Shadow struct for the `credentials` row shape (management-list projection).
pub struct CredentialRow {
    pub id: Vec<u8>,
    pub name: Option<Box<str>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl FromRow for CredentialRow {
    fn from_row(row: &tokio_postgres::Row) -> Result<Self, RepositoryError> {
        Ok(CredentialRow {
            id: row.try_get("id")?,
            name: row
                .try_get::<_, Option<String>>("name")?
                .map(String::into_boxed_str),
            created_at: row.try_get("created_at")?,
            last_used_at: row.try_get("last_used_at")?,
        })
    }
}

impl From<CredentialRow> for Credential {
    fn from(row: CredentialRow) -> Self {
        Credential {
            id: row.id,
            name: row.name,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
        }
    }
}

/// Shadow struct for a `recovery_codes` row.
pub struct RecoveryCodeRow {
    pub position: i32,
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
    pub used: bool,
}

impl FromRow for RecoveryCodeRow {
    fn from_row(row: &tokio_postgres::Row) -> Result<Self, RepositoryError> {
        Ok(RecoveryCodeRow {
            position: row.try_get("position")?,
            salt: row.try_get("salt")?,
            hash: row.try_get("hash")?,
            used: row.try_get("used")?,
        })
    }
}

impl From<RecoveryCodeRow> for RecoveryCodeRecord {
    fn from(row: RecoveryCodeRow) -> Self {
        RecoveryCodeRecord {
            position: row.position as u32,
            salt: row.salt,
            hash: row.hash,
            used: row.used,
        }
    }
}

/// Shadow struct for the `recovery_state` row.
pub struct RecoveryStateRow {
    pub attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub last_rotated_at: Option<DateTime<Utc>>,
}

impl FromRow for RecoveryStateRow {
    fn from_row(row: &tokio_postgres::Row) -> Result<Self, RepositoryError> {
        Ok(RecoveryStateRow {
            attempts: row.try_get("attempts")?,
            locked_until: row.try_get("locked_until")?,
            last_rotated_at: row.try_get("last_rotated_at")?,
        })
    }
}

/// Maps a `recovery_state` row into the domain `RecoveryLockout` half of
/// `RecoveryState`; `codes` is populated separately by the repository.
impl From<RecoveryStateRow> for RecoveryState {
    fn from(row: RecoveryStateRow) -> Self {
        RecoveryState {
            codes: Vec::new(),
            lockout: RecoveryLockout {
                attempts: row.attempts as u32,
                locked_until: row.locked_until,
            },
            last_rotated_at: row.last_rotated_at,
        }
    }
}
