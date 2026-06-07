use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::utils::FromRow;
use rs_repository_utils::RepositoryError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: Box<str>,
    pub role: Option<Box<str>>,
    pub status: Box<str>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

impl FromRow for User {
    fn from_row(row: &tokio_postgres::Row) -> Result<Self, RepositoryError> {
        Ok(User {
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

pub enum RegistrationOutcome {
    Created(User),
    Resumed(User),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub data: serde_json::Value,
    pub purpose: Box<str>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl FromRow for WebAuthnSession {
    fn from_row(row: &tokio_postgres::Row) -> Result<Self, RepositoryError> {
        Ok(WebAuthnSession {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            data: row.try_get("data")?,
            purpose: row.try_get::<_, String>("purpose")?.into_boxed_str(),
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
        })
    }
}
