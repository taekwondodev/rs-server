use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::utils::postgres::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub role: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

impl FromRow for User {
    fn from_row(row: &tokio_postgres::Row) -> Result<Self, crate::app::AppError> {
        Ok(User {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            role: row.try_get("role")?,
            status: row.try_get("status")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            is_active: row.try_get("is_active")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub data: serde_json::Value,
    pub purpose: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl FromRow for WebAuthnSession {
    fn from_row(row: &tokio_postgres::Row) -> Result<Self, crate::app::AppError> {
        Ok(WebAuthnSession {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            data: row.try_get("data")?,
            purpose: row.try_get("purpose")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
        })
    }
}
