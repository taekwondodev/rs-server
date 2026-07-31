use std::sync::Arc;

use std::future::Future;
use std::pin::Pin;

use deadpool_postgres::Pool;
use domain_auth::{AuthRepository, DomainError, RegistrationOutcome, User, UserId};
use rs_repository_utils::{
    BaseRepository, CircuitBreaker, FromRow, HealthIndicator, RepositoryError, ServiceHealth,
};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::{queries, row::{UserRow, WebAuthnSessionRow}};

/// Single boundary conversion point per public trait method (see module docs
/// on `DomainError`): infra method bodies use `anyhow::Result` internally so
/// every infra error (tokio-postgres, deadpool, RepositoryError, serde_json,
/// FromRow) converts via anyhow's blanket `From`, then this classifies the
/// handful of cases that need a specific `DomainError` variant instead of a
/// generic `Internal`.
fn classify_repo_error(e: anyhow::Error) -> DomainError {
    match e.downcast::<RepositoryError>() {
        Ok(RepositoryError::CircuitBreakerOpen(msg)) => {
            DomainError::ServiceUnavailable(msg.to_string())
        }
        Ok(RepositoryError::InvalidQuery(_)) => {
            DomainError::BadRequest("Invalid query parameters".into())
        }
        Ok(other) => DomainError::Internal(anyhow::anyhow!(other)),
        Err(e) => DomainError::Internal(e),
    }
}

pub struct Repository {
    base: BaseRepository,
}

impl Repository {
    pub fn new(db: Pool, circuit_breaker: Arc<CircuitBreaker>) -> Self {
        Self {
            base: BaseRepository::new(db, circuit_breaker, domain_auth::metrics::prometheus_observer()),
        }
    }

    async fn activate_user(tx: &tokio_postgres::Transaction<'_>, username: &str) -> anyhow::Result<()> {
        tx.execute(queries::users::UPDATE_STATUS_ACTIVE, &[&username]).await?;
        Ok(())
    }

    async fn create_credential(
        tx: &tokio_postgres::Transaction<'_>,
        user_id: UserId,
        passkey: &Passkey,
    ) -> anyhow::Result<()> {
        let passkey_json = serde_json::to_value(passkey)?;
        let user_id = user_id.into_inner();
        tx.execute(
            queries::credentials::INSERT,
            &[&passkey.cred_id().as_slice(), &user_id, &passkey_json],
        )
        .await?;
        Ok(())
    }
}

impl HealthIndicator for Repository {
    fn name(&self) -> &'static str {
        "database"
    }

    fn check(&self) -> Pin<Box<dyn Future<Output = ServiceHealth> + Send + '_>> {
        Box::pin(async move {
            let status = self.base.pool().status();
            domain_auth::metrics::update_db_pool_stats(
                status.size - status.available,
                status.available,
                status.max_size,
            );
            let breaker_u8 = match self.base.breaker_state() {
                rs_repository_utils::CircuitBreakerState::Closed => 0,
                rs_repository_utils::CircuitBreakerState::Open => 1,
            };
            domain_auth::metrics::update_circuit_breaker_state("database", breaker_u8);
            self.base.check_health().await
        })
    }
}

impl AuthRepository for Repository {
    async fn create_user(
        &self,
        username: &str,
        role: Option<&str>,
    ) -> Result<RegistrationOutcome, DomainError> {
        let (conflicted, user): (bool, User) = self
            .base
            .execute_with_circuit_breaker("insert", "users", |db| async move {
                let client = db.get().await?;
                let row = client.query_one(queries::users::UPSERT, &[&username, &role]).await?;
                let conflicted: bool = row.try_get("conflicted")?;
                let user: User = UserRow::from_row(&row)?.into();
                Ok::<_, anyhow::Error>((conflicted, user))
            })
            .await
            .map_err(classify_repo_error)?;

        if conflicted {
            if &*user.status == "active" {
                return Err(DomainError::Conflict("Username already exists"));
            }
            return Ok(RegistrationOutcome::Resumed(user));
        }

        Ok(RegistrationOutcome::Created(user))
    }

    async fn get_user_and_session(
        &self,
        session_id: Uuid,
        username: &str,
        purpose: &str,
    ) -> Result<(User, domain_auth::WebAuthnSession), DomainError> {
        let found = self
            .base
            .execute_with_circuit_breaker("select", "users", |db| async move {
                let client = db.get().await?;

                let row = client
                    .query_opt(
                        queries::users::SELECT_WITH_SESSION,
                        &[&username, &session_id, &purpose],
                    )
                    .await?;

                let mapped = match row {
                    Some(row) => {
                        let user: User = UserRow::from_row(&row)?.into();
                        let session: domain_auth::WebAuthnSession = WebAuthnSessionRow::from_row(&row)?.into();
                        Some((user, session))
                    }
                    None => None,
                };
                Ok::<_, anyhow::Error>(mapped)
            })
            .await
            .map_err(classify_repo_error)?;

        found.ok_or(DomainError::NotFound("User or session not found"))
    }

    async fn get_active_user_with_credential(
        &self,
        username: &str,
    ) -> Result<(User, Vec<Passkey>), DomainError> {
        let found = self
            .base
            .execute_with_circuit_breaker("select", "users", |db| async move {
                let client = db.get().await?;

                let rows = client
                    .query(queries::users::SELECT_ACTIVE_WITH_CREDENTIALS, &[&username])
                    .await?;

                if rows.is_empty() {
                    return Ok::<_, anyhow::Error>(None);
                }

                let user: User = UserRow::from_row(&rows[0])?.into();

                let passkeys = rows
                    .iter()
                    .map(|row| {
                        let passkey_json: serde_json::Value = row.try_get("passkey")?;
                        let passkey: Passkey = serde_json::from_value(passkey_json)?;
                        Ok::<_, anyhow::Error>(passkey)
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;

                Ok(Some((user, passkeys)))
            })
            .await
            .map_err(classify_repo_error)?;

        found.ok_or(DomainError::Unauthorized("user or credentials not found"))
    }

    async fn create_webauthn_session(
        &self,
        user_id: UserId,
        data: serde_json::Value,
        purpose: &str,
    ) -> Result<Uuid, DomainError> {
        let user_id = user_id.into_inner();
        self.base
            .execute_with_circuit_breaker("insert", "webauthn_sessions", |db| async move {
                let client = db.get().await?;
                let expire_at = chrono::Utc::now() + chrono::Duration::minutes(30);

                let row = client
                    .query_one(
                        queries::webauthn_sessions::INSERT,
                        &[&user_id, &data, &purpose, &expire_at],
                    )
                    .await?;

                Ok::<_, anyhow::Error>(row.get("id"))
            })
            .await
            .map_err(classify_repo_error)
    }

    async fn delete_webauthn_session(&self, id: Uuid) -> Result<(), DomainError> {
        let affected = self
            .base
            .execute_with_circuit_breaker("delete", "webauthn_sessions", |db| async move {
                let client = db.get().await?;
                let result = client.execute(queries::webauthn_sessions::DELETE_BY_ID, &[&id]).await?;
                Ok::<_, anyhow::Error>(result)
            })
            .await
            .map_err(classify_repo_error)?;

        if affected == 0 {
            return Err(DomainError::NotFound("Session not found"));
        }
        Ok(())
    }

    async fn update_credential(&self, cred_id: &[u8], new_counter: u32) -> Result<(), DomainError> {
        let affected = self
            .base
            .execute_with_circuit_breaker("update", "credentials", |db| async move {
                let client = db.get().await?;
                let result = client
                    .execute(
                        queries::credentials::UPDATE_COUNTER,
                        &[&(new_counter as i64), &cred_id],
                    )
                    .await?;
                Ok::<_, anyhow::Error>(result)
            })
            .await
            .map_err(classify_repo_error)?;

        if affected == 0 {
            return Err(DomainError::NotFound("Credential not found"));
        }
        Ok(())
    }

    async fn complete_registration(
        &self,
        user_id: UserId,
        username: &str,
        passkey: &Passkey,
    ) -> Result<(), DomainError> {
        let result: anyhow::Result<()> = async {
            let mut client = self.base.pool().get().await?;
            let tx = client.transaction().await?;

            let inner = async {
                Repository::create_credential(&tx, user_id, passkey).await?;
                Repository::activate_user(&tx, username).await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;

            match inner {
                Ok(()) => {
                    tx.commit().await?;
                    Ok(())
                }
                Err(e) => {
                    let _ = tx.rollback().await;
                    Err(e)
                }
            }
        }
        .await;

        result.map_err(classify_repo_error)
    }
}
