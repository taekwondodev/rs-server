use std::sync::Arc;

use deadpool_postgres::Pool;
use uuid::Uuid;

use crate::{
    app::AppError,
    auth::{
        dto::ServiceHealth,
        model::{RegistrationOutcome, User, WebAuthnSession},
        queries,
        traits::AuthRepository,
    },
    config::CircuitBreaker,
    utils::{BaseRepository, FromRow, prometheus_observer},
};

pub struct Repository {
    base: BaseRepository,
}

impl Repository {
    pub fn new(db: Pool, circuit_breaker: Arc<CircuitBreaker>) -> Self {
        Self {
            base: BaseRepository::new(db, circuit_breaker, prometheus_observer()),
        }
    }

    async fn activate_user(
        tx: &tokio_postgres::Transaction<'_>,
        username: &str,
    ) -> Result<(), AppError> {
        tx.execute(queries::users::UPDATE_STATUS_ACTIVE, &[&username]).await?;
        Ok(())
    }

    async fn create_credential(
        tx: &tokio_postgres::Transaction<'_>,
        user_id: Uuid,
        passkey: &webauthn_rs::prelude::Passkey,
    ) -> Result<(), AppError> {
        let passkey_json = serde_json::to_value(passkey)?;
        tx.execute(
            queries::credentials::INSERT,
            &[&passkey.cred_id().as_slice(), &user_id, &passkey_json],
        )
        .await?;
        Ok(())
    }
}

impl AuthRepository for Repository {
    async fn check_db(&self) -> ServiceHealth {
        let status = self.base.pool().status();
        crate::app::middleware::metrics::update_db_pool_stats(
            status.size - status.available,
            status.available,
            status.max_size,
        );
        let breaker_u8 = match self.base.breaker_state() {
            rs_repository_utils::CircuitBreakerState::Closed => 0,
            rs_repository_utils::CircuitBreakerState::Open => 1,
        };
        crate::app::middleware::metrics::update_circuit_breaker_state("database", breaker_u8);
        self.base.check_health().await.into()
    }

    async fn create_user(
        &self,
        username: &str,
        role: Option<&str>,
    ) -> Result<RegistrationOutcome, AppError> {
        self.base
            .execute_with_circuit_breaker("insert", "users", |db| async move {
                let client = db.get().await?;

                let row = client
                    .query_one(queries::users::UPSERT, &[&username, &role])
                    .await?;

                let conflicted: bool = row.try_get("conflicted")?;
                let user = User::from_row(&row).map_err(AppError::from)?;

                if conflicted {
                    if &*user.status == "active" {
                        return Err(AppError::AlreadyExists("Username already exists"));
                    }
                    return Ok(RegistrationOutcome::Resumed(user));
                }

                Ok(RegistrationOutcome::Created(user))
            })
            .await
    }

    async fn get_user_and_session(
        &self,
        session_id: Uuid,
        username: &str,
        purpose: &str,
    ) -> Result<(User, WebAuthnSession), AppError> {
        self.base
            .execute_with_circuit_breaker("select", "users", |db| async move {
                let client = db.get().await?;

                match client
                    .query_opt(
                        queries::users::SELECT_WITH_SESSION,
                        &[&username, &session_id, &purpose],
                    )
                    .await?
                {
                    Some(row) => {
                        let user = User::from_row(&row)?;
                        let session = WebAuthnSession::from_row(&row)?;
                        Ok((user, session))
                    }
                    None => Err(AppError::NotFound("User or session not found")),
                }
            })
            .await
    }

    async fn get_active_user_with_credential(
        &self,
        username: &str,
    ) -> Result<(User, Vec<webauthn_rs::prelude::Passkey>), AppError> {
        self.base
            .execute_with_circuit_breaker("select", "users", |db| async move {
                let client = db.get().await?;

                let rows = client
                    .query(queries::users::SELECT_ACTIVE_WITH_CREDENTIALS, &[&username])
                    .await?;

                if rows.is_empty() {
                    return Err(AppError::NotFound("User or credentials not found"));
                }

                let user = User::from_row(&rows[0])?;

                let passkeys = rows
                    .iter()
                    .map(|row| {
                        let passkey_json: serde_json::Value = row.try_get("passkey")?;
                        let passkey: webauthn_rs::prelude::Passkey =
                            serde_json::from_value(passkey_json)?;
                        Ok(passkey)
                    })
                    .collect::<Result<Vec<_>, AppError>>()?;

                Ok((user, passkeys))
            })
            .await
    }

    async fn create_webauthn_session(
        &self,
        user_id: Uuid,
        data: serde_json::Value,
        purpose: &str,
    ) -> Result<Uuid, AppError> {
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

                Ok(row.get("id"))
            })
            .await
    }

    async fn delete_webauthn_session(&self, id: Uuid) -> Result<(), AppError> {
        self.base
            .execute_with_circuit_breaker("delete", "webauthn_sessions", |db| async move {
                let client = db.get().await?;

                let result = client
                    .execute(queries::webauthn_sessions::DELETE_BY_ID, &[&id])
                    .await?;

                if result == 0 {
                    return Err(AppError::NotFound("Session not found"));
                }

                Ok(())
            })
            .await
    }

    async fn update_credential(&self, cred_id: &[u8], new_counter: u32) -> Result<(), AppError> {
        self.base
            .execute_with_circuit_breaker("update", "credentials", |db| async move {
                let client = db.get().await?;

                let result = client
                    .execute(
                        queries::credentials::UPDATE_COUNTER,
                        &[&(new_counter as i64), &cred_id],
                    )
                    .await?;

                if result == 0 {
                    return Err(AppError::NotFound("Credential not found"));
                }

                Ok(())
            })
            .await
    }

    async fn complete_registration(
        &self,
        user_id: Uuid,
        username: &str,
        passkey: &webauthn_rs::prelude::Passkey,
    ) -> Result<(), AppError> {
        let mut client = self.base.pool().get().await?;
        let tx = client.transaction().await?;
        let result = async {
            Repository::create_credential(&tx, user_id, passkey).await?;
            Repository::activate_user(&tx, username).await?;
            Ok::<(), AppError>(())
        }
        .await;
        match result {
            Ok(()) => tx.commit().await.map_err(AppError::from),
            Err(e) => {
                let _ = tx.rollback().await;
                Err(e)
            }
        }
    }
}
