use std::sync::Arc;

use chrono::Utc;
use deadpool_postgres::{Pool, Transaction};
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
    db_delete, db_insert, db_select, db_update,
    utils::{BaseRepository, FromRow},
};

pub struct Repository {
    base: BaseRepository,
}

impl Repository {
    pub fn new(db: Pool, circuit_breaker: Arc<CircuitBreaker>) -> Self {
        Self {
            base: BaseRepository::new(db, circuit_breaker),
        }
    }

    async fn activate_user(tx: &Transaction<'_>, username: &str) -> Result<(), AppError> {
        db_update!("users", {
            tx.execute(queries::users::UPDATE_STATUS_ACTIVE, &[&username])
                .await
        })?;

        Ok(())
    }

    async fn create_credential(
        tx: &Transaction<'_>,
        user_id: Uuid,
        passkey: &webauthn_rs::prelude::Passkey,
    ) -> Result<(), AppError> {
        let passkey_json = serde_json::to_value(passkey)?;

        db_insert!("credentials", {
            tx.execute(
                queries::credentials::INSERT,
                &[&passkey.cred_id().as_slice(), &user_id, &passkey_json],
            )
            .await
        })?;

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
        let username = username.to_string();
        let role = role.map(|s| s.to_string());

        self.base
            .execute_with_circuit_breaker(move |db| async move {
                let client = db.get().await?;

                let row = db_insert!("users", {
                    client
                        .query_one(queries::users::UPSERT, &[&username, &role])
                        .await
                })?;

                let conflicted: bool = row.try_get("conflicted")?;
                let user = User::from_row(&row).map_err(AppError::from)?;

                if conflicted {
                    if user.status == "active" {
                        return Err(AppError::AlreadyExists(
                            "Username already exists".to_string(),
                        ));
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
        let username = username.to_string();
        let purpose = purpose.to_string();

        self.base
            .execute_with_circuit_breaker(move |db| async move {
                let client = db.get().await?;

                match db_select!("users", {
                    client
                        .query_opt(
                            queries::users::SELECT_WITH_SESSION,
                            &[&username, &session_id, &purpose],
                        )
                        .await
                })? {
                    Some(row) => {
                        let user = User::from_row(&row)?;
                        let session = WebAuthnSession::from_row(&row)?;
                        Ok((user, session))
                    }
                    None => Err(AppError::NotFound("User or session not found".to_string())),
                }
            })
            .await
    }

    async fn get_active_user_with_credential(
        &self,
        username: &str,
    ) -> Result<(User, Vec<webauthn_rs::prelude::Passkey>), AppError> {
        let username = username.to_string();

        self.base
            .execute_with_circuit_breaker(move |db| async move {
                let client = db.get().await?;

                let rows = db_select!("users", {
                    client
                        .query(queries::users::SELECT_ACTIVE_WITH_CREDENTIALS, &[&username])
                        .await
                })?;

                if rows.is_empty() {
                    return Err(AppError::NotFound(
                        "User or credentials not found".to_string(),
                    ));
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
        let purpose = purpose.to_string();

        self.base
            .execute_with_circuit_breaker(move |db| async move {
                let client = db.get().await?;
                let expire_at = Utc::now() + chrono::Duration::minutes(30);

                let row = db_insert!("webauthn_sessions", {
                    client
                        .query_one(
                            queries::webauthn_sessions::INSERT,
                            &[&user_id, &data, &purpose, &expire_at],
                        )
                        .await
                })?;

                Ok(row.get("id"))
            })
            .await
    }

    async fn delete_webauthn_session(&self, id: Uuid) -> Result<(), AppError> {
        self.base
            .execute_with_circuit_breaker(move |db| async move {
                let client = db.get().await?;

                let result = db_delete!("webauthn_sessions", {
                    client
                        .execute(queries::webauthn_sessions::DELETE_BY_ID, &[&id])
                        .await
                })?;

                if result == 0 {
                    return Err(AppError::NotFound("Session not found".to_string()));
                }

                Ok(())
            })
            .await
    }

    async fn update_credential(&self, cred_id: &[u8], new_counter: u32) -> Result<(), AppError> {
        let cred_id = cred_id.to_vec();

        self.base
            .execute_with_circuit_breaker(move |db| async move {
                let client = db.get().await?;

                let result = db_update!("credentials", {
                    client
                        .execute(
                            queries::credentials::UPDATE_COUNTER,
                            &[&(new_counter as i64), &cred_id.as_slice()],
                        )
                        .await
                })?;

                if result == 0 {
                    return Err(AppError::NotFound("Credential not found".to_string()));
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
        let username = username.to_string();
        let passkey = passkey.clone();

        self.base
            .execute_with_circuit_breaker(move |db| async move {
                let mut client = db.get().await?;
                let tx = client.transaction().await?;

                Repository::create_credential(&tx, user_id, &passkey).await?;
                Repository::activate_user(&tx, &username).await?;

                tx.commit().await?;
                Ok(())
            })
            .await
    }
}
