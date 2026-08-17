use std::sync::Arc;

use std::future::Future;
use std::pin::Pin;

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use domain_auth::{
    AuthRepository, Credential, DomainError, RegistrationOutcome, RecoveryCodeRecord,
    RecoveryLockout, RecoveryState, User, UserId,
};
use rs_repository_utils::{
    BaseRepository, CircuitBreaker, FromRow, HealthIndicator, RepositoryError, ServiceHealth,
};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::queries::recovery_codes as rc_queries;
use crate::queries::recovery_state as rs_queries;
use crate::{
    queries,
    row::{CredentialRow, RecoveryCodeRow, RecoveryStateRow, UserRow, WebAuthnSessionRow},
};

/// True when the error chain contains a Postgres unique-violation (23505) —
/// e.g. re-registering the same authenticator despite excludeCredentials.
/// Surfaces as a clean `Conflict` instead of a 500.
fn is_unique_violation(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<tokio_postgres::Error>()
            .is_some_and(|pg| pg.code() == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION))
    })
}

/// Boundary classifier for credential writes: a unique violation is a
/// duplicate passkey -> `Conflict`; everything else falls through to the
/// generic classifier.
fn classify_write_error(e: anyhow::Error) -> DomainError {
    if is_unique_violation(&e) {
        DomainError::Conflict("Credential already exists")
    } else {
        classify_repo_error(e)
    }
}

/// Internal (never crosses a trait boundary) decision of a removal attempt;
/// the public method converts it to `DomainError` right here at the boundary.
enum RemoveOutcome {
    Removed,
    NotFound,
    LastCredential,
}

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
        name: Option<&str>,
    ) -> anyhow::Result<()> {
        let passkey_json = serde_json::to_value(passkey)?;
        let user_id = user_id.into_inner();
        tx.execute(
            queries::credentials::INSERT,
            &[&passkey.cred_id().as_slice(), &user_id, &passkey_json, &name],
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

    async fn get_user_and_session_by_id(
        &self,
        session_id: Uuid,
        user_id: UserId,
        purpose: &str,
    ) -> Result<(User, domain_auth::WebAuthnSession), DomainError> {
        let found = self
            .base
            .execute_with_circuit_breaker("select", "users", |db| async move {
                let client = db.get().await?;
                let user_id = user_id.into_inner();

                let row = client
                    .query_opt(
                        queries::users::SELECT_WITH_SESSION_BY_ID,
                        &[&user_id, &session_id, &purpose],
                    )
                    .await?;

                let mapped = match row {
                    Some(row) => {
                        let user: User = UserRow::from_row(&row)?.into();
                        let session: domain_auth::WebAuthnSession =
                            WebAuthnSessionRow::from_row(&row)?.into();
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

    async fn get_active_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<User>, DomainError> {
        self.base
            .execute_with_circuit_breaker("select", "users", |db| async move {
                let client = db.get().await?;
                let row = client
                    .query_opt(queries::users::SELECT_ACTIVE_BY_USERNAME, &[&username])
                    .await?;
                let mapped: Option<User> = row
                    .map(|r| UserRow::from_row(&r).map(User::from))
                    .transpose()?;
                Ok::<_, anyhow::Error>(mapped)
            })
            .await
            .map_err(classify_repo_error)
    }

    async fn list_credentials(&self, user_id: UserId) -> Result<Vec<Credential>, DomainError> {
        self.base
            .execute_with_circuit_breaker("select", "credentials", |db| async move {
                let client = db.get().await?;
                let user_id = user_id.into_inner();

                let rows = client
                    .query(queries::credentials::SELECT_BY_USER, &[&user_id])
                    .await?;

                let credentials = rows
                    .iter()
                    .map(|row| Ok::<_, anyhow::Error>(CredentialRow::from_row(row)?.into()))
                    .collect::<anyhow::Result<Vec<_>>>()?;

                Ok::<_, anyhow::Error>(credentials)
            })
            .await
            .map_err(classify_repo_error)
    }

    async fn store_credential(
        &self,
        user_id: UserId,
        passkey: &Passkey,
        name: Option<&str>,
    ) -> Result<(), DomainError> {
        let result: anyhow::Result<u64> = self
            .base
            .execute_with_circuit_breaker("insert", "credentials", |db| async move {
                let client = db.get().await?;
                let passkey_json = serde_json::to_value(passkey)?;
                let user_id = user_id.into_inner();

                client
                    .execute(
                        queries::credentials::INSERT_OWNED_ACTIVE,
                        &[&passkey.cred_id().as_slice(), &user_id, &passkey_json, &name],
                    )
                    .await
                    .map_err(Into::into)
            })
            .await;

        match result {
            Err(e) => Err(classify_write_error(e)),
            Ok(0) => Err(DomainError::NotFound("User not found or inactive")),
            Ok(_) => Ok(()),
        }
    }

    async fn remove_credential(
        &self,
        user_id: UserId,
        cred_id: &[u8],
    ) -> Result<(), DomainError> {
        let outcome: anyhow::Result<RemoveOutcome> = self
            .base
            .with_transaction("delete", "credentials", |mut client| async move {
                let tx = client.transaction().await?;

                // Serialize per-user credential mutations: the last-credential
                // guard's count and the delete must not interleave with a
                // concurrent remove for the same user, or both could observe
                // count>1 and delete down to zero.
                let locked = tx
                    .execute(queries::users::LOCK_BY_ID, &[&user_id.into_inner()])
                    .await?;
                if locked == 0 {
                    return Ok(RemoveOutcome::NotFound);
                }

                // Ownership first: an id that was never the user's is a 404
                // regardless of how many credentials they hold. Existence and
                // count travel in one round trip.
                let row = tx
                    .query_one(
                        queries::credentials::EXISTS_COUNT_BY_USER,
                        &[&cred_id, &user_id.into_inner()],
                    )
                    .await?;
                let owned: bool = row.get("owned");
                if !owned {
                    return Ok(RemoveOutcome::NotFound);
                }

                let remaining: i64 = row.get("remaining");
                if remaining <= 1 {
                    return Ok(RemoveOutcome::LastCredential);
                }

                let deleted = tx
                    .execute(
                        queries::credentials::DELETE_BY_ID_AND_USER,
                        &[&cred_id, &user_id.into_inner()],
                    )
                    .await?;

                debug_assert_eq!(deleted, 1, "ownership was just confirmed");

                tx.commit().await?;
                Ok(RemoveOutcome::Removed)
            })
            .await;

        match outcome.map_err(classify_repo_error)? {
            RemoveOutcome::Removed => Ok(()),
            RemoveOutcome::NotFound => Err(DomainError::NotFound("Credential not found")),
            RemoveOutcome::LastCredential => {
                Err(DomainError::Conflict("Cannot remove the last credential"))
            }
        }
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
                let expire_at = chrono::Utc::now() + chrono::Duration::seconds(60);

                client.execute(queries::webauthn_sessions::DELETE_EXPIRED, &[]).await?;

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
        name: Option<&str>,
    ) -> Result<(), DomainError> {
        let result: anyhow::Result<()> = self
            .base
            .with_transaction("insert", "credentials", |mut client| async move {
                let tx = client.transaction().await?;
                Repository::create_credential(&tx, user_id, passkey, name).await?;
                Repository::activate_user(&tx, username).await?;
                tx.commit().await?;
                Ok::<(), anyhow::Error>(())
            })
            .await;

        match result {
            Err(e) => Err(classify_write_error(e)),
            Ok(()) => Ok(()),
        }
    }

    async fn replace_recovery_batch(
        &self,
        user_id: UserId,
        codes: &[RecoveryCodeRecord],
        last_rotated_at: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let user_id = user_id.into_inner();
        self.base
            .with_transaction("insert", "recovery_codes", |mut client| async move {
                let tx = client.transaction().await?;

                // Replace the old batch and the state atomically: delete the
                // existing codes, insert the new ones, and record the rotation
                // timestamp so the service can enforce the cooldown.
                tx.execute(rc_queries::DELETE_BY_USER, &[&user_id]).await?;
                for code in codes {
                    tx.execute(
                        rc_queries::INSERT,
                        &[
                            &user_id,
                            &(code.position as i32),
                            &code.salt,
                            &code.hash,
                        ],
                    )
                    .await?;
                }
                // Reset the lockout counters on batch replacement: generation
                // and rotation are authenticated actions (the user proved
                // identity via a passkey), so starting the recovery path fresh
                // with zero attempts is correct — a successful login/rotation
                // is not a recovery-code failure sequence.
                tx.execute(
                    rs_queries::UPSERT,
                    &[
                        &user_id,
                        &(0_i32),
                        &Option::<DateTime<Utc>>::None,
                        &last_rotated_at,
                    ],
                )
                .await?;

                tx.commit().await?;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .map_err(classify_repo_error)
    }

    async fn get_recovery_state(
        &self,
        user_id: UserId,
    ) -> Result<Option<RecoveryState>, DomainError> {
        let user_id = user_id.into_inner();
        self.base
            .execute_with_circuit_breaker("select", "recovery", |db| async move {
                let client = db.get().await?;

                let state_row = client
                    .query_opt(rs_queries::SELECT_BY_USER, &[&user_id])
                    .await?;

                let code_rows = client
                    .query(rc_queries::SELECT_BY_USER, &[&user_id])
                    .await?;

                let codes = code_rows
                    .iter()
                    .map(|row| Ok::<_, anyhow::Error>(RecoveryCodeRow::from_row(row)?.into()))
                    .collect::<anyhow::Result<Vec<_>>>()?;

                let mut state = match state_row {
                    Some(row) => RecoveryState::from(RecoveryStateRow::from_row(&row)?),
                    None => RecoveryState {
                        codes: Vec::new(),
                        lockout: RecoveryLockout::default(),
                        last_rotated_at: None,
                    },
                };
                state.codes = codes;

                // A user with no recovery rows at all — no batch, no state row
                // (or an unknown user) — reports None so the service can treat
                // it as "no recovery codes configured".
                if state.codes.is_empty() && state.last_rotated_at.is_none() {
                    Ok::<_, anyhow::Error>(None)
                } else {
                    Ok(Some(state))
                }
            })
            .await
            .map_err(classify_repo_error)
    }

    async fn complete_recovery(
        &self,
        user_id: UserId,
        username: &str,
        passkey: &Passkey,
        name: Option<&str>,
    ) -> Result<(), DomainError> {
        let user_id = user_id.into_inner();
        let result: anyhow::Result<()> = self
            .base
            .with_transaction("insert", "recovery", |mut client| async move {
                let tx = client.transaction().await?;

                // Enroll the fresh passkey.
                Repository::create_credential(&tx, user_id.into(), passkey, name).await?;
                Repository::activate_user(&tx, username).await?;

                // Invalidate the entire batch and reset the recovery state in
                // the same transaction — a code can never be "half used".
                tx.execute(rc_queries::CLEAR_BY_USER, &[&user_id]).await?;
                tx.execute(rs_queries::DELETE_BY_USER, &[&user_id]).await?;

                tx.commit().await?;
                Ok::<(), anyhow::Error>(())
            })
            .await;

        match result {
            Err(e) => Err(classify_write_error(e)),
            Ok(()) => Ok(()),
        }
    }

    async fn set_recovery_lockout(
        &self,
        user_id: UserId,
        lockout: &RecoveryLockout,
    ) -> Result<(), DomainError> {
        let user_id = user_id.into_inner();
        self.base
            .execute_with_circuit_breaker("update", "recovery_state", |db| async move {
                let client = db.get().await?;
                // Upsert preserving last_rotated_at (unset here — it is owned
                // by the batch-replacement path).
                client
                    .execute(
                        rs_queries::UPSERT,
                        &[
                            &user_id,
                            &(lockout.attempts as i32),
                            &lockout.locked_until,
                            &Option::<DateTime<Utc>>::None,
                        ],
                    )
                    .await?;
                Ok::<_, anyhow::Error>(())
            })
            .await
            .map_err(classify_repo_error)
    }
}
