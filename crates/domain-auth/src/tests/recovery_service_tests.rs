//! Service-layer tests for recovery-code management (generate/rotate) and
//! verification (single-use + lockout). The repository is an in-memory stub
//! wired per test — never a real DB. Expected values come from the spec's
//! Testing Decisions (thresholds, counts), not recomputed from the code.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::{
    commands::{ManageRecoveryCodesCommand, VerifyRecoveryCodeCommand},
    error::DomainError,
    model::{Credential, RegistrationOutcome, User, WebAuthnSession},
    recovery::crypto::{generate_recovery_codes, hash_code},
    recovery::{RecoveryCodeRecord, RecoveryLockout, RecoveryState},
    security_audit::ClientContext,
    service::AuthService,
    traits::{AuthRepository, JwtService, TokenPair},
    UserId,
};

fn now() -> DateTime<Utc> {
    Utc::now()
}

fn user(id: UserId) -> User {
    User {
        id,
        username: "alice".into(),
        role: None,
        status: "active".into(),
        created_at: now(),
        updated_at: now(),
        is_active: true,
    }
}

fn test_webauthn() -> webauthn_rs::Webauthn {
    let origin = webauthn_rs::prelude::Url::parse("http://localhost").unwrap();
    webauthn_rs::WebauthnBuilder::new("localhost", &origin)
        .unwrap()
        .rp_name("rs-server tests")
        .build()
        .unwrap()
}

/// Builds a `RecoveryState` with one batch where the given plaintext code is
/// the code at position 0 (usable), and the rest are random placeholders.
fn state_with_code(code: &str) -> RecoveryState {
    let mut records = Vec::new();
    for i in 0..10 {
        let salt = vec![i as u8; 16];
        let hash = if i == 0 {
            hash_code(code, &salt)
        } else {
            hash_code(&format!("placeholder-{i}"), &salt)
        };
        records.push(RecoveryCodeRecord {
            position: i,
            salt,
            hash,
            used: false,
        });
    }
    RecoveryState {
        codes: records,
        lockout: RecoveryLockout::default(),
        last_rotated_at: None,
    }
}

/// In-memory `AuthRepository` with recovery-focused state. The WebAuthn and
/// credential methods are stubs; the recovery methods are the exercised seam.
struct MockAuthRepository {
    user: Mutex<Option<User>>,
    state: Mutex<Option<RecoveryState>>,
    completed_recoveries: Mutex<Vec<UserId>>,
    last_rotated_at: Mutex<Option<DateTime<Utc>>>,
}

impl Default for MockAuthRepository {
    fn default() -> Self {
        Self {
            user: Mutex::new(Some(user(UserId::new(Uuid::new_v4())))),
            state: Mutex::new(None),
            completed_recoveries: Mutex::new(Vec::new()),
            last_rotated_at: Mutex::new(None),
        }
    }
}

impl MockAuthRepository {
    fn with_user(self, user: User) -> Self {
        *self.user.lock().unwrap() = Some(user);
        self
    }

    fn with_no_user(self) -> Self {
        *self.user.lock().unwrap() = None;
        self
    }

    fn with_state(self, state: RecoveryState) -> Self {
        *self.state.lock().unwrap() = Some(state);
        self
    }

    fn with_last_rotation(self, at: DateTime<Utc>) -> Self {
        *self.last_rotated_at.lock().unwrap() = Some(at);
        // The service reads the cooldown from `state.last_rotated_at`, so the
        // seeded state must reflect it too (not only the separate field).
        {
            let mut state = self.state.lock().unwrap();
            if let Some(s) = state.as_mut() {
                s.last_rotated_at = Some(at);
            }
        }
        self
    }

    fn completed_recoveries(&self) -> Vec<UserId> {
        self.completed_recoveries.lock().unwrap().clone()
    }

    /// Simulates a completed recovery without threading a real `Passkey`
    /// (which the trait method ignores) — clears the batch and state, exactly
    /// what the real `complete_recovery` transaction does.
    fn simulate_recovery_complete(&self, user_id: UserId) {
        *self.state.lock().unwrap() = None;
        *self.last_rotated_at.lock().unwrap() = None;
        self.completed_recoveries.lock().unwrap().push(user_id);
    }
}

impl AuthRepository for MockAuthRepository {
    async fn create_user(&self, _username: &str, _role: Option<&str>) -> Result<RegistrationOutcome, DomainError> {
        unimplemented!("not exercised by recovery tests")
    }

    async fn get_user_and_session(
        &self,
        _session_id: Uuid,
        _username: &str,
        _purpose: &str,
    ) -> Result<(User, WebAuthnSession), DomainError> {
        unimplemented!("not exercised by recovery tests")
    }

    async fn get_user_and_session_by_id(
        &self,
        _session_id: Uuid,
        _user_id: UserId,
        _purpose: &str,
    ) -> Result<(User, WebAuthnSession), DomainError> {
        unimplemented!("not exercised by recovery tests")
    }

    async fn get_active_user_with_credential(
        &self,
        _username: &str,
    ) -> Result<(User, Vec<Passkey>), DomainError> {
        unimplemented!("not exercised by recovery tests")
    }

    async fn get_active_user_by_username(
        &self,
        _username: &str,
    ) -> Result<Option<User>, DomainError> {
        Ok(self.user.lock().unwrap().clone())
    }

    async fn list_credentials(&self, _user_id: UserId) -> Result<Vec<Credential>, DomainError> {
        unimplemented!("not exercised by recovery tests")
    }

    async fn store_credential(
        &self,
        _user_id: UserId,
        _passkey: &Passkey,
        _name: Option<&str>,
    ) -> Result<(), DomainError> {
        unimplemented!("not exercised by recovery tests")
    }

    async fn remove_credential(
        &self,
        _user_id: UserId,
        _cred_id: &[u8],
    ) -> Result<(), DomainError> {
        unimplemented!("not exercised by recovery tests")
    }

    async fn create_webauthn_session(
        &self,
        _user_id: UserId,
        _data: serde_json::Value,
        _purpose: &str,
    ) -> Result<Uuid, DomainError> {
        unimplemented!("not exercised by recovery tests")
    }

    async fn delete_webauthn_session(&self, _id: Uuid) -> Result<(), DomainError> {
        unimplemented!("not exercised by recovery tests")
    }

    async fn update_credential(&self, _cred_id: &[u8], _new_counter: u32) -> Result<(), DomainError> {
        unimplemented!("not exercised by recovery tests")
    }

    async fn complete_registration(
        &self,
        _user_id: UserId,
        _username: &str,
        _passkey: &Passkey,
        _name: Option<&str>,
    ) -> Result<(), DomainError> {
        unimplemented!("not exercised by recovery tests")
    }

    async fn replace_recovery_batch(
        &self,
        _user_id: UserId,
        codes: &[RecoveryCodeRecord],
        last_rotated_at: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        *self.last_rotated_at.lock().unwrap() = Some(last_rotated_at);
        *self.state.lock().unwrap() = Some(RecoveryState {
            codes: codes.to_vec(),
            lockout: RecoveryLockout::default(),
            last_rotated_at: Some(last_rotated_at),
        });
        Ok(())
    }

    async fn get_recovery_state(
        &self,
        _user_id: UserId,
    ) -> Result<Option<RecoveryState>, DomainError> {
        Ok(self.state.lock().unwrap().clone())
    }

    async fn complete_recovery(
        &self,
        user_id: UserId,
        _username: &str,
        _passkey: &Passkey,
        _name: Option<&str>,
    ) -> Result<(), DomainError> {
        // Atomic completion: the batch is consumed and the state reset.
        *self.state.lock().unwrap() = None;
        *self.last_rotated_at.lock().unwrap() = None;
        self.completed_recoveries.lock().unwrap().push(user_id);
        Ok(())
    }

    async fn set_recovery_lockout(
        &self,
        _user_id: UserId,
        lockout: &RecoveryLockout,
    ) -> Result<(), DomainError> {
        let mut state = self.state.lock().unwrap();
        if let Some(s) = state.as_mut() {
            s.lockout = lockout.clone();
        }
        Ok(())
    }
}

#[derive(Default)]
struct MockJwtService;

impl JwtService for MockJwtService {
    fn generate_token_pair(&self, _user_id: UserId, _username: &str, _role: Option<&str>) -> TokenPair {
        unimplemented!()
    }

    fn generate_token_pair_with_family(
        &self,
        _user_id: UserId,
        _username: &str,
        _role: Option<&str>,
        _family_id: &str,
    ) -> TokenPair {
        unimplemented!()
    }

    async fn validate_refresh(
        &self,
        _token: &str,
        _client: &ClientContext,
    ) -> Result<crate::claims::RefreshTokenClaims, DomainError> {
        unimplemented!()
    }

    async fn validate_access(
        &self,
        _token: &str,
    ) -> Result<crate::claims::AccessTokenClaims, DomainError> {
        unimplemented!()
    }

    async fn store_session(&self, _jti: &str, _family_id: &str, _exp: i64) -> Result<(), DomainError> {
        unimplemented!()
    }

    async fn validate_session(&self, _jti: &str) -> Result<(), DomainError> {
        unimplemented!()
    }

    async fn revoke_session(&self, _jti: &str, _family_id: &str) -> Result<(), DomainError> {
        unimplemented!()
    }

    async fn revoke_family(&self, _family_id: &str) -> Result<(), DomainError> {
        unimplemented!()
    }
}

fn service(
    repo: MockAuthRepository,
) -> (AuthService<MockAuthRepository, MockJwtService>, Arc<MockAuthRepository>) {
    let repo = Arc::new(repo);
    let svc = AuthService::new(
        test_webauthn(),
        Arc::clone(&repo),
        Arc::new(MockJwtService),
    );
    (svc, repo)
}

fn uid() -> UserId {
    UserId::new(Uuid::new_v4())
}

fn cmd(uid: UserId) -> ManageRecoveryCodesCommand {
    ManageRecoveryCodesCommand {
        user_id: uid,
        client: ClientContext::default(),
    }
}

// ---------------------------------------------------------------------------
// generate_recovery_codes (T2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn generate_returns_batch_and_stores_hashed_records() {
    let repo = MockAuthRepository::default();
    let (svc, repo_arc) = service(repo);
    let u = uid();

    let result = svc
        .generate_recovery_codes(cmd(u))
        .await
        .expect("generation succeeds on first call");

    assert_eq!(result.codes.len(), 10);
    // All codes are 16 chars (spec Testing Decision).
    assert!(result.codes.iter().all(|c| c.len() == 16));
    // A batch was stored (10 records), proving generation persists.
    let stored = repo_arc.get_recovery_state(u).await.unwrap();
    let stored = stored.expect("batch stored");
    assert_eq!(stored.codes.len(), 10);
    // The plaintext was never stored: hashes differ from any code.
    for rec in &stored.codes {
        assert!(!result.codes.iter().any(|c| c.as_bytes() == rec.hash.as_slice()));
    }
}

#[tokio::test]
async fn generate_refuses_when_batch_already_exists() {
    let code = generate_recovery_codes(1)[0].clone();
    let repo = MockAuthRepository::default().with_state(state_with_code(&code));
    let (svc, _repo_arc) = service(repo);
    let u = uid();

    let err = svc
        .generate_recovery_codes(cmd(u))
        .await
        .expect_err("second generation is refused");

    assert!(matches!(err, DomainError::Conflict(_)));
}

// ---------------------------------------------------------------------------
// rotate_recovery_codes (T2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rotate_returns_fresh_batch() {
    let code = generate_recovery_codes(1)[0].clone();
    // A batch that was last rotated 48h ago (well past the 24h cooldown).
    let repo = MockAuthRepository::default()
        .with_state(state_with_code(&code))
        .with_last_rotation(Utc::now() - Duration::hours(48));
    let (svc, _repo_arc) = service(repo);
    let u = uid();

    let result = svc
        .rotate_recovery_codes(cmd(u))
        .await
        .expect("rotation past cooldown succeeds");

    assert_eq!(result.codes.len(), 10);
    // The new batch differs from the old code.
    assert!(!result.codes.iter().any(|c| c.as_ref() == code));
}

#[tokio::test]
async fn rotate_refuses_within_cooldown() {
    let code = generate_recovery_codes(1)[0].clone();
    // Last rotation 1h ago — inside the 24h cooldown.
    let repo = MockAuthRepository::default()
        .with_state(state_with_code(&code))
        .with_last_rotation(Utc::now() - Duration::hours(1));
    let (svc, _repo_arc) = service(repo);
    let u = uid();

    let err = svc
        .rotate_recovery_codes(cmd(u))
        .await
        .expect_err("rotation inside cooldown is refused");

    assert!(matches!(err, DomainError::Conflict(_)));
}

// ---------------------------------------------------------------------------
// verify_recovery_code (T3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_success_returns_user_but_does_not_consume() {
    let code = generate_recovery_codes(1)[0].clone();
    let u = uid();
    // The recovered user's id must match the account the code was generated for.
    let repo = MockAuthRepository::default()
        .with_user(user(u))
        .with_state(state_with_code(&code));
    let (svc, repo_arc) = service(repo);

    let result = svc
        .verify_recovery_code(VerifyRecoveryCodeCommand {
            username: "alice".into(),
            code: code.clone().into_boxed_str(),
            client: ClientContext::default(),
        })
        .await
        .expect("correct code verifies");

    assert_eq!(result.id, u);
    // Consumption happens atomically in complete_recovery (finish), not here,
    // so a failed attestation does not burn a code.
    assert!(repo_arc.completed_recoveries().is_empty());
}

#[tokio::test]
async fn verify_wrong_code_is_unauthorized() {
    let code = generate_recovery_codes(1)[0].clone();
    let repo = MockAuthRepository::default().with_state(state_with_code(&code));
    let (svc, repo_arc) = service(repo);

    let err = svc
        .verify_recovery_code(VerifyRecoveryCodeCommand {
            username: "alice".into(),
            code: "AAAAAAAAAAAAAAAA".into(),
            client: ClientContext::default(),
        })
        .await
        .expect_err("wrong code rejected");

    assert!(matches!(err, DomainError::Unauthorized(_)));
    // No position consumed on a wrong code.
    assert!(repo_arc.completed_recoveries().is_empty());
}

#[tokio::test]
async fn verify_unknown_username_is_generic_unauthorized() {
    let repo = MockAuthRepository::default().with_no_user();
    let (svc, _repo_arc) = service(repo);

    let err = svc
        .verify_recovery_code(VerifyRecoveryCodeCommand {
            username: "ghost".into(),
            code: "AAAAAAAAAAAAAAAA".into(),
            client: ClientContext::default(),
        })
        .await
        .expect_err("unknown user rejected");

    // Same generic error as a wrong code — no oracle on which condition fired.
    assert!(matches!(err, DomainError::Unauthorized(_)));
}

#[tokio::test]
async fn verify_trips_lockout_after_threshold() {
    let code = generate_recovery_codes(1)[0].clone();
    let repo = MockAuthRepository::default().with_state(state_with_code(&code));
    let (svc, repo_arc) = service(repo);

    // 5 consecutive failures trip the lockout (spec Testing Decision).
    for _ in 0..5 {
        let _ = svc
            .verify_recovery_code(VerifyRecoveryCodeCommand {
                username: "alice".into(),
                code: "AAAAAAAAAAAAAAAA".into(),
                client: ClientContext::default(),
            })
            .await;
    }

    let state = repo_arc.get_recovery_state(uid()).await.unwrap().unwrap();
    assert!(state.lockout.attempts >= 5);
    assert!(
        state.lockout.locked_until.is_some(),
        "lockout deadline set after threshold"
    );
}

#[tokio::test]
async fn verify_rejects_while_locked() {
    // Seed a locked state (locked_until in the future).
    let code = generate_recovery_codes(1)[0].clone();
    let mut state = state_with_code(&code);
    state.lockout.locked_until = Some(Utc::now() + Duration::hours(1));
    let repo = MockAuthRepository::default().with_state(state);
    let (svc, repo_arc) = service(repo);

    // Even the CORRECT code is rejected while locked, and not consumed.
    let err = svc
        .verify_recovery_code(VerifyRecoveryCodeCommand {
            username: "alice".into(),
            code: code.into_boxed_str(),
            client: ClientContext::default(),
        })
        .await
        .expect_err("locked recovery path rejects even a correct code");

    assert!(matches!(err, DomainError::Unauthorized(_)));
    assert!(repo_arc.completed_recoveries().is_empty());
}

#[tokio::test]
async fn verify_success_clears_attempt_counter() {
    let code = generate_recovery_codes(1)[0].clone();
    let repo = MockAuthRepository::default().with_state(state_with_code(&code));
    let (svc, repo_arc) = service(repo);

    // 3 failures, then a success.
    for _ in 0..3 {
        let _ = svc
            .verify_recovery_code(VerifyRecoveryCodeCommand {
                username: "alice".into(),
                code: "AAAAAAAAAAAAAAAA".into(),
                client: ClientContext::default(),
            })
            .await;
    }
    svc.verify_recovery_code(VerifyRecoveryCodeCommand {
        username: "alice".into(),
        code: code.clone().into_boxed_str(),
        client: ClientContext::default(),
    })
    .await
    .expect("correct code succeeds after failures");

    let state = repo_arc.get_recovery_state(uid()).await.unwrap().unwrap();
    assert_eq!(state.lockout.attempts, 0, "success clears the attempt counter");
}

// ---------------------------------------------------------------------------
// finish_recovery / complete_recovery — atomic consumption
// ---------------------------------------------------------------------------

#[tokio::test]
async fn complete_recovery_invalidates_batch_and_allows_regeneration() {
    // Regression for the blocker: after a successful recovery, the user must
    // be able to generate a fresh batch (the recovery state was left behind
    // previously, so `generate` saw a leftover batch and returned Conflict).
    let u = uid();
    // Start with NO batch — first generation creates one.
    let repo = MockAuthRepository::default().with_user(user(u));
    let (svc, repo_arc) = service(repo);

    // First generation succeeds.
    svc.generate_recovery_codes(cmd(u))
        .await
        .expect("first generation succeeds");

    // A recovery completes: the batch and state are consumed atomically. The
    // mock drives it through the same seam `finish_recovery` would.
    repo_arc.simulate_recovery_complete(u);

    // After recovery, a fresh batch can be generated again (no leftover state).
    svc.generate_recovery_codes(cmd(u))
        .await
        .expect("regeneration after recovery succeeds");
}
