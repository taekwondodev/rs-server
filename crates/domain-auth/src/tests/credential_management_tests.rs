//! Service-layer tests for the passkey management flows (add/list/remove).
//!
//! The WebAuthn ceremonies themselves belong to `webauthn-rs`; what we own
//! here is the wiring: excludeCredentials from existing credentials, the
//! last-credential guard mapping, and the session lookups. The repository is
//! a hand-rolled in-memory stub configured per test — never a real DB.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

use crate::{
    commands::{
        AddCredentialCommand, BeginCommand, FinishAddCredentialCommand, RemoveCredentialCommand,
    },
    error::DomainError,
    model::{Credential, RegistrationOutcome, User, WebAuthnSession},
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

fn credential(id: Vec<u8>, name: Option<&str>) -> Credential {
    Credential {
        id,
        name: name.map(Into::into),
        created_at: now(),
        last_used_at: None,
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

fn b64(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Result the mock's `remove_credential` reports, mirroring the boundary
/// contract of the real repository (`Ok` vs `NotFound` vs last-credential
/// `Conflict`).
#[derive(Default)]
enum MockRemoveResult {
    #[default]
    Removed,
    NotFound,
    LastCredential,
}

/// In-memory `AuthRepository`. Only the methods the management flows touch
/// are wired; everything else panics if a test accidentally reaches it.
#[derive(Default)]
struct MockAuthRepository {
    credentials: Mutex<Vec<Credential>>,
    sessions: Mutex<Vec<(Uuid, UserId, String, serde_json::Value)>>,
    remove_result: Mutex<MockRemoveResult>,
    resume: Mutex<bool>,
}

impl MockAuthRepository {
    fn add_session(&self, user_id: UserId, purpose: &str, data: serde_json::Value) -> Uuid {
        let id = Uuid::new_v4();
        self.sessions
            .lock()
            .unwrap()
            .push((id, user_id, purpose.into(), data));
        id
    }

    fn with_remove_result(self, result: MockRemoveResult) -> Self {
        *self.remove_result.lock().unwrap() = result;
        self
    }

    fn with_credentials(self, credentials: Vec<Credential>) -> Self {
        *self.credentials.lock().unwrap() = credentials;
        self
    }

    /// `create_user` reports the user as resumed (pending) instead of fresh.
    fn with_resume(self) -> Self {
        *self.resume.lock().unwrap() = true;
        self
    }
}

impl AuthRepository for MockAuthRepository {
    async fn create_user(&self, _username: &str, _role: Option<&str>) -> Result<RegistrationOutcome, DomainError> {
        let user = user(UserId::new(Uuid::new_v4()));
        if *self.resume.lock().unwrap() {
            Ok(RegistrationOutcome::Resumed(user))
        } else {
            Ok(RegistrationOutcome::Created(user))
        }
    }

    async fn get_user_and_session(
        &self,
        _session_id: Uuid,
        _username: &str,
        _purpose: &str,
    ) -> Result<(User, WebAuthnSession), DomainError> {
        unimplemented!("not exercised by management-flow tests")
    }

    async fn get_user_and_session_by_id(
        &self,
        session_id: Uuid,
        user_id: UserId,
        purpose: &str,
    ) -> Result<(User, WebAuthnSession), DomainError> {
        let found = self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .find(|(id, uid, p, _)| *id == session_id && *uid == user_id && p == purpose)
            .cloned();
        match found {
            Some((id, _, _, data)) => Ok((
                user(user_id),
                WebAuthnSession {
                    id,
                    user_id,
                    data,
                    purpose: purpose.into(),
                    created_at: now(),
                    expires_at: now(),
                },
            )),
            None => Err(DomainError::NotFound("User or session not found")),
        }
    }

    async fn get_active_user_with_credential(
        &self,
        _username: &str,
    ) -> Result<(User, Vec<Passkey>), DomainError> {
        unimplemented!("not exercised by management-flow tests")
    }

    async fn list_credentials(&self, _user_id: UserId) -> Result<Vec<Credential>, DomainError> {
        Ok(self.credentials.lock().unwrap().clone())
    }

    async fn store_credential(
        &self,
        _user_id: UserId,
        _passkey: &Passkey,
        _name: Option<&str>,
    ) -> Result<(), DomainError> {
        unimplemented!("needs a real ceremony; covered by webauthn-rs itself")
    }

    async fn remove_credential(
        &self,
        _user_id: UserId,
        _cred_id: &[u8],
    ) -> Result<(), DomainError> {
        match *self.remove_result.lock().unwrap() {
            MockRemoveResult::Removed => Ok(()),
            MockRemoveResult::NotFound => Err(DomainError::NotFound("Credential not found")),
            MockRemoveResult::LastCredential => {
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
        Ok(self.add_session(user_id, purpose, data))
    }

    async fn delete_webauthn_session(&self, _id: Uuid) -> Result<(), DomainError> {
        Ok(())
    }

    async fn update_credential(&self, _cred_id: &[u8], _new_counter: u32) -> Result<(), DomainError> {
        unimplemented!("not exercised by management-flow tests")
    }

    async fn complete_registration(
        &self,
        _user_id: UserId,
        _username: &str,
        _passkey: &Passkey,
        _name: Option<&str>,
    ) -> Result<(), DomainError> {
        unimplemented!("not exercised by management-flow tests")
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

fn service(repo: MockAuthRepository) -> AuthService<MockAuthRepository, MockJwtService> {
    AuthService::new(
        test_webauthn(),
        Arc::new(repo),
        Arc::new(MockJwtService),
    )
}

// ---------------------------------------------------------------------------
// begin_add_credential — excludeCredentials
// ---------------------------------------------------------------------------

#[tokio::test]
async fn begin_add_credential_excludes_existing_credentials() {
    let repo = MockAuthRepository::default().with_credentials(vec![
        credential(vec![1, 2, 3], Some("iPhone")),
        credential(vec![4, 5], None),
    ]);
    let svc = service(repo);
    let uid = UserId::new(Uuid::new_v4());

    let result = svc
        .begin_add_credential(AddCredentialCommand {
            user_id: uid,
            username: "alice".into(),
        })
        .await
        .expect("ceremony starts");

    // webauthn-rs 0.5 wraps the options in `publicKey` (the browser
    // `navigator.credentials.create({publicKey})` payload shape).
    let excludes = result
        .options
        .get("publicKey")
        .and_then(|pk| pk.get("excludeCredentials"))
        .expect("excludeCredentials is present when the user has credentials")
        .as_array()
        .expect("excludeCredentials is an array");

    let ids: Vec<String> = excludes
        .iter()
        .map(|d| d.get("id").unwrap().as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids, vec![b64(&[1, 2, 3]), b64(&[4, 5])]);
}

#[tokio::test]
async fn begin_add_credential_without_credentials_has_empty_exclude_list() {
    let svc = service(MockAuthRepository::default());
    let uid = UserId::new(Uuid::new_v4());

    let result = svc
        .begin_add_credential(AddCredentialCommand {
            user_id: uid,
            username: "alice".into(),
        })
        .await
        .expect("ceremony starts");

    let excludes = result
        .options
        .get("publicKey")
        .and_then(|pk| pk.get("excludeCredentials"))
        .expect("excludeCredentials is always present (empty list, not omitted)")
        .as_array()
        .expect("excludeCredentials is an array");
    assert!(excludes.is_empty());
}

#[tokio::test]
async fn begin_register_resumed_excludes_existing_credentials() {
    // The same exclude wiring must apply when a registration is resumed,
    // not only to the dedicated add flow.
    let repo = MockAuthRepository::default()
        .with_resume()
        .with_credentials(vec![credential(vec![9, 9, 9], None)]);
    let svc = service(repo);

    let (result, _kind) = svc
        .begin_register(BeginCommand {
            username: "alice".into(),
            role: None,
        })
        .await
        .expect("ceremony starts");

    let excludes = result
        .options
        .get("publicKey")
        .and_then(|pk| pk.get("excludeCredentials"))
        .expect("excludeCredentials present")
        .as_array()
        .unwrap();
    let ids: Vec<String> = excludes
        .iter()
        .map(|d| d.get("id").unwrap().as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids, vec![b64(&[9, 9, 9])]);
}

// ---------------------------------------------------------------------------
// remove_credential — outcome mapping (guard lives in the repository)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn remove_credential_success() {
    let repo = MockAuthRepository::default().with_remove_result(MockRemoveResult::Removed);
    let svc = service(repo);
    let uid = UserId::new(Uuid::new_v4());

    let result = svc
        .remove_credential(RemoveCredentialCommand {
            user_id: uid,
            cred_id: vec![1, 2, 3],
            client: ClientContext::default(),
        })
        .await;

    assert!(matches!(result, Ok(r) if r.message == "Credential removed successfully!"));
}

#[tokio::test]
async fn remove_credential_not_found_maps_to_not_found_error() {
    let repo = MockAuthRepository::default().with_remove_result(MockRemoveResult::NotFound);
    let svc = service(repo);
    let uid = UserId::new(Uuid::new_v4());

    let err = svc
        .remove_credential(RemoveCredentialCommand {
            user_id: uid,
            cred_id: vec![9, 9],
            client: ClientContext::default(),
        })
        .await
        .expect_err("not found propagates");

    assert!(matches!(err, DomainError::NotFound(_)));
}

#[tokio::test]
async fn remove_last_credential_maps_to_conflict() {
    // The last-credential guard lives in the repository transaction; the
    // service's job is to propagate the boundary error unchanged.
    let repo = MockAuthRepository::default().with_remove_result(MockRemoveResult::LastCredential);
    let svc = service(repo);
    let uid = UserId::new(Uuid::new_v4());

    let err = svc
        .remove_credential(RemoveCredentialCommand {
            user_id: uid,
            cred_id: vec![1],
            client: ClientContext::default(),
        })
        .await
        .expect_err("last-credential removal is refused");

    assert!(matches!(err, DomainError::Conflict(_)));
}

// ---------------------------------------------------------------------------
// finish_add_credential — session and verification plumbing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn finish_add_credential_rejects_session_from_another_user() {
    // A REAL credential_add session belonging to someone else: the service
    // must refuse it for a different caller. If the service looked up the
    // session with the wrong identity (e.g. the session owner instead of the
    // caller), this test fails because the mock WOULD find the session.
    let owner = UserId::new(Uuid::new_v4());
    let attacker = UserId::new(Uuid::new_v4());
    let repo = MockAuthRepository::default();
    let svc = service(repo);

    let begin = svc
        .begin_add_credential(AddCredentialCommand {
            user_id: owner,
            username: "alice".into(),
        })
        .await
        .expect("owner starts the ceremony");

    let err = svc
        .finish_add_credential(FinishAddCredentialCommand {
            user_id: attacker,
            session_id: begin.session_id,
            credentials: serde_json::json!({}),
            name: None,
            client: ClientContext::default(),
        })
        .await
        .expect_err("another user's session is refused");

    assert!(matches!(err, DomainError::NotFound(_)));
}

#[tokio::test]
async fn finish_add_credential_rejects_invalid_attestation() {
    // Seed a real credential_add session (data from a genuine ceremony
    // start), then feed a structurally-valid-but-bogus attestation: the
    // verification inside webauthn-rs must surface as BadRequest, the same
    // contract finish_register already has.
    let repo = MockAuthRepository::default();
    let svc = service(repo);
    let uid = UserId::new(Uuid::new_v4());

    let begin = svc
        .begin_add_credential(AddCredentialCommand {
            user_id: uid,
            username: "alice".into(),
        })
        .await
        .expect("ceremony starts");

    let err = svc
        .finish_add_credential(FinishAddCredentialCommand {
            user_id: uid,
            session_id: begin.session_id,
            credentials: serde_json::json!({
                "id": "AQID",
                "rawId": "AQID",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "e30=",
                    "attestationObject": "e30="
                }
            }),
            name: Some("Phone".into()),
            client: ClientContext::default(),
        })
        .await
        .expect_err("bogus attestation is refused");

    assert!(matches!(err, DomainError::BadRequest(_)));
}
