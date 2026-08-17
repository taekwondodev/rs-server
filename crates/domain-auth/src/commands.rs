use domain_shared::UserId;

use crate::security_audit::ClientContext;

/// Plain domain command, mapped from `http`'s `BeginRequest` (the axum
/// extractor/wire type) before calling into `AuthService`. Reused for both
/// `begin_register` and `begin_login` since both accept the same
/// username+role shape today — same relationship the pre-refactor code had
/// with a single `BeginRequest` DTO serving both routes.
#[derive(Debug, Clone)]
pub struct BeginCommand {
    pub username: Box<str>,
    pub role: Option<Box<str>>,
}

/// Plain domain command, mapped from `http`'s `FinishRequest`.
#[derive(Debug, Clone)]
pub struct FinishCommand {
    pub username: Box<str>,
    pub session_id: Box<str>,
    pub credentials: serde_json::Value,
    /// Optional human-readable label for the freshly registered passkey.
    pub name: Option<Box<str>>,
    pub client: ClientContext,
}

/// Add-credential ceremony, authenticated: identity comes from the access
/// token claims, never from the request body.
#[derive(Debug, Clone)]
pub struct AddCredentialCommand {
    pub user_id: UserId,
    pub username: Box<str>,
}

#[derive(Debug, Clone)]
pub struct FinishAddCredentialCommand {
    pub user_id: UserId,
    pub session_id: Box<str>,
    pub credentials: serde_json::Value,
    pub name: Option<Box<str>>,
    pub client: ClientContext,
}

#[derive(Debug, Clone)]
pub struct RemoveCredentialCommand {
    pub user_id: UserId,
    pub cred_id: Vec<u8>,
    pub client: ClientContext,
}

/// Generate-or-rotate recovery codes. Identity comes from the authenticated
/// access-token claims (`user_id`), never the request body. The same command
/// serves first generation and rotation; the service distinguishes them by
/// whether a batch already exists / how recent the last rotation was.
#[derive(Debug, Clone)]
pub struct ManageRecoveryCodesCommand {
    pub user_id: UserId,
    pub client: ClientContext,
}

/// Present a recovery code to start the recovery ceremony. This is the one
/// flow where identity is not a passkey or token — it is username + code, the
/// only path back into an account whose every authenticator is lost.
#[derive(Debug, Clone)]
pub struct VerifyRecoveryCodeCommand {
    pub username: Box<str>,
    pub code: Box<str>,
    pub client: ClientContext,
}
