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
    pub client: crate::security_audit::ClientContext,
}
