use std::borrow::Cow;

/// Plain result of `AuthService::begin_register`/`begin_login`. `http` maps
/// this into its own axum/utoipa-flavored `BeginResponse` wire type.
#[derive(Debug)]
pub struct BeginResult {
    pub options: serde_json::Value,
    pub session_id: Box<str>,
}

/// Distinguishes a fresh registration from one resuming an incomplete
/// registration attempt, without `AuthService` reaching into Prometheus
/// itself. `http::handler::begin_register` reads this to call
/// `metrics::track_registration_conflict` at the HTTP boundary, matching how
/// every other track_* call already happens at the handler layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationKind {
    Fresh,
    Resumed,
}

#[derive(Debug)]
pub struct MessageResult {
    pub message: Cow<'static, str>,
}

#[derive(Debug)]
pub struct TokenResult {
    pub message: Cow<'static, str>,
    pub access_token: Box<str>,
}
