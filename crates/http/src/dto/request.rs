use serde::Deserialize;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

use crate::{
    impl_validated_json_request,
    validation::{
        validate_json_credentials, validate_optional_credential_name, validate_role, validate_text,
        validate_username, Validatable,
    },
};

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(deny_unknown_fields)]
pub struct BeginRequest {
    #[cfg_attr(feature = "openapi", schema(example = "john_doe", min_length = 3, max_length = 64))]
    pub username: Box<str>,
    #[cfg_attr(feature = "openapi", schema(example = "admin"))]
    pub role: Option<Box<str>>,
}

impl Validatable for BeginRequest {
    fn validate(&self) -> Result<(), crate::error::HttpError> {
        validate_username(&self.username)?;
        if let Some(role) = &self.role {
            validate_role(role)?;
        }
        Ok(())
    }
}

impl From<BeginRequest> for domain_auth::BeginCommand {
    fn from(req: BeginRequest) -> Self {
        domain_auth::BeginCommand {
            username: req.username,
            role: req.role,
        }
    }
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(deny_unknown_fields)]
pub struct FinishRequest {
    #[cfg_attr(feature = "openapi", schema(example = "john_doe"))]
    pub username: Box<str>,
    #[cfg_attr(feature = "openapi", schema(example = "550e8400-e29b-41d4-a716-446655440000"))]
    pub session_id: Box<str>,
    #[cfg_attr(
        feature = "openapi",
        schema(example = json!({"id": "AQIDBAUGBwgJCgsMDQ4PEA", "rawId": "AQIDBAUGBwgJCgsMDQ4PEA", "type": "public-key"}))
    )]
    pub credentials: serde_json::Value,
    #[cfg_attr(feature = "openapi", schema(example = "MacBook Pro"))]
    pub name: Option<Box<str>>,
}

impl Validatable for FinishRequest {
    fn validate(&self) -> Result<(), crate::error::HttpError> {
        validate_username(&self.username)?;
        validate_text(&self.session_id, "Session ID")?;
        validate_json_credentials(&self.credentials)?;
        validate_optional_credential_name(self.name.as_deref())?;
        Ok(())
    }
}

impl From<FinishRequest> for domain_auth::FinishCommand {
    fn from(req: FinishRequest) -> Self {
        domain_auth::FinishCommand {
            username: req.username,
            session_id: req.session_id,
            credentials: req.credentials,
            name: req.name,
            client: domain_auth::ClientContext::default(),
        }
    }
}

impl_validated_json_request!(BeginRequest);
impl_validated_json_request!(FinishRequest);

/// Body of `POST /auth/credentials/finish`. Unlike `FinishRequest` there is
/// no username: the authenticated user is derived from the Bearer token, so
/// the body carries only the ceremony artifacts plus the optional name.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(deny_unknown_fields)]
pub struct FinishCredentialRequest {
    #[cfg_attr(feature = "openapi", schema(example = "550e8400-e29b-41d4-a716-446655440000"))]
    pub session_id: Box<str>,
    #[cfg_attr(
        feature = "openapi",
        schema(example = json!({"id": "AQIDBAUGBwgJCgsMDQ4PEA", "rawId": "AQIDBAUGBwgJCgsMDQ4PEA", "type": "public-key"}))
    )]
    pub credentials: serde_json::Value,
    #[cfg_attr(feature = "openapi", schema(example = "MacBook Pro"))]
    pub name: Option<Box<str>>,
}

impl Validatable for FinishCredentialRequest {
    fn validate(&self) -> Result<(), crate::error::HttpError> {
        validate_text(&self.session_id, "Session ID")?;
        validate_json_credentials(&self.credentials)?;
        validate_optional_credential_name(self.name.as_deref())?;
        Ok(())
    }
}

impl_validated_json_request!(FinishCredentialRequest);
