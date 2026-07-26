use serde::Deserialize;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

use crate::{
    impl_validated_json_request,
    validation::{Validatable, validate_json_credentials, validate_role, validate_text, validate_username},
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
}

impl Validatable for FinishRequest {
    fn validate(&self) -> Result<(), crate::error::HttpError> {
        validate_username(&self.username)?;
        validate_text(&self.session_id, "Session ID")?;
        validate_json_credentials(&self.credentials)?;
        Ok(())
    }
}

impl From<FinishRequest> for domain_auth::FinishCommand {
    fn from(req: FinishRequest) -> Self {
        domain_auth::FinishCommand {
            username: req.username,
            session_id: req.session_id,
            credentials: req.credentials,
        }
    }
}

impl_validated_json_request!(BeginRequest);
impl_validated_json_request!(FinishRequest);
