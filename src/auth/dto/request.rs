use serde::Deserialize;
use utoipa::ToSchema;

use crate::{
    app::AppError,
    impl_validated_json_request,
    utils::validation::{validate_json_credentials, validate_text, validate_username, Validatable},
};

#[derive(Debug, Deserialize, ToSchema)]
pub struct BeginRequest {
    #[schema(example = "john_doe", min_length = 3)]
    pub username: String,
    #[schema(example = "admin")]
    pub role: Option<String>,
}

impl Validatable for BeginRequest {
    fn validate(&self) -> Result<(), AppError> {
        validate_username(&self.username)?;
        Ok(())
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct FinishRequest {
    #[schema(example = "john_doe")]
    pub username: String,
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub session_id: String,
    #[schema(example = json!({"id": "AQIDBAUGBwgJCgsMDQ4PEA", "rawId": "AQIDBAUGBwgJCgsMDQ4PEA", "type": "public-key"}))]
    pub credentials: serde_json::Value,
}

impl Validatable for FinishRequest {
    fn validate(&self) -> Result<(), AppError> {
        validate_username(&self.username)?;
        validate_text(&self.session_id, "Session ID")?;
        validate_json_credentials(&self.credentials)?;
        Ok(())
    }
}

impl_validated_json_request!(BeginRequest);
impl_validated_json_request!(FinishRequest);
