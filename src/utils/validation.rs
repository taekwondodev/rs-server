use crate::app::AppError;

use axum::{
    Json,
    extract::{FromRequest, Request},
};

pub trait Validatable {
    fn validate(&self) -> Result<(), AppError>;
}

pub async fn extract_and_validate<T, S>(req: Request, state: &S) -> Result<T, AppError>
where
    T: Validatable + serde::de::DeserializeOwned,
    S: Send + Sync,
{
    let Json(request) = Json::<T>::from_request(req, state).await?;
    request.validate()?;
    Ok(request)
}

#[macro_export]
macro_rules! impl_validated_json_request {
    ($type:ty) => {
        impl<S> axum::extract::FromRequest<S> for $type
        where
            S: Send + Sync,
        {
            type Rejection = $crate::app::AppError;

            fn from_request(
                req: axum::extract::Request,
                state: &S,
            ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
                $crate::utils::validation::extract_and_validate(req, state)
            }
        }
    };
}

// ============================================================================
// Validation Helpers
// ============================================================================

const MAX_USERNAME_LEN: usize = 64;
const MAX_ROLE_LEN: usize = 32;

#[inline]
pub fn validate_text(text: &str, field: &str) -> Result<(), AppError> {
    if text.trim().is_empty() {
        return Err(AppError::BadRequest(format!("{} cannot be empty", field).into()));
    }
    Ok(())
}

#[inline]
pub fn validate_username(username: &str) -> Result<(), AppError> {
    if username.trim().is_empty() {
        return Err(AppError::BadRequest("Username cannot be empty".into()));
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err(AppError::BadRequest(
            format!("Username must be at most {MAX_USERNAME_LEN} characters").into(),
        ));
    }
    if username.trim().len() < 3 {
        return Err(AppError::BadRequest(
            "Username must be at least 3 characters".into(),
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AppError::BadRequest(
            "Username contains invalid characters".into(),
        ));
    }
    Ok(())
}

#[inline]
pub fn validate_role(role: &str) -> Result<(), AppError> {
    if role.trim().is_empty() {
        return Err(AppError::BadRequest("Role cannot be empty".into()));
    }
    if role.len() > MAX_ROLE_LEN {
        return Err(AppError::BadRequest(
            format!("Role must be at most {MAX_ROLE_LEN} characters").into(),
        ));
    }
    if !role.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(AppError::BadRequest(
            "Role contains invalid characters".into(),
        ));
    }
    Ok(())
}

#[inline]
pub fn validate_json_credentials(credentials: &serde_json::Value) -> Result<(), AppError> {
    if credentials.is_null() {
        return Err(AppError::BadRequest("Invalid credentials".into()));
    }
    if !credentials.is_object() {
        return Err(AppError::BadRequest("Invalid credentials".into()));
    }
    if let Some(obj) = credentials.as_object()
        && obj.is_empty()
    {
        return Err(AppError::BadRequest("Invalid credentials".into()));
    }
    Ok(())
}
