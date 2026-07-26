use crate::error::HttpError;

use axum::{
    Json,
    extract::{FromRequest, Request},
};

pub trait Validatable {
    fn validate(&self) -> Result<(), HttpError>;
}

pub async fn extract_and_validate<T, S>(req: Request, state: &S) -> Result<T, HttpError>
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
            type Rejection = $crate::error::HttpError;

            fn from_request(
                req: axum::extract::Request,
                state: &S,
            ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
                $crate::validation::extract_and_validate(req, state)
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
pub fn validate_text(text: &str, field: &str) -> Result<(), HttpError> {
    if text.trim().is_empty() {
        return Err(HttpError::bad_request(format!("{} cannot be empty", field)));
    }
    Ok(())
}

#[inline]
pub fn validate_username(username: &str) -> Result<(), HttpError> {
    if username.trim().is_empty() {
        return Err(HttpError::bad_request("Username cannot be empty"));
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err(HttpError::bad_request(format!(
            "Username must be at most {MAX_USERNAME_LEN} characters"
        )));
    }
    if username.trim().len() < 3 {
        return Err(HttpError::bad_request("Username must be at least 3 characters"));
    }
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(HttpError::bad_request("Username contains invalid characters"));
    }
    Ok(())
}

#[inline]
pub fn validate_role(role: &str) -> Result<(), HttpError> {
    if role.trim().is_empty() {
        return Err(HttpError::bad_request("Role cannot be empty"));
    }
    if role.len() > MAX_ROLE_LEN {
        return Err(HttpError::bad_request(format!("Role must be at most {MAX_ROLE_LEN} characters")));
    }
    if !role.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(HttpError::bad_request("Role contains invalid characters"));
    }
    Ok(())
}

#[inline]
pub fn validate_json_credentials(credentials: &serde_json::Value) -> Result<(), HttpError> {
    if credentials.is_null() {
        return Err(HttpError::bad_request("Invalid credentials"));
    }
    if !credentials.is_object() {
        return Err(HttpError::bad_request("Invalid credentials"));
    }
    if let Some(obj) = credentials.as_object()
        && obj.is_empty()
    {
        return Err(HttpError::bad_request("Invalid credentials"));
    }
    Ok(())
}
