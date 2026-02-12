use crate::app::AppError;

use axum::{
    extract::{FromRequest, Request},
    Json,
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

#[inline]
pub fn validate_text(text: &str, field: &str) -> Result<(), AppError> {
    if text.trim().is_empty() {
        return Err(AppError::BadRequest(format!("{} cannot be empty", field)));
    }
    Ok(())
}

#[inline]
pub fn validate_username(username: &str) -> Result<(), AppError> {
    validate_text(username, "Username")?;

    if username.trim().len() < 3 {
        return Err(AppError::BadRequest(String::from(
            "Username must be at least 3 characters",
        )));
    }

    Ok(())
}

#[inline]
pub fn validate_json_credentials(credentials: &serde_json::Value) -> Result<(), AppError> {
    if credentials.is_null() {
        return Err(AppError::BadRequest(String::from("Invalid credentials")));
    }

    if !credentials.is_object() {
        return Err(AppError::BadRequest(String::from("Invalid credentials")));
    }

    if let Some(obj) = credentials.as_object() {
        if obj.is_empty() {
            return Err(AppError::BadRequest(String::from("Invalid credentials")));
        }
    }

    Ok(())
}
