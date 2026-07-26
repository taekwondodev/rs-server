pub mod claims;
pub mod commands;
pub mod dto;
pub mod error;
pub mod metrics;
pub mod model;
pub mod security_audit;
pub mod service;
pub mod traits;

pub use domain_shared::UserId;

pub use claims::{AccessTokenClaims, RefreshTokenClaims};
pub use commands::{BeginCommand, FinishCommand};
pub use dto::{BeginResult, MessageResult, RegistrationKind, TokenResult};
pub use error::DomainError;
pub use model::{RegistrationOutcome, User, WebAuthnSession};
pub use security_audit::SecurityEvent;
pub use service::AuthService;
pub use traits::{AuthRepository, JwtService, TokenPair};

#[cfg(test)]
mod tests;
