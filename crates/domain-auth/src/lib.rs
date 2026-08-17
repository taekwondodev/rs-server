pub mod claims;
pub mod commands;
pub mod dto;
pub mod error;
pub mod metrics;
pub mod model;
pub mod recovery;
pub mod security_audit;
pub mod service;
pub mod traits;

pub use domain_shared::UserId;

pub use claims::{AccessTokenClaims, RefreshTokenClaims};
pub use commands::{
    AddCredentialCommand, BeginCommand, FinishAddCredentialCommand, FinishCommand,
    ManageRecoveryCodesCommand, RemoveCredentialCommand, VerifyRecoveryCodeCommand,
};
pub use dto::{BeginResult, MessageResult, RecoveryCodesResult, RegistrationKind, TokenResult};
pub use error::DomainError;
pub use model::{Credential, RegistrationOutcome, User, WebAuthnSession};
pub use recovery::{RecoveryCodeRecord, RecoveryLockout, RecoveryState};
pub use security_audit::{ClientContext, SecurityEvent};
pub use service::AuthService;
pub use traits::{AuthRepository, JwtService, TokenPair};

#[cfg(test)]
mod tests;
