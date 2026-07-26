use std::sync::Arc;

use domain_auth::{AuthRepository, AuthService, JwtService};
use rs_repository_utils::HealthIndicator;

use crate::cookie::CookieService;

/// Generic over the port implementations — `http` never names
/// `infra_postgres::Repository` or `infra_jwt::Jwt` concretely. Only
/// `rs-server`'s `main.rs` picks the concrete `R`/`J` and monomorphizes.
///
/// Used as axum's `State<AppState<R, J>>` directly (not `Arc`-wrapped) rather
/// than the pre-split `Arc<AppState>`: `AccessTokenClaims`/`SecurityEvent`
/// etc. now live in `domain`, so the `FromRequestParts` impls in
/// `middleware::auth`/`middleware::gateway` implement a foreign trait for a
/// foreign `Self` type. That's only coherent (orphan rules) when a local type
/// appears *directly* as the trait's state parameter — `Arc<AppState<..>>`
/// doesn't count since `Arc` isn't a fundamental type, but `AppState<..>`
/// itself does. `AppState` derives `Clone` (all fields are already `Arc`s
/// internally) so this costs nothing extra per request.
pub struct AppState<R, J>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    pub auth_service: Arc<AuthService<R, J>>,
    pub jwt_service: Arc<J>,
    pub cookie_service: Arc<CookieService>,
    /// Open-ended set of checkable dependencies for `/healthz` — not tied to
    /// `R`/`J` on purpose, so adding an indicator never touches this struct's
    /// generic shape. See `health::HealthIndicator` docs for why this is the
    /// one legitimate `dyn Trait` in the workspace.
    pub health_indicators: Vec<Arc<dyn HealthIndicator>>,
}

// Manual `Clone` impl: `#[derive(Clone)]` would add `R: Clone, J: Clone`
// bounds on the struct itself, which aren't needed — every field is already
// an `Arc`, so cloning is always just a refcount bump regardless of whether
// `R`/`J` implement `Clone`.
impl<R, J> Clone for AppState<R, J>
where
    R: AuthRepository + 'static,
    J: JwtService + 'static,
{
    fn clone(&self) -> Self {
        Self {
            auth_service: Arc::clone(&self.auth_service),
            jwt_service: Arc::clone(&self.jwt_service),
            cookie_service: Arc::clone(&self.cookie_service),
            health_indicators: self.health_indicators.clone(),
        }
    }
}
