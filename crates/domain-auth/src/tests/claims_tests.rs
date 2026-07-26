//! Pure claim-data invariants (fields/new()/getters). Crypto-dependent
//! behavior (to_token/validate roundtrips, tampering, wrong issuer/audience,
//! expiry, cross-algorithm rejection) moved to `infra_jwt`'s test suite along
//! with `JwtCrypto`.
use std::time::Duration;
use domain_shared::UserId;
use uuid::Uuid;

use crate::claims::{AccessTokenClaims, RefreshTokenClaims};

const ISSUER: &str = "https://auth.example.com";
const AUDIENCE: &str = "https://api.example.com";

fn user() -> (UserId, &'static str, Option<&'static str>) {
    (UserId::from(Uuid::new_v4()), "alice", Some("user"))
}

#[test]
fn access_claims_fields_set_correctly() {
    let (id, username, role) = user();
    let claims = AccessTokenClaims::new(
        id,
        username.to_string(),
        role.map(str::to_string),
        ISSUER,
        AUDIENCE,
        Duration::from_secs(300),
    );

    assert_eq!(claims.sub, id);
    assert_eq!(claims.username.as_ref(), username);
    assert_eq!(claims.role.as_deref(), role);
    assert_eq!(claims.iss.as_ref(), ISSUER);
    assert_eq!(claims.aud.as_ref(), AUDIENCE);
    assert!(claims.exp > claims.iat);
}

#[test]
fn access_claims_no_role_serializes_without_field() {
    let claims = AccessTokenClaims::new(
        Uuid::new_v4().into(),
        "bob".to_string(),
        None,
        ISSUER,
        AUDIENCE,
        Duration::from_secs(300),
    );
    let json = serde_json::to_string(&claims).unwrap();
    assert!(!json.contains("role"));
}

#[test]
fn refresh_claims_jti_is_unique_per_token() {
    let (id, username, _) = user();
    let c1 = RefreshTokenClaims::new(
        id,
        username.to_string(),
        None,
        None,
        ISSUER,
        AUDIENCE,
        Duration::from_secs(300),
    );
    let c2 = RefreshTokenClaims::new(
        id,
        username.to_string(),
        None,
        None,
        ISSUER,
        AUDIENCE,
        Duration::from_secs(300),
    );
    assert_ne!(c1.jti, c2.jti);
}

#[test]
fn refresh_claims_generates_family_id_when_none() {
    let (id, username, _) = user();
    let claims = RefreshTokenClaims::new(
        id,
        username.to_string(),
        None,
        None,
        ISSUER,
        AUDIENCE,
        Duration::from_secs(300),
    );
    assert!(!claims.family_id.is_empty());
}

#[test]
fn refresh_claims_preserves_provided_family_id() {
    let (id, username, _) = user();
    let family = "existing-family".to_string();
    let claims = RefreshTokenClaims::new(
        id,
        username.to_string(),
        None,
        Some(family.clone()),
        ISSUER,
        AUDIENCE,
        Duration::from_secs(300),
    );
    assert_eq!(claims.family_id.as_ref(), family);
}

#[test]
fn refresh_claims_carries_username_and_role() {
    let (id, username, role) = user();
    let claims = RefreshTokenClaims::new(
        id,
        username.to_string(),
        role.map(str::to_string),
        None,
        ISSUER,
        AUDIENCE,
        Duration::from_secs(300),
    );
    assert_eq!(claims.username(), username);
    assert_eq!(claims.role(), role);
}
