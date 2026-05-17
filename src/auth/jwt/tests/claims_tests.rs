use std::time::Duration;
use uuid::Uuid;

use crate::auth::jwt::{AccessTokenClaims, JwtCrypto, RefreshTokenClaims};

const TEST_SECRET: &[u8] = b"test-secret-key-at-least-32-bytes!!";
const ISSUER: &str = "https://auth.example.com";
const AUDIENCE: &str = "https://api.example.com";

fn crypto() -> JwtCrypto {
    JwtCrypto::from_secret(TEST_SECRET, ISSUER, AUDIENCE)
}

fn user() -> (Uuid, &'static str, Option<&'static str>) {
    (Uuid::new_v4(), "alice", Some("user"))
}

// --- AccessTokenClaims domain invariants ---

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
    assert_eq!(claims.username, username);
    assert_eq!(claims.role.as_deref(), role);
    assert_eq!(claims.iss, ISSUER);
    assert_eq!(claims.aud, AUDIENCE);
    assert!(claims.exp > claims.iat);
}

#[test]
fn access_claims_no_role_serializes_without_field() {
    let claims = AccessTokenClaims::new(
        Uuid::new_v4(),
        "bob".to_string(),
        None,
        ISSUER,
        AUDIENCE,
        Duration::from_secs(300),
    );
    let json = serde_json::to_string(&claims).unwrap();
    assert!(!json.contains("role"));
}

// --- Access token roundtrip ---

#[tokio::test]
async fn access_token_roundtrip_preserves_claims() {
    let (id, username, role) = user();
    let c = crypto();
    let claims = AccessTokenClaims::new(
        id,
        username.to_string(),
        role.map(str::to_string),
        ISSUER,
        AUDIENCE,
        Duration::from_secs(300),
    );

    let token = claims.to_token(&c);
    let decoded = AccessTokenClaims::validate(&c, &token).await.unwrap();

    assert_eq!(decoded.sub, id);
    assert_eq!(decoded.username, username);
    assert_eq!(decoded.role.as_deref(), role);
    assert_eq!(decoded.iss, ISSUER);
    assert_eq!(decoded.aud, AUDIENCE);
}

// --- OWASP: Authentication token validation ---

#[tokio::test]
async fn access_token_wrong_issuer_rejected() {
    let (id, username, _) = user();
    let c = crypto();
    let claims = AccessTokenClaims::new(
        id,
        username.to_string(),
        None,
        "https://evil.com",
        AUDIENCE,
        Duration::from_secs(300),
    );
    let token = claims.to_token(&c);

    assert!(AccessTokenClaims::validate(&c, &token).await.is_err());
}

#[tokio::test]
async fn access_token_wrong_audience_rejected() {
    let (id, username, _) = user();
    let c = crypto();
    let claims = AccessTokenClaims::new(
        id,
        username.to_string(),
        None,
        ISSUER,
        "https://evil.com",
        Duration::from_secs(300),
    );
    let token = claims.to_token(&c);

    assert!(AccessTokenClaims::validate(&c, &token).await.is_err());
}

#[tokio::test]
async fn access_token_expired_rejected() {
    let (id, username, _) = user();
    let c = crypto();
    let mut claims = AccessTokenClaims::new(
        id,
        username.to_string(),
        None,
        ISSUER,
        AUDIENCE,
        Duration::from_secs(300),
    );
    claims.exp = claims.iat - 120;

    let token = claims.to_token(&c);
    assert!(AccessTokenClaims::validate(&c, &token).await.is_err());
}

#[tokio::test]
async fn access_token_tampered_signature_rejected() {
    let (id, username, _) = user();
    let c = crypto();
    let claims = AccessTokenClaims::new(
        id,
        username.to_string(),
        None,
        ISSUER,
        AUDIENCE,
        Duration::from_secs(300),
    );
    let token = claims.to_token(&c);

    let mut parts: Vec<&str> = token.splitn(3, '.').collect();
    let mut bad_sig = parts[2].to_string();
    bad_sig.push('X');
    parts[2] = &bad_sig;
    let tampered = parts.join(".");

    assert!(AccessTokenClaims::validate(&c, &tampered).await.is_err());
}

// --- OWASP: Cross-algorithm attack (HKDF key independence) ---

#[tokio::test]
async fn refresh_token_not_accepted_as_access_token() {
    let (id, username, _) = user();
    let c = crypto();
    let refresh = RefreshTokenClaims::new(
        id,
        username.to_string(),
        None,
        None,
        ISSUER,
        AUDIENCE,
        Duration::from_secs(300),
    );
    let refresh_token = refresh.to_token(&c);

    assert!(AccessTokenClaims::validate(&c, &refresh_token).await.is_err());
}

// --- RefreshTokenClaims domain invariants ---

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
    assert_eq!(claims.family_id, family);
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
