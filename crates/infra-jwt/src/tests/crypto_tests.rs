//! Crypto-dependent claim behavior (encode/decode roundtrips, tampering,
//! wrong issuer/audience, expiry, cross-algorithm rejection). Pure claim-data
//! invariants (fields/new()/getters) live in `domain`'s test suite instead —
//! this crate only owns the crypto layer wrapped around those claim structs.
use std::time::Duration;
use uuid::Uuid;

use domain_auth::{AccessTokenClaims, RefreshTokenClaims, UserId};

use crate::crypto::JwtCrypto;

const TEST_SECRET: &[u8] = b"test-secret-key-at-least-32-bytes!!";
const ISSUER: &str = "https://auth.example.com";
const AUDIENCE: &str = "https://api.example.com";

fn crypto() -> JwtCrypto {
    JwtCrypto::from_secret(TEST_SECRET, ISSUER, AUDIENCE)
}

fn user() -> (UserId, &'static str, Option<&'static str>) {
    (UserId::from(Uuid::new_v4()), "alice", Some("user"))
}

#[test]
fn access_token_roundtrip_preserves_claims() {
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

    let token = c.encode_access(&claims);
    let decoded = c.decode_access(&token).unwrap();

    assert_eq!(decoded.sub, id);
    assert_eq!(decoded.username.as_ref(), username);
    assert_eq!(decoded.role.as_deref(), role);
    assert_eq!(decoded.iss.as_ref(), ISSUER);
    assert_eq!(decoded.aud.as_ref(), AUDIENCE);
}

#[test]
fn access_token_wrong_issuer_rejected() {
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
    let token = c.encode_access(&claims);

    assert!(c.decode_access(&token).is_err());
}

#[test]
fn access_token_wrong_audience_rejected() {
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
    let token = c.encode_access(&claims);

    assert!(c.decode_access(&token).is_err());
}

#[test]
fn access_token_expired_rejected() {
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

    let token = c.encode_access(&claims);
    assert!(c.decode_access(&token).is_err());
}

#[test]
fn access_token_tampered_signature_rejected() {
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
    let token = c.encode_access(&claims);

    let mut parts: Vec<&str> = token.splitn(3, '.').collect();
    let mut bad_sig = parts[2].to_string();
    bad_sig.push('X');
    parts[2] = &bad_sig;
    let tampered = parts.join(".");

    assert!(c.decode_access(&tampered).is_err());
}

#[test]
fn refresh_token_not_accepted_as_access_token() {
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
    let refresh_token = c.encode_refresh(&refresh);

    assert!(c.decode_access(&refresh_token).is_err());
}
