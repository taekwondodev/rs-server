use std::time::Duration;

use axum::{body::Body, http::Request};
use uuid::Uuid;

use crate::{
    app::middleware::gateway::{inject_identity_headers, strip_forwarded_headers},
    auth::jwt::AccessTokenClaims,
};

const X_USER_ID: &str = "x-user-id";
const X_USER_ROLE: &str = "x-user-role";

fn make_request(headers: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder().uri("/test").method("GET");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    builder.body(Body::empty()).unwrap()
}

fn claims(sub: Uuid, role: Option<&str>) -> AccessTokenClaims {
    AccessTokenClaims::new(
        sub,
        "testuser".to_string(),
        role.map(str::to_string),
        "https://auth.example.com",
        "https://api.example.com",
        Duration::from_secs(300),
    )
}

// OWASP A01 — Broken Access Control: header injection bypass

#[test]
fn strip_removes_x_user_id() {
    let mut req = make_request(&[(X_USER_ID, "attacker-uuid")]);
    strip_forwarded_headers(&mut req);
    assert!(req.headers().get(X_USER_ID).is_none());
}

#[test]
fn strip_removes_x_user_role() {
    let mut req = make_request(&[(X_USER_ROLE, "admin")]);
    strip_forwarded_headers(&mut req);
    assert!(req.headers().get(X_USER_ROLE).is_none());
}

#[test]
fn strip_removes_both_simultaneously() {
    let mut req = make_request(&[(X_USER_ID, "attacker"), (X_USER_ROLE, "admin")]);
    strip_forwarded_headers(&mut req);
    assert!(req.headers().get(X_USER_ID).is_none());
    assert!(req.headers().get(X_USER_ROLE).is_none());
}

#[test]
fn strip_is_idempotent_on_clean_request() {
    let mut req = make_request(&[]);
    strip_forwarded_headers(&mut req);
    assert!(req.headers().get(X_USER_ID).is_none());
    assert!(req.headers().get(X_USER_ROLE).is_none());
}

// Header injection: validated claims → correct downstream headers

#[test]
fn inject_sets_x_user_id_from_sub() {
    let sub = Uuid::new_v4();
    let mut req = make_request(&[]);
    inject_identity_headers(&mut req, &claims(sub, Some("user"))).unwrap();
    assert_eq!(
        req.headers().get(X_USER_ID).unwrap().to_str().unwrap(),
        sub.to_string()
    );
}

#[test]
fn inject_sets_x_user_role_when_present() {
    let mut req = make_request(&[]);
    inject_identity_headers(&mut req, &claims(Uuid::new_v4(), Some("admin"))).unwrap();
    assert_eq!(
        req.headers().get(X_USER_ROLE).unwrap().to_str().unwrap(),
        "admin"
    );
}

// OWASP Info Disclosure: absent role must not produce empty header downstream

#[test]
fn inject_omits_x_user_role_when_none() {
    let mut req = make_request(&[]);
    inject_identity_headers(&mut req, &claims(Uuid::new_v4(), None)).unwrap();
    assert!(req.headers().get(X_USER_ROLE).is_none());
}

// OWASP A01 Privilege Escalation: inject always overwrites, never merges

#[test]
fn inject_overwrites_residual_role_with_real_role() {
    let mut req = make_request(&[(X_USER_ROLE, "admin")]);
    inject_identity_headers(&mut req, &claims(Uuid::new_v4(), Some("user"))).unwrap();
    assert_eq!(
        req.headers().get(X_USER_ROLE).unwrap().to_str().unwrap(),
        "user"
    );
}

#[test]
fn inject_overwrites_residual_user_id_with_real_sub() {
    let real_sub = Uuid::new_v4();
    let mut req = make_request(&[(X_USER_ID, "00000000-0000-0000-0000-000000000000")]);
    inject_identity_headers(&mut req, &claims(real_sub, None)).unwrap();
    assert_eq!(
        req.headers().get(X_USER_ID).unwrap().to_str().unwrap(),
        real_sub.to_string()
    );
}
