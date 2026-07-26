//! `WebAuthnConfig`/`Webauthn` construction doesn't fit cleanly into either
//! infra crate (touches neither postgres nor redis) and `domain_auth::AuthService`
//! just takes a ready-built `Webauthn` — so it's wired here in the bin crate.
//! Takes `rp_id`/`rp_origin` as plain params (not `http::OriginConfig`
//! directly) to avoid pulling an `http` dependency into this decision.
use std::env;

use url::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder};

pub struct WebAuthnConfig {
    pub rp_name: Box<str>,
}

impl WebAuthnConfig {
    pub fn from_env() -> Self {
        let rp_name = env::var("WEBAUTHN_RP_NAME").unwrap().into_boxed_str();
        Self { rp_name }
    }

    pub fn create_webauthn(&self, rp_id: &str, rp_origin: &Url) -> Webauthn {
        let builder = WebauthnBuilder::new(rp_id, rp_origin).unwrap();
        builder.rp_name(&self.rp_name).build().unwrap()
    }
}
