use std::env;

#[derive(Debug)]
pub struct JwtConfig {
    secret_key: Box<str>,
    issuer: Box<str>,
    audience: Box<str>,
}

impl JwtConfig {
    pub fn from_env() -> Self {
        let secret_key = env::var("JWT_SECRET_KEY").unwrap().into_boxed_str();

        if secret_key.len() < 32 {
            panic!("JWT_SECRET_KEY must be at least 32 characters");
        }

        Self {
            secret_key,
            issuer: env::var("JWT_ISSUER").expect("JWT_ISSUER must be set").into_boxed_str(),
            audience: env::var("JWT_AUDIENCE").expect("JWT_AUDIENCE must be set").into_boxed_str(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }
}
