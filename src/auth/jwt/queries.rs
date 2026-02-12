pub mod blacklist {
    pub fn key(jti: &str) -> String {
        format!("blacklist:{}", jti)
    }
}
