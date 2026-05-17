pub mod session {
    pub fn key(jti: &str) -> String {
        format!("session:{}", jti)
    }

    pub fn family_key(family_id: &str) -> String {
        format!("family:{}", family_id)
    }
}
