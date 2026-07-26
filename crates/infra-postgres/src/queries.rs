pub mod users {
    pub const UPSERT: &str = include_str!("sql/users_upsert.sql");
    pub const UPDATE_STATUS_ACTIVE: &str = include_str!("sql/users_update_status_active.sql");
    pub const SELECT_WITH_SESSION: &str = include_str!("sql/users_select_with_session.sql");
    pub const SELECT_ACTIVE_WITH_CREDENTIALS: &str =
        include_str!("sql/users_select_active_with_credentials.sql");
}

pub mod credentials {
    pub const INSERT: &str = include_str!("sql/credentials_insert.sql");
    pub const UPDATE_COUNTER: &str = include_str!("sql/credentials_update_counter.sql");
}

pub mod webauthn_sessions {
    pub const INSERT: &str = include_str!("sql/webauthn_sessions_insert.sql");
    pub const DELETE_BY_ID: &str = include_str!("sql/webauthn_sessions_delete_by_id.sql");
}
