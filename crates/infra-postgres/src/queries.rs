pub mod users {
    pub const UPSERT: &str = include_str!("sql/users_upsert.sql");
    pub const UPDATE_STATUS_ACTIVE: &str = include_str!("sql/users_update_status_active.sql");
    pub const SELECT_WITH_SESSION: &str = include_str!("sql/users_select_with_session.sql");
    pub const SELECT_WITH_SESSION_BY_ID: &str =
        include_str!("sql/users_select_with_session_by_id.sql");
    pub const SELECT_ACTIVE_WITH_CREDENTIALS: &str =
        include_str!("sql/users_select_active_with_credentials.sql");
    pub const LOCK_BY_ID: &str = include_str!("sql/users_lock_by_id.sql");
}

pub mod credentials {
    pub const INSERT: &str = include_str!("sql/credentials_insert.sql");
    pub const INSERT_OWNED_ACTIVE: &str = include_str!("sql/credentials_insert_owned_active.sql");
    pub const UPDATE_COUNTER: &str = include_str!("sql/credentials_update_counter.sql");
    pub const SELECT_BY_USER: &str = include_str!("sql/credentials_select_by_user.sql");
    pub const EXISTS_COUNT_BY_USER: &str = include_str!("sql/credentials_exists_count_by_user.sql");
    pub const DELETE_BY_ID_AND_USER: &str =
        include_str!("sql/credentials_delete_by_id_and_user.sql");
}

pub mod webauthn_sessions {
    pub const INSERT: &str = include_str!("sql/webauthn_sessions_insert.sql");
    pub const DELETE_BY_ID: &str = include_str!("sql/webauthn_sessions_delete_by_id.sql");
    pub const DELETE_EXPIRED: &str = include_str!("sql/webauthn_sessions_delete_expired.sql");
}