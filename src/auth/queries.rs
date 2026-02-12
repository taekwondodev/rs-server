pub mod users {
    pub const SELECT_BY_USERNAME: &str = "SELECT * FROM users WHERE username = $1";

    pub const INSERT_WITH_ROLE: &str = "INSERT INTO users (username, role)
         VALUES ($1, $2)
         RETURNING *";

    pub const INSERT_WITHOUT_ROLE: &str = "INSERT INTO users (username)
         VALUES ($1)
         RETURNING *";

    pub const UPDATE_STATUS_ACTIVE: &str = "UPDATE users SET status = 'active' WHERE username = $1";

    pub const SELECT_WITH_SESSION: &str = "SELECT u.id, u.username, u.role, u.status,
                u.created_at, u.updated_at, u.is_active,
                ws.id as session_id, ws.user_id, ws.data, ws.purpose,
                ws.created_at as session_created_at, ws.expires_at
         FROM users u
         INNER JOIN webauthn_sessions ws ON u.id = ws.user_id
         WHERE u.username = $1 AND ws.id = $2 AND ws.purpose = $3";

    pub const SELECT_ACTIVE_WITH_CREDENTIALS: &str = "SELECT u.id, u.username, u.role, u.status,
                u.created_at, u.updated_at, u.is_active,
                c.passkey
         FROM users u
         INNER JOIN credentials c ON u.id = c.user_id
         WHERE u.username = $1 AND u.status = 'active'";
}

pub mod credentials {
    pub const INSERT: &str = "INSERT INTO credentials (id, user_id, passkey)
         VALUES ($1, $2, $3)";

    pub const UPDATE_COUNTER: &str = "UPDATE credentials
         SET passkey = jsonb_set(passkey, '{counter}', $1::text::jsonb)
         WHERE id = $2";
}

pub mod webauthn_sessions {
    pub const INSERT: &str = "INSERT INTO webauthn_sessions (user_id, data, purpose, expires_at)
         VALUES ($1, $2, $3, $4)
         RETURNING id";

    pub const DELETE_BY_ID: &str = "DELETE FROM webauthn_sessions WHERE id = $1";
}
