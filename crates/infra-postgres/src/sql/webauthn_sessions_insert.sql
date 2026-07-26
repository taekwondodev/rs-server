INSERT INTO webauthn_sessions (user_id, data, purpose, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING id;
