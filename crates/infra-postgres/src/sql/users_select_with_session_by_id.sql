SELECT
    u.id, u.username, u.role, u.status,
    u.created_at, u.updated_at, u.is_active,
    ws.id as session_id, ws.user_id, ws.data, ws.purpose,
    ws.created_at as session_created_at, ws.expires_at
FROM users u
INNER JOIN webauthn_sessions ws ON u.id = ws.user_id
WHERE u.id = $1 AND ws.id = $2 AND ws.purpose = $3 AND ws.expires_at > now();