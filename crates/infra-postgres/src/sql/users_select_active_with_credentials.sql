SELECT
    u.id, u.username, u.role, u.status,
    u.created_at, u.updated_at, u.is_active,
    c.passkey
FROM users u
INNER JOIN credentials c ON u.id = c.user_id
WHERE u.username = $1 AND u.status = 'active';
