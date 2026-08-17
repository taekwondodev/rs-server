SELECT id, username, role, status, created_at, updated_at, is_active
FROM users
WHERE username = $1 AND status = 'active';
