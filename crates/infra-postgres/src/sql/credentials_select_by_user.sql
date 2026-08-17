SELECT id, name, created_at, last_used_at
FROM credentials
WHERE user_id = $1
ORDER BY created_at;