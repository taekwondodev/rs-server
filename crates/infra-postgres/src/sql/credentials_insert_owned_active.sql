-- Add-credential ceremony only: refuses to store a credential for a user
-- that is missing or no longer active (defense-in-depth on top of the
-- access-token check — the token may outlive a deactivation by its TTL).
INSERT INTO credentials (id, user_id, passkey, name)
SELECT $1, u.id, $3, $4
FROM users u
WHERE u.id = $2 AND u.status = 'active';