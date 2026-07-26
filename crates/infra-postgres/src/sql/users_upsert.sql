INSERT INTO users (username, role)
VALUES ($1, $2)
ON CONFLICT (username) DO UPDATE SET updated_at = users.updated_at
RETURNING *, (xmax::text::bigint <> 0) AS conflicted;
