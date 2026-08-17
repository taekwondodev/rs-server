INSERT INTO recovery_codes (user_id, position, salt, hash, used)
VALUES ($1, $2, $3, $4, FALSE);
