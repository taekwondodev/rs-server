SELECT
    EXISTS (SELECT 1 FROM credentials WHERE id = $1 AND user_id = $2) AS owned,
    (SELECT COUNT(*) FROM credentials WHERE user_id = $2) AS remaining;