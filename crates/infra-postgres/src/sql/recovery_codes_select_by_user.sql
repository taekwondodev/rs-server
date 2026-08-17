SELECT position, salt, hash, used
FROM recovery_codes
WHERE user_id = $1
ORDER BY position;
