SELECT attempts, locked_until, last_rotated_at
FROM recovery_state
WHERE user_id = $1;
