-- Upsert the per-user lockout + rotation-cooldown state.
-- attempts and locked_until are always overwritten by the caller. last_rotated_at
-- is preserved when NULL is passed (the lockout path) and updated only when a
-- real timestamp is supplied (the batch-replacement/rotation path), so the
-- cooldown window is not silently reset by a lockout write.
INSERT INTO recovery_state (user_id, attempts, locked_until, last_rotated_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id) DO UPDATE SET
    attempts = EXCLUDED.attempts,
    locked_until = EXCLUDED.locked_until,
    last_rotated_at = COALESCE(EXCLUDED.last_rotated_at, recovery_state.last_rotated_at);
