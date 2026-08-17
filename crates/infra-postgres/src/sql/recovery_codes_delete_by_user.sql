-- Replace the user's whole batch: delete any existing codes then insert the
-- new ones. Called inside a transaction by `replace_recovery_batch`, so the
-- delete + insert + state upsert are atomic.
DELETE FROM recovery_codes WHERE user_id = $1;
