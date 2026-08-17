-- Reset the user's recovery state to a clean slate after a successful
-- recovery: no lockout, no rotation cooldown. The user can then generate a
-- fresh batch normally.
DELETE FROM recovery_state WHERE user_id = $1;
