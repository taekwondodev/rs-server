-- Multiple passkeys per user:
--   * human-readable label for each credential (nullable until the client
--     supplies one at finish)
--   * new webauthn_sessions purpose for the authenticated add-credential
--     ceremony, kept distinct from 'registration' so audit/metrics can tell
--     first registration apart from adding a passkey to an active account
ALTER TABLE credentials ADD COLUMN name TEXT;

ALTER TABLE webauthn_sessions DROP CONSTRAINT webauthn_sessions_purpose_check;
ALTER TABLE webauthn_sessions
    ADD CONSTRAINT webauthn_sessions_purpose_check
    CHECK (purpose IN ('registration', 'login', 'credential_add'));

-- Repair the V2 trigger: `NEW.last_used_at = NOW;` assigned the uninvoked
-- function object, which raises at runtime the first time a credential's
-- counter is updated on login. The parenthesised call is correct in both
-- cases (if `NOW` somehow resolved, `NOW()` behaves identically).
CREATE OR REPLACE FUNCTION update_last_used()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_used_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;