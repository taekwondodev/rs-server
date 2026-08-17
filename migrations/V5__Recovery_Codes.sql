-- Account recovery via recovery codes.
--
-- Two tables:
--   * recovery_codes  — the per-position salted hashes of a user's recovery-code
--                       batch. The plaintext is shown once at generation and
--                       never stored. Each position is single-use.
--   * recovery_state   — per-user anti-brute-force state and the rotation
--                       cooldown. Lives in Postgres (not Redis) so a server
--                       restart cannot silently reset the protection.

CREATE TABLE recovery_codes (
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    position   INT         NOT NULL,
    salt       BYTEA       NOT NULL,
    hash       BYTEA       NOT NULL,
    used       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, position)
);

CREATE INDEX idx_recovery_codes_user_id ON recovery_codes(user_id);

CREATE TABLE recovery_state (
    user_id         UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    attempts        INT         NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ
);

-- The recovery flow re-uses the registration ceremony mechanics but is a
-- distinct meaning: a user recovering an account after losing every
-- authenticator. Keeping it separate keeps audit and metrics honest.
ALTER TABLE webauthn_sessions DROP CONSTRAINT webauthn_sessions_purpose_check;
ALTER TABLE webauthn_sessions
    ADD CONSTRAINT webauthn_sessions_purpose_check
    CHECK (purpose IN ('registration', 'login', 'credential_add', 'recovery'));
