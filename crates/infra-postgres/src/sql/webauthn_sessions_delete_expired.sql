DELETE FROM webauthn_sessions WHERE expires_at < now();
