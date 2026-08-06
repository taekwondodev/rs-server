# Auth token strategy: stateless access token, stateful refresh token with family-based reuse detection

Access tokens are EdDSA-signed, stateless, 5 minute TTL — no Redis lookup, verified by signature
alone, kept short-lived to bound the blast radius of a leaked token without paying a Redis
round-trip on every request. Refresh tokens are HS256-signed, stateful, 24 hour TTL, always
validated against a Redis session whitelist so they can be revoked before expiry. Sessions are
grouped into rotation families (`family:{family_id} → jti`); a refresh token presented after its
session has already been rotated out (`session:{jti}` missing in Redis) is treated as replay and
triggers `revoke_family`, killing the entire chain rather than just the one token.
