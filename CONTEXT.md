# rs-server

Authentication service: WebAuthn passkey + JWT (EdDSA access, HS256 refresh) auth, built as a hexagonal-architecture Cargo workspace.

## Language

**UserId**:
Cross-context identifier for "which user", living in the `domain-shared` crate so other bounded contexts can reference a user without depending on `domain-auth`. See ADR-0001/`domain-shared`'s scope rule in `CLAUDE.md`.
_Avoid_: User (that's `domain-auth`'s entity, not the shared-kernel identifier)

**Session**:
A single active refresh-token grant, tracked in Redis as `session:{jti} → "1"` with a TTL; deleting the key invalidates that specific token.
_Avoid_: token, JTI (JTI is the technical field a session is keyed by, not the domain concept)

**Family**:
The rotation chain of refresh tokens issued from one login, tracked in Redis as `family:{family_id} → jti`. Reuse of a token outside its family's current head signals replay and triggers revocation of the whole chain. See ADR-0003.
_Avoid_: chain, lineage

**Reuse detection**:
The check that a presented refresh token's `session:{jti}` still exists in Redis; a valid JWT with a missing session means replay after rotation, and triggers `revoke_family`.
_Avoid_: replay check
