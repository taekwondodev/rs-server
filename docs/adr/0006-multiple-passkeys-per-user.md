# Multiple passkeys per user, managed by the account owner

A username can hold many WebAuthn credentials. Login already accepted
`Vec<Passkey>` (the allowCredentials list), but there was no way to get a
second passkey onto an account: `create_user` refused re-registration for an
`active` user with `Conflict`, and the register ceremony never passed
`excludeCredentials`. This ADR records the decisions that closed the gap.

## Decisions

1. **Add/list/remove are authenticated operations, scoped by the Bearer
   access token.** Identity comes from the claims (`sub`), never from the
   request body — the add/finish DTO deliberately has no username field, and
   the remove route takes only the credential id in the path. This is the
   standard "add a device" pattern (Apple/Google) and closes the account
   takeover hole that a username-only re-registration would open.

2. **New dedicated endpoints** (`/auth/credentials/begin|finish`,
   `GET /auth/credentials`, `DELETE /auth/credentials/{id}`) instead of
   reusing `/auth/register/*`: the register contract (username + role in the
   body, unauthenticated) is materially different from an authenticated
   management operation, and mixing them would pollute both the DTOs and the
   audit trail.

3. **`start_passkey_registration` always receives the user's existing
   credential ids as `excludeCredentials`** — in the add flow, the resumed
   registration flow, and (trivially, as an empty list) the fresh flow. This
   prevents enrolling the same authenticator twice, which would otherwise
   dead-end in a primary-key violation on `credentials.id`.

4. **Removing the last remaining credential is refused with `Conflict`**
   (409). An `active` user with zero credentials is a permanent dead-end:
   login requires a credential, and registration refuses existing users. The
   guard lives in the repository inside a transaction that locks the user
   row first, so two concurrent removals cannot both pass the count check
   and delete down to zero.

5. **Session purpose extended with `credential_add`** (V4 migration widens
   the `webauthn_sessions.purpose` CHECK). The add ceremony is a WebAuthn
   registration in mechanics but an authenticated management action in
   meaning; distinguishing them keeps audit events and metrics honest.

6. **Credentials get an optional human-readable `name`** (`credentials.name
   TEXT`, supplied at finish and never required). With multiple passkeys, a
   bare id is useless when the user needs to pick which one to revoke.

7. **Removing a passkey does not revoke active sessions.** Sessions are
   independent JWT grants (ADR-0003); passkey removal governs future
   authentication. No new `revoke_by_user` path was added on the JWT side.

8. **No cap on credentials per user.** The add flow is authenticated, so
   abuse requires a stolen token; a limit would add code without addressing
   a real threat.

## Migration

`V4__Credential_Management.sql`: adds `credentials.name`, widens the purpose
CHECK, and repairs the V2 `update_last_used` trigger (which assigned `NOW`
without calling it — a runtime error on the first credential-counter update
during login).