# Account recovery via recovery codes (lost all authenticators)

A WebAuthn passkey's private key lives in a secure element and can never be
extracted or backed up. If a user loses every registered authenticator they are
permanently locked out: login needs a credential, and registration refuses an
`active` user (ADR-0006). This ADR records the decision to add a trusted,
offline-saveable fallback.

## Decisions

1. **Recovery codes, not an exportable FIDO credential.** A "saved FIDO
   credential" is a contradiction — passkeys are non-extractable by design. The
   fallback is the industry-standard recovery-code pattern (Google/Microsoft/
   GitHub): a batch of high-entropy single-use codes the user saves offline.

2. **Batch of 10 codes × 16 unambiguous characters**, generated with a CSPRNG,
   shown exactly once, stored only as **per-code salted SHA-256 hashes**. A
   fast hash is acceptable because the codes are random high entropy (~2^90);
   the salt defeats rainbow tables and cross-user/cross-position oracles.

3. **Single-use consumption.** Verifying a code marks exactly that position
   consumed. In a successful recovery, the **whole remaining batch is
   invalidated** (deleted), so a recovered account can no longer be
   re-recovered with an old code.

4. **Anti-brute-force lockout lives in Postgres, not Redis** (ADR-0003 uses
   Redis for sessions, but a server restart must not silently reset the
   recovery protection). After **5 consecutive failures** the recovery path
   locks with a cooldown deadline. It is **recovery-path only** — normal
   passkey login is unaffected.

5. **Generate and rotate are authenticated operations**, identity from the
   access-token claims (never the request body). Rotation enforces a **24h
   cooldown** and invalidates the previous batch; generation (first setup) has
   no cooldown. Codes are **opt-in but promoted** at first registration and via
   `/auth/credentials/*`.

6. **The recovery flow reuses the registration ceremony mechanics** with a new
   `webauthn_sessions.purpose` value `recovery`. It is the **one flow where
   identity is not a passkey or token** — the user presents username + code.
   The `recovery` session permits *only* enrolling a fresh passkey; it does not
   mint tokens directly. After re-enrollment the user logs in normally.

7. **Failed/locked recovery returns a single generic `Unauthorized`** — no
   oracle leaks whether the username, code, batch, or lockout condition fired.

8. **Audit**: `RecoveryCodeGenerated`, `RecoveryCodeUsed` (high priority — a
   no-hardware access), `RecoveryFailed`, all on the existing `SecurityEvent`
   tracing path.

## Session revocation: a deliberate narrowing

The original spec (grilling Q3) said "consuming a code revokes all active
sessions". The implementation **invalidates the batch but does not revoke JWT
sessions**, because ADR-0006 point 7 already establishes that removing a
passkey does not revoke active sessions, and `JwtService` has no revoke-all-
for-user primitive. A recovery re-enrolls a passkey — the same shape as
passkey management — so it follows the same principle. The lockout state lives
in Postgres precisely so a takeover attempt via recovery codes is throttled
independently of any session state.

## Atomic completion

Consuming a code is deferred until the recovery **finishes**, not when it
begins: `verify_recovery_code` (in `/begin`) only validates the code and
updates the lockout counter; it does not consume. `finish_recovery` calls
`complete_recovery`, which in **one transaction** enrolls the fresh passkey,
deletes every remaining code in the batch, and resets `recovery_state` (lockout
+ rotation cooldown). A failed attestation therefore does not burn a code, and
the user can generate a fresh batch after a successful recovery.

## Migration

`V5__Recovery_Codes.sql`: adds `recovery_codes` (per-user, per-position salted
hashes) and `recovery_state` (per-user lockout + rotation cooldown), and widens
`webauthn_sessions.purpose` to accept `recovery`.
