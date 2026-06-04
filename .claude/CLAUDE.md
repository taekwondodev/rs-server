# rs-server — Claude Setup Instructions

This file is loaded automatically by Claude Code. Follow it when the developer asks to set up or adapt this template.

---

## Stack

Rust 1.85+ · Axum · PostgreSQL (deadpool) · Redis · WebAuthn passkey · JWT (EdDSA access + HS256 refresh) · Prometheus · Docker Compose

---

## First Setup After `git clone`

### 1. Environment

Copy `.env.example` to `.env`, then fill in every value. These four are not optional — the server panics at startup if missing:

```
JWT_SECRET_KEY   # openssl rand -base64 32
JWT_ISSUER       # https://auth.example.com
JWT_AUDIENCE     # https://api.example.com
URL_BACKEND      # https://your-backend-url
```

Also change the three default passwords (`changeme_*`) before starting Docker.

### 2. Rename the project

In `Cargo.toml` change `name = "rs-server"` to the service name.
Set `WEBAUTHN_RP_NAME` in `.env` to match.

### 3. Start infrastructure

```bash
docker compose up -d
```

### 4. Turn on `strict` mode

In `Cargo.toml`:

```toml
[features]
default = ["strict"]
strict = []
```

Run `cargo build`. Every `dead_code` warning that appears is a template utility with no caller yet — handle them in the next step.

### 5. Delete unused template scaffold

For each warning from step 4, decide: use it or delete it. Don't suppress it. These are the items that commonly have no callers in a fresh project:

| Item | Location |
|---|---|
| `AdminClaims` extractor | `src/app/middleware/auth.rs` |
| `AccessTokenClaims::sub/username/role` | `src/auth/jwt/claims.rs` — keep these once you add domain handlers that read the token |

Run `cargo build` again. Zero warnings means the codebase is clean.

### 5a. Decide: monolith or gateway

**Monolith (default):** remove the gateway scaffold entirely.

1. Delete `src/app/middleware/gateway.rs`
2. Delete `src/app/middleware/tests/` (entire directory)
3. In `src/app/middleware/mod.rs` remove:
   ```rust
   #[cfg(feature = "gateway")]
   pub(crate) mod gateway;

   #[cfg(test)]
   mod tests;
   ```
4. In `src/app/middleware/security_audit.rs` remove the two `GatewayForward` lines (variant + `emit` arm)
5. In `src/app/router.rs` revert to consuming `state` directly and remove the gateway block:
   ```rust
   // change back
   .with_state(state)   // was state.clone()

   // remove entirely
   #[cfg(feature = "gateway")]
   let router = router.merge(...);
   ```
6. In `Cargo.toml` remove `gateway = []` from `[features]`

**Gateway (microservice):** keep everything, then replace `proxy_stub` with a real proxy handler and wire your downstream routes inside the `#[cfg(feature = "gateway")]` block in `router.rs`.

### 6. Add your first domain module

Create `src/<domain>/` with this layout:

```
src/<domain>/
├── mod.rs
├── handler.rs      # HTTP only — parse, delegate, respond
├── service.rs      # business logic
├── repository/
│   ├── mod.rs
│   ├── impl.rs
│   └── queries.rs  # private SQL
├── model.rs
├── dto.rs
└── traits.rs
```

Wire it into `src/app/router.rs` and `src/app/state.rs`.

---

## CORS

CORS is browser-only enforcement — native and mobile clients ignore it entirely.

- Config: `src/config/origin.rs` (`create_cors_layer`)
- Applied: `src/main.rs`

**If the backend is consumed only by mobile or non-browser clients**, remove:
1. `cors_layer` from `src/main.rs`
2. `src/config/origin.rs` (entire file)
3. `ORIGIN_FRONTEND` env var from `.env` and `.env.example`
4. `OriginConfig` from `src/app/state.rs` / `src/config/mod.rs`

`URL_BACKEND` must stay — it is also used by WebAuthn as `rp_id`.

---

## Auth System

The auth module is complete. Read before touching.

- Access token: EdDSA, stateless, 5 min. Never add a Redis lookup for it.
- Refresh token: HS256, stateful, 24 h. Always validated against Redis whitelist.
- Redis: `session:{jti} → "1"` + `family:{family_id} → jti`, both with TTL. Self-cleaning.
- Reuse detection: a valid JWT whose `session:{jti}` is missing in Redis means replay after rotation → `revoke_family` kills the chain.
- HKDF: one `JWT_SECRET_KEY` derives two independent keys internally. Don't split it into two env vars.

To extend token claims add fields to `AccessTokenClaims` or `RefreshTokenClaims` in `src/auth/jwt/claims.rs` and update their `new()`.
