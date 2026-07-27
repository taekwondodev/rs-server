# rs-server — Claude Setup Instructions

This file is loaded automatically by Claude Code. Follow it when the developer asks to set up or adapt this template.

---

## Stack

Rust 1.85+ · Axum · PostgreSQL (deadpool) · Redis · WebAuthn passkey · JWT (EdDSA access + HS256 refresh) · Prometheus · Docker Compose

Cargo workspace, hexagonal/ports-and-adapters architecture — see **Workspace Layout** below before touching anything.

---

## Workspace Layout

One crate per architectural role, not one crate for everything. Dependency direction is a hard rule, not a convention — a workspace member depending the wrong way is a bug, not a style nit.

```
crates/domain-shared    shared-kernel identifiers only (currently: UserId). No business rules.
crates/domain-auth      auth bounded context: entities, ports (traits), AuthService, DomainError.
                        Depends on domain-shared only. Zero infra/HTTP deps (no axum, no
                        tokio-postgres, no redis, no jsonwebtoken).
crates/infra-postgres   AuthRepository port implementation (Postgres). Depends on domain-auth.
                        Also implements rs_repository_utils::HealthIndicator for Repository.
crates/infra-jwt        JwtService port implementation (JWT crypto + Redis sessions). Depends on
                        domain-auth. Also implements HealthIndicator for Jwt.
crates/http             axum adapter: generic AppState<R, J>, handlers, wire DTOs, HttpError.
                        Depends on domain-auth — NEVER names infra-postgres::Repository or
                        infra-jwt::Jwt concretely. Only rs-server's main.rs picks concrete types.
rs-server (bin, root)   composition root. Depends on everything. The only crate that monomorphizes
                        AuthService<Repository, Jwt> and wires AppState.
```

Rule of thumb: **`domain-*` crates depend on nothing infra/HTTP-flavored, ever.** `infra-*`/`http`
crates depend on their one `domain-*` crate and nothing else in the workspace (never on each
other). The bin crate is the only place that's allowed to know every concrete type at once.

**Ports stay generic, never `dyn Trait` — with one deliberate exception.** `AuthService<R:
AuthRepository, J: JwtService>` and `http::AppState<R, J>` are monomorphized generics — zero-cost
static dispatch. Don't introduce `Box`/`Arc<dyn Trait>` for "flexibility"; the workspace boundary
already gives you swappable adapters at compile time. `rs_repository_utils::HealthIndicator` is the one
exception, and it's deliberate: see **Health Checks** below for why.

**Errors**: `domain_auth::DomainError` (thiserror) is the only error type ports return. Infra crate
method bodies use an inner `anyhow::Result` so infra errors (`tokio_postgres::Error`,
`redis::RedisError`, etc.) auto-convert via anyhow's blanket `From`, then exactly one
`.map_err(DomainError::Internal)` per public trait method at the boundary — not per call site.
`http::HttpError` wraps `DomainError` and is the only place `IntoResponse` for an error exists.

**Shared kernel**: `domain-shared::UserId` exists so a future bounded context (payments, etc.) can
say "which user" without depending on the whole `domain-auth` crate. Keep `domain-shared` to
identifiers/value objects only — the moment it grows a business rule, it belongs in a specific
domain crate instead.

**Health checks**: `check_db`/`check_redis` used to live directly on `AuthRepository`/`JwtService`
— that was a leftover from the pre-workspace monolith, not a design choice, and it meant every new
bounded context's repository port would either duplicate health-check methods that have nothing to
do with its business rules, or `/healthz` would stay permanently auth-only. Fixed by extracting
`rs_repository_utils::HealthIndicator` (`name()` + `check()`), implemented directly on `Repository`/`Jwt`
alongside their real ports, aggregated via `rs_repository_utils::check_all(&[Arc<dyn HealthIndicator>])` in
`http::AppState`. This is the one legitimate `dyn Trait` in the workspace: the set of checkable
resources is open-ended (today: postgres, redis; tomorrow: a payment gateway, a message queue) in
a way `AuthService<R, J>`'s fixed generic pair can't express. To add a new indicator: `impl
HealthIndicator` on the adapter, push it into the `health_indicators` vec built in `rs-server`'s
`main.rs` — no `domain-*` crate needs to change. Surfacing it over HTTP means adding a field to
`http::dto::response::HealthChecks` by hand (that wire type is intentionally a fixed struct, not
`HealthReport`'s open map — see the doc comment on `HealthResponse::from_report`).

---

## First Setup After `git clone`

### 1. Environment

Copy `.env.example` to `.env`, then fill in every value. These six are not optional — the server panics at startup if missing:

```
JWT_SECRET_KEY   # openssl rand -base64 32
JWT_ISSUER       # https://auth.example.com
JWT_AUDIENCE     # https://api.example.com
URL_BACKEND      # https://your-backend-url
SERVER_PORT      # public port
INTERNAL_PORT    # /healthz + /metrics only
```

Also change the three default passwords (`changeme_*`) before starting Docker.

`INTERNAL_PORT` must stay unpublished in `compose.yaml` — that's what keeps `/healthz`/`/metrics`
off the public internet while still reachable container-to-container (e.g. Prometheus). If you
change `INTERNAL_PORT`, also update the hardcoded target in `prometheus.yml`

### 2. Rename the project

In the root `Cargo.toml` change `name = "rs-server"` to the service name — this only renames the
composition-root binary package. Leave `crates/*` names alone; they describe architectural roles
(`domain-auth`, `infra-postgres`, ...), not the product name.
Set `WEBAUTHN_RP_NAME` in `.env` to match.

### 3. Start infrastructure

```bash
docker compose up -d
```

### 4. Turn on `strict` mode

In the root `Cargo.toml`:

```toml
[features]
default = ["strict"]
strict = ["domain-auth/strict", "infra-postgres/strict", "infra-jwt/strict", "http/strict"]
```

`strict` fans out across every workspace member — it's declared once at the root and each crate's
own `Cargo.toml` re-declares `strict = []` to receive it. Run `cargo build --workspace`. Every
`dead_code` warning that appears is a template utility with no caller yet — handle it in the next
step.

### 5. Delete unused template scaffold

For each warning from step 4, decide: use it or delete it. Don't suppress it. These are the items that commonly have no callers in a fresh project:

| Item | Location |
|---|---|
| `AdminClaims` extractor | `crates/http/src/middleware/auth.rs` |
| `AccessTokenClaims::sub/username/role` | `crates/domain-auth/src/claims.rs` — keep these once you add domain handlers that read the token |

Run `cargo build --workspace` again. Zero warnings means the codebase is clean.

**Note**: `AdminClaims`/`AccessTokenClaims` live in a *library* crate (`http`/`domain-auth`), not a
binary — rustc's dead-code lint doesn't flag unused `pub` items in a library the way it flags them
in a bin. `strict` mode's zero-warning guarantee is real for the binary crate but weaker for these
specific public library items; that's expected, not a regression to chase.

### 5a. Decide: monolith or gateway

**Monolith (default):** remove the gateway scaffold entirely.

1. Delete `crates/http/src/middleware/gateway.rs` and `crates/http/src/middleware/gateway/tests.rs`
2. In `crates/http/src/middleware/mod.rs` remove:
   ```rust
   #[cfg(feature = "gateway")]
   pub(crate) mod gateway;
   ```
3. In `crates/domain-auth/src/security_audit.rs` remove the `GatewayForward` variant (and its
   `#[cfg(feature = "gateway")]` gate) plus its `emit` match arm
4. In `crates/http/src/router.rs` remove the `#[cfg(feature = "gateway")]` merge block that adds
   the catch-all proxy route
5. Remove `gateway = [...]` from three `[features]` blocks: root `Cargo.toml`,
   `crates/http/Cargo.toml`, `crates/domain-auth/Cargo.toml`

**Gateway (microservice):** keep everything, then replace `proxy_stub` with a real proxy handler
in `crates/http/src/middleware/gateway.rs` and wire your downstream routes inside the
`#[cfg(feature = "gateway")]` block in `crates/http/src/router.rs`.

### 6. Add your first bounded context

Auth is one bounded context (`domain-auth` + `infra-postgres` + `infra-jwt` + the auth slice of
`http`). A second feature (payments, notifications, whatever) is **not** a module inside
`domain-auth` — it's its own set of crates, following the same shape:

```
crates/domain-<name>/          mirrors domain-auth's shape
├── src/model.rs                entities
├── src/traits.rs                ports (repository/gateway traits)
├── src/service.rs               <Name>Service<R, ...> — generic, static dispatch
├── src/dto.rs                    plain result types (no axum/utoipa)
├── src/commands.rs               plain input types
└── src/error.rs                  its own DomainError-equivalent (or share the pattern, not the type)
```

Rules for the new context:
- `crates/domain-<name>` depends on `domain-shared` only — **never** on `domain-auth`. If it needs
  to reference a user, use `domain_shared::UserId`, not `domain_auth::User`.
- New infra needs (e.g. a payment gateway SDK) become their own `crates/infra-<tech>` crate
  implementing `domain-<name>`'s ports — same boundary-conversion pattern as `infra-postgres`
  (`anyhow` internally, one `DomainError`-equivalent conversion per public trait method).
- Extend `crates/http` with a new handler/dto module for the context (mirrors `handler.rs`/`dto/`),
  merge its routes in `router.rs`. If the two contexts need genuinely different HTTP-layer
  concerns, a second `http-<name>` crate is also fine — `http` is a technology adapter, not a
  business boundary, so it's your call based on how much actually diverges.
- Wire the new service into `rs-server`'s `main.rs` (composition root) alongside `AuthService`.
  Combining two independently-generic services into one axum state typically means either axum's
  `FromRef` on a combined state struct, or `.merge()`-ing two independently-`with_state`'d routers.
- If the new infra adapter has something worth health-checking (a payment gateway API, a queue),
  `impl rs_repository_utils::HealthIndicator` on it and add it to the `health_indicators` vec in `main.rs` —
  don't add a `check_*` method to the new bounded context's own repository port (see **Health
  Checks** above for why that's the wrong place for it).

---

## CORS

CORS is browser-only enforcement — native and mobile clients ignore it entirely.

- Config: `crates/http/src/config.rs` (`OriginConfig`, `create_cors_layer`)
- Applied: `src/main.rs` (composition root)

**If the backend is consumed only by mobile or non-browser clients**, remove:
1. `cors_layer` from `src/main.rs`
2. `OriginConfig`/`create_cors_layer` from `crates/http/src/config.rs`
3. `ORIGIN_FRONTEND` env var from `.env` and `.env.example`
4. The `origin_config` construction in `src/main.rs`, and thread `rp_id`/`rp_origin` for WebAuthn
   from another source (see `src/webauthn.rs` — it already takes them as plain `&str`/`&Url`
   params, not `OriginConfig` directly, so it doesn't need to change)

`URL_BACKEND` must stay — it is also used by WebAuthn as `rp_id`.

---

## Auth System

The auth module is complete. Read before touching.

- Access token: EdDSA, stateless, 5 min. Never add a Redis lookup for it.
- Refresh token: HS256, stateful, 24 h. Always validated against Redis whitelist.
- Redis: `session:{jti} → "1"` + `family:{family_id} → jti`, both with TTL. Self-cleaning.
- Reuse detection: a valid JWT whose `session:{jti}` is missing in Redis means replay after rotation → `revoke_family` kills the chain.
- HKDF: one `JWT_SECRET_KEY` derives two independent keys internally. Don't split it into two env variables.

Claims are split across two crates on purpose — don't merge them back:
- `crates/domain-auth/src/claims.rs`: `AccessTokenClaims`/`RefreshTokenClaims` — plain data
  (fields, `new()`, getters). To extend token claims, add fields here and update `new()`.
- `crates/infra-jwt/src/crypto.rs`: `JwtCrypto` — all encode/decode/HKDF/PEM logic. `to_token`/
  `validate` are **not** methods on the claim structs; they're inherent methods on `JwtCrypto`
  operating on the claim structs' public fields. Adding a field to a claims struct in
  `domain-auth` never requires touching `infra-jwt`'s crypto code unless the new field changes
  validation rules (e.g. a new required claim to check on decode).
