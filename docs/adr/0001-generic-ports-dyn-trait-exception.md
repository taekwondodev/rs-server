# Generic ports, single dyn Trait exception for health checks

`AuthService<R: AuthRepository, J: JwtService>` and `http::AppState<R, J>` are monomorphized
generics for zero-cost static dispatch; adapters are swapped at compile time via the workspace
boundary, so `Box`/`Arc<dyn Trait>` isn't needed for that flexibility. The one deliberate exception
is `rs_repository_utils::HealthIndicator` (`name()` + `check()`), implemented on `Repository`/`Jwt`
alongside their real ports and aggregated via `check_all(&[Arc<dyn HealthIndicator>])` in
`http::AppState` — the set of checkable resources (postgres, redis, tomorrow a payment gateway or
queue) is open-ended in a way `AuthService<R, J>`'s fixed generic pair can't express. `check_db`/
`check_redis` used to live directly on `AuthRepository`/`JwtService` as a leftover from the
pre-workspace monolith, forcing every new bounded context's repository port to either duplicate
health-check methods unrelated to its business rules, or leave `/healthz` permanently auth-only.

## Consequences

To add a new indicator: `impl HealthIndicator` on the adapter, push it into the
`health_indicators` vec built in `rs-server`'s `main.rs` — no `domain-*` crate needs to change.
Surfacing it over HTTP means adding a field to `http::dto::response::HealthChecks` by hand — that
wire type is intentionally a fixed struct, not `HealthReport`'s open map (see the doc comment on
`HealthResponse::from_report`).
