# DomainError as the sole port error type; boundary conversion duplicated per crate

`domain_auth::DomainError` (thiserror) is the only error type ports return. Infra crate method
bodies use an inner `anyhow::Result` so infra errors (`tokio_postgres::Error`, `redis::RedisError`,
`rs_repository_utils::RepositoryError`, etc.) auto-convert via anyhow's blanket `From`, then
exactly one boundary-conversion fn per crate (`classify_repo_error` in both
`infra-postgres/src/repo.rs` and `infra-jwt/src/service.rs`) runs per public trait method, not per
call site — downcasting to `RepositoryError` to map `CircuitBreakerOpen` → `ServiceUnavailable`
and `InvalidQuery` → `BadRequest`, with everything else falling through to `DomainError::Internal`.
The two copies are intentionally duplicated, not shared: `infra-postgres`/`infra-jwt` never depend
on each other, and centralizing the fn in `domain-auth` would leak infra vocabulary (circuit
breakers, connection pools) into the zero-infra-deps domain crate — a stronger coupling than the
`HealthIndicator` exception in ADR-0001. `http::HttpError` wraps `DomainError` and is the only
place `IntoResponse` for an error exists.
