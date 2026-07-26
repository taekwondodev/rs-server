# Rust Backend Template

A production-ready Rust backend template featuring Type-Driven Design, hexagonal architecture, and comprehensive observability. Built with Axum, PostgreSQL, and Redis.

## Template Philosophy

This template embodies **Type-Driven Design (TyDD)** principles:
- Encode business logic into the type system
- Make invalid states unrepresentable
- Leverage Rust's ownership model for zero-cost abstractions
- Prefer compile-time guarantees over runtime checks

## Features

### Core Architecture
- **Hexagonal / Ports & Adapters**: Cargo workspace, one crate per architectural role — business logic never depends on a specific database, cache, or web framework
- **Bounded-Context Ready**: Each feature is its own set of crates (`domain-<name>` + adapters), sharing only a minimal identifier kernel — adding a second feature never means reaching into the first one's internals
- **Type-Driven Design**: NewTypes, strong typing, and compile-time safety
- **Generic Ports, Zero-Cost Dispatch**: Repository/service traits are generic bounds, monomorphized at the composition root — no vtable indirection on the request path. The one deliberate exception is health checks: an open-ended, heterogeneous set of dependencies genuinely needs dynamic dispatch, so that's the single `dyn Trait` in the workspace
- **Async First**: Built on Tokio runtime with Axum web framework

### Resilience & Reliability
- **Circuit Breaker Pattern**: Automatic failure detection and recovery for external dependencies
- **Exponential Backoff**: Intelligent retry mechanism for transient failures
- **Health Checks**: Comprehensive endpoint for monitoring service and dependency health

### Database & Caching
- **PostgreSQL**: Type-safe queries with deadpool connection pooling
- **Redis**: JWT session whitelist with token family tracking — self-cleaning via TTL, no background jobs
- **Query Builders**: Optional dynamic SQL builders for complex operations
- **Connection Pooling**: Efficient resource management with deadpool

### Observability (Day 0)
- **Structured Tracing**: `tracing` + `tracing-subscriber` with JSON output (NDJSON) for log aggregators
- **Prometheus Metrics**: Built-in metrics collection with custom histograms
- **Request Tracing**: Automatic HTTP request/response logging with method, path, status, and latency
- **Security Audit Logging**: Structured security events for auth success/failure, token rejection, and privilege escalation attempts
- **Error Context**: Rich error propagation with full context preservation

### Developer Experience
- **Swagger UI**: Interactive API documentation with OpenAPI 3.0 (dev-only, `--features openapi`; excluded from default/prod builds)
- **Type-Safe Configuration**: Environment-based config with validation
- **Hot Reload Ready**: Fast iteration with cargo-watch
- **Comprehensive Tests**: Service layer and domain type testing strategy

### Security
- **CORS Configuration**: Flexible cross-origin setup for multiple environments
- **Input Validation**: Max length, charset allowlist (`[a-zA-Z0-9_-]`), and `deny_unknown_fields` on all request DTOs — unknown JSON keys rejected with 400
- **Body Size Limit**: 16 KB cap on all requests — prevents memory exhaustion from oversized payloads
- **Information Hiding**: Internal error details (DB errors, JWT internals, stack context) are logged server-side only — HTTP responses return fixed generic strings
- **PII-Free Logs**: Usernames and other personal identifiers are never written to logs — only the subject UUID (`user_id`) is retained for non-repudiation
- **Secret Management**: HKDF derives independent access and refresh keys from a single `JWT_SECRET_KEY` — no separate secrets to rotate
- **RFC 9068 Compliance**: Access tokens carry `iss` and `aud` claims, validated on every request to prevent cross-service relay attacks
- **Token Family Reuse Detection**: Replaying a rotated refresh token immediately revokes the entire session chain
- **Security Audit Trail**: Tamper-evident structured log of all authentication and authorization events

## Architecture

Cargo workspace, one crate per architectural role. Dependency direction is enforced by the compiler, not by convention:

```
crates/domain-shared    shared-kernel identifiers only (e.g. UserId) — no business logic
crates/domain-auth      auth bounded context: entities, ports, AuthService, DomainError
crates/infra-postgres   AuthRepository implementation (Postgres)
crates/infra-jwt        JwtService implementation (JWT crypto + Redis sessions)
crates/http             axum adapter: generic AppState<R, J>, handlers, wire DTOs
rs-server (bin)         composition root — the only crate that picks concrete types
```

`domain-*` crates depend on nothing infra- or HTTP-flavored — no `axum`, `tokio-postgres`, `redis`,
or `jsonwebtoken` in sight. `infra-*`/`http` each depend on their one domain crate and nothing else
in the workspace (health-checking comes from the `rs-repository-utils` library dependency, not a
local crate). Adding a second feature (payments, notifications, ...) means adding a parallel
`domain-<name>`/`infra-<name>` crate set, not editing `domain-auth` — see
[`.claude/CLAUDE.md`](.claude/CLAUDE.md) for the full walkthrough.

## Quick Start

### Prerequisites

- **Docker & Docker Compose** (for infrastructure)
- **Rust 1.85+** (for development)
- **Git**

### 1. Configure Environment

```bash
cp .env.example .env
# Edit .env with your settings
```

**⚠️ SECURITY WARNING**: The template uses default passwords (`changeme_superuser_password`, `changeme_app_password` and `changeme_redis_password`) that **MUST** be changed before deploying to any environment. Also set `JWT_ISSUER`, `JWT_AUDIENCE`, and generate a strong `JWT_SECRET_KEY` (minimum 32 bytes).

### 2. Start Infrastructure

```bash
docker compose up -d
```

### 3. Change Database Passwords

```bash
# 1. Connect to the PostgreSQL container as superuser
docker exec -it server_postgres psql -U postgres -d server_db

# 2. Change the password for the application role
ALTER ROLE server_app WITH PASSWORD 'your_secure_app_password';

# 3. Exit psql
\q

# 4. Update your .env file with the new password
# Edit .env and change:
POSTGRES_PASSWORD=your_secure_app_password

# 5. Restart the server container to apply the new password
docker compose restart server
```
---

The service will be available at:
- **API**: http://localhost:8080
- **Swagger UI**: http://localhost:8080/swagger-ui (run with `cargo run --features openapi`; not present in default/prod builds)
- **Health Check**: http://localhost:8080/healthz
- **Metrics**: http://localhost:8080/metrics

## Usage Guide

For setup instructions and project adaptation guidance, see [`.claude/CLAUDE.md`](.claude/CLAUDE.md) — loaded automatically by Claude Code.

## Testing

```bash
cargo test --workspace
```

## Monitoring

### Prometheus Metrics

Available at `/metrics`:
- HTTP request duration histograms
- Database pool statistics
- Redis connection health
- Circuit breaker state

### Security Audit Logs

All security events are emitted as structured JSON fields with `security: true` for easy filtering:

| Event | Level | Fields |
|---|---|---|
| Auth success | INFO | `user_id`, `event` |
| Auth failure | WARN | `user_id`, `event`, `reason` |
| Token rejected | WARN | `reason` |
| Unauthorized access | WARN | — |
| Admin access denied | WARN | `user_id` |

Filter in Loki:
```
{job="rs-server"} | json | security="true"
```

Logs are persisted via Docker `json-file` driver (100 MB × 5 files per container).

### Health Checks

Available at `/healthz`:
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "checks": {
    "database": {
      "status": "healthy",
      "message": "Database connection successful",
      "response_time_ms": 5
    },
    "redis": {
      "status": "healthy",
      "message": "Redis connection successful",
      "response_time_ms": 2
    }
  }
}
```

### SonarQube (Optional)

To enable SonarQube analysis:

1. Add GitHub Secrets:
   - `SONAR_TOKEN`: Your SonarCloud token

The workflow automatically configures project key and organization from your repository name.
