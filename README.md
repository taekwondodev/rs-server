# Rust Backend Template

A production-ready Rust backend template featuring Type-Driven Design, modern async architecture, and comprehensive observability. Built with Axum, PostgreSQL, and Redis.

## Template Philosophy

This template embodies **Type-Driven Design (TyDD)** principles:
- Encode business logic into the type system
- Make invalid states unrepresentable
- Leverage Rust's ownership model for zero-cost abstractions
- Prefer compile-time guarantees over runtime checks

## Features

### Core Architecture
- **Feature-Based Organization**: Code organized by business domain, not technical layers
- **Type-Driven Design**: NewTypes, strong typing, and compile-time safety
- **Clean Separation**: Handler → Service → Repository pattern with strict boundaries
- **Async First**: Built on Tokio runtime with Axum web framework

### Resilience & Reliability
- **Circuit Breaker Pattern**: Automatic failure detection and recovery for external dependencies
- **Exponential Backoff**: Intelligent retry mechanism for transient failures
- **Health Checks**: Comprehensive endpoint for monitoring service and dependency health

### Database & Caching
- **PostgreSQL**: Type-safe queries with prepared statement caching
- **Redis**: Session management and distributed caching
- **Query Builders**: Optional dynamic SQL builders for complex operations
- **Connection Pooling**: Efficient resource management with deadpool

### Observability (Day 0)
- **Structured Tracing**: `tracing` + `tracing-subscriber` for distributed tracing
- **Prometheus Metrics**: Built-in metrics collection with custom histograms
- **Request Tracing**: Automatic HTTP request/response logging
- **Error Context**: Rich error propagation with full context preservation

### Developer Experience
- **Swagger UI**: Interactive API documentation with OpenAPI 3.0
- **Type-Safe Configuration**: Environment-based config with validation
- **Hot Reload Ready**: Fast iteration with cargo-watch
- **Comprehensive Tests**: Service layer and domain type testing strategy

### Security
- **CORS Configuration**: Flexible cross-origin setup for multiple environments
- **Input Validation**: Request validation at the type system level
- **Secure Error Handling**: No information leakage in error responses
- **Secret Management**: Environment-based secret injection

## Quick Start

### Prerequisites

- **Docker & Docker Compose** (for infrastructure)
- **Rust 1.75+** (for development)
- **Git**

### 1. Configure Environment

```bash
cp .env.example .env
# Edit .env with your settings
```

**⚠️ SECURITY WARNING**: The template uses default passwords (`changeme_superuser_password` and `changeme_app_password`) that **MUST** be changed before deploying to any environment.

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
- **Swagger UI**: http://localhost:8080/swagger-ui
- **Health Check**: http://localhost:8080/healthz
- **Metrics**: http://localhost:8080/metrics

## Usage Guide

### Feature Flags

```toml
[features]
default = []
strict = []  # Enable warnings for template utilities
```

**Template Mode (default):** No warnings for unused utilities
**Project Mode:** Set `default = ["strict"]` in `Cargo.toml`

## Testing

```bash
cargo test
```

## Monitoring

### Prometheus Metrics

Available at `/metrics`:
- HTTP request duration histograms
- Database pool statistics
- Redis connection health
- Circuit breaker state

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
