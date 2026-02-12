# rs-passkey-auth

A secure authentication service using WebAuthn passkeys and JWT tokens, built with Rust and Axum.

## Features

- **WebAuthn Authentication**: Full support for passwordless passkeys
- **JWT Tokens**: Secure tokens with Ed25519 cryptography
- **Circuit Breaker Pattern**: Automatic failure detection and recovery for database and Redis
- **Exponential Backoff**: Intelligent retry mechanism for transient failures
- **RESTful API**: Well-documented endpoints with Swagger UI
- **PostgreSQL Database**: Robust and reliable storage
- **Redis Cache**: Efficient session and token blacklist management
- **Containerization**: Complete setup with Docker and Docker Compose
- **Configurable CORS**: Support for multi-origin applications
- **Structured Logging**: Complete operation tracing
- **Monitoring**: Prometheus metrics for observabilit

## Tech Stack

- **Rust** - Programming language
- **Axum** - Async web framework
- **WebAuthn-rs** - WebAuthn implementation
- **JWT** - Secure authentication tokens
- **PostgreSQL** - Primary database
- **Redis** - Cache and session management
- **Docker** - Containerization
- **Prometheus** - Metrics and monitoring
- **Swagger UI** - Interactive API documentation
- **Failsafe** - Circuit breaker and resilience patterns

## Prerequisites

- Docker and Docker Compose
- Rust 1.92+ (for local development)
- Git

## Quick Start

### 1. Clone the repository

```bash
git clone <repository-url>
cd rs-passkey-auth
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

**Edit the `.env` file with your configurations**

### 3. Start the services

```bash
docker compose up -d
```

The service will be available at:
- **API**: http://localhost:8080
- **Swagger UI**: http://localhost:8080/swagger-ui
- **Health Check**: http://localhost:8080/healthz
- **Prometheus metrics**: http://localhost:8080/metrics

### Complete Documentation

Visit http://localhost:8080/swagger-ui for complete interactive documentation with examples and real-time testing.

## Security

- **Ed25519 Cryptography**: JWT tokens with secure digital signatures
- **WebAuthn Standard**: Standards-compliant passwordless authentication
- **Token Blacklisting**: Secure refresh token invalidation
- **Configurable CORS**: Cross-origin protection
- **Input Validation**: Rigorous validation of all inputs
- **Error Handling**: Secure error handling without information leakage
- **Circuit Breaker**: Protection against cascading failures

## Testing

Run the tests locally:

```bash
cargo test
```
