# Signet

[![CI](https://github.com/ConeDjordjic/signet/actions/workflows/ci.yml/badge.svg)](https://github.com/ConeDjordjic/signet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.87%2B-orange.svg)](https://www.rust-lang.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%2B-blue.svg)](https://www.postgresql.org)

Authentication and authorization service with JWT and role-based access control (RBAC).

## Overview

Signet handles user authentication and permissions for multi-tenant applications. Users can belong to multiple projects with different roles in each. Tokens are scoped to projects, so one user can have different permissions in different projects.

## Features

- **JWT Authentication**: Ed25519 signatures, refresh token rotation
- **Multi-tenant**: Project-based isolation with per-project roles
- **RBAC**: Roles, permissions, and per-user overrides
- **gRPC API**: Fast token verification for microservices
- **Events**: Outbox pattern with Redis Streams
- **Observability**: OpenTelemetry tracing, Prometheus metrics
- **Security**: Argon2id hashing, account lockout, rate limiting

## Requirements

- Rust 1.87+
- PostgreSQL 16+
- Redis 7+ (optional)
- Docker (optional)

## Quick Start

```bash
# Start with Docker
docker compose up -d

# Or run locally
cp .env.example .env
# Edit .env with your settings
cargo run --release
```

HTTP API: `http://localhost:8080`
gRPC API: `localhost:50051`
API docs: `/swagger-ui`

## Integrating with Your Backend

Signet runs as a separate service. Your backend calls it to verify tokens and check permissions.

```
Client  ──►  Your Backend  ──►  Signet
(Browser)       (API)           (Auth)
```

### Integration Options

#### 1. HTTP API

Call Signet's HTTP endpoints from your backend.

```python
# Python example
import httpx

SIGNET_URL = "http://signet:8080"

async def verify_token(token: str) -> dict | None:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{SIGNET_URL}/auth/verify",
            json={"token": token}
        )
        data = response.json()
        return data if data["valid"] else None

async def check_permission(token: str, resource: str, action: str) -> bool:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{SIGNET_URL}/permissions/check",
            headers={"Authorization": f"Bearer {token}"},
            json={"resource": resource, "action": action, "user_id": "..."}
        )
        return response.json()["allowed"]
```

#### 2. gRPC API (Recommended)

Use gRPC for lower latency in microservices.

```protobuf
service AuthService {
  rpc VerifyToken(VerifyTokenRequest) returns (VerifyTokenResponse);
  rpc CheckPermission(CheckPermissionRequest) returns (CheckPermissionResponse);
  rpc CheckPermissions(CheckPermissionsRequest) returns (CheckPermissionsResponse);
}
```

```go
// Go example
package middleware

import (
    "context"
    pb "yourapp/proto/signet"
    "google.golang.org/grpc"
)

type AuthMiddleware struct {
    client pb.AuthServiceClient
}

func NewAuthMiddleware(addr string) (*AuthMiddleware, error) {
    conn, err := grpc.Dial(addr, grpc.WithInsecure())
    if err != nil {
        return nil, err
    }
    return &AuthMiddleware{client: pb.NewAuthServiceClient(conn)}, nil
}

func (m *AuthMiddleware) VerifyToken(ctx context.Context, token string) (*pb.VerifyTokenResponse, error) {
    return m.client.VerifyToken(ctx, &pb.VerifyTokenRequest{Token: token})
}
```

#### 3. Local JWT Verification

Verify tokens locally using Signet's public key. Fastest option, but only validates the signature.

```javascript
// Node.js example
import { importSPKI, jwtVerify } from 'jose';

const SIGNET_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY;

async function verifyToken(token) {
  const publicKey = await importSPKI(SIGNET_PUBLIC_KEY, 'EdDSA');
  const { payload } = await jwtVerify(token, publicKey);
  return {
    userId: payload.sub,
    email: payload.email,
    projectId: payload.project_id,
    role: payload.role,
  };
}
```

### Typical Flow

1. **Login**: Client calls Signet directly
2. **Store tokens**: Client saves access and refresh tokens
3. **API requests**: Client sends access token to your backend
4. **Verify**: Your backend checks the token via Signet or locally
5. **Authorize**: Your backend checks permissions via Signet
6. **Refresh**: Client gets new tokens when expired

### Express.js Example

```javascript
const express = require('express');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const packageDefinition = protoLoader.loadSync('proto/auth.proto');
const signetProto = grpc.loadPackageDefinition(packageDefinition).signet.auth.v1;
const signetClient = new signetProto.AuthService('localhost:50051', grpc.credentials.createInsecure());

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });

  signetClient.VerifyToken({ token }, (err, response) => {
    if (err || !response.valid) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.user = {
      id: response.user_id,
      email: response.email,
      projectId: response.project_id,
      role: response.role,
    };
    next();
  });
}

function requirePermission(resource, action) {
  return (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    signetClient.CheckPermission({ token, resource, action }, (err, response) => {
      if (err || !response.allowed) {
        return res.status(403).json({ error: 'Permission denied' });
      }
      next();
    });
  };
}

app.get('/api/posts', authMiddleware, (req, res) => { /* ... */ });
app.delete('/api/posts/:id', authMiddleware, requirePermission('posts', 'delete'), (req, res) => { /* ... */ });
```

## API Usage

### Authentication

```bash
# Register
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass123!"}'

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass123!"}'

# Login with project scope
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass123!", "project_id": "<uuid>"}'

# Refresh tokens
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'

# Verify token
curl -X POST http://localhost:8080/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "<access_token>"}'

# Logout from all devices
curl -X POST http://localhost:8080/auth/logout-all \
  -H "Authorization: Bearer <access_token>"

# Revoke current access token
curl -X POST http://localhost:8080/auth/revoke \
  -H "Authorization: Bearer <access_token>"

# Forgot password (your backend sends the token via email)
curl -X POST http://localhost:8080/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
# Returns: {"message": "...", "reset_token": "abc123..."} or null if user not found

# Reset password
curl -X POST http://localhost:8080/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "<reset_token>", "password": "newSecurePassword123!"}'
```

### Projects

```bash
# Create project (creates default roles: admin, editor, viewer)
curl -X POST http://localhost:8080/projects \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Project", "slug": "my-project"}'

# List projects
curl http://localhost:8080/projects \
  -H "Authorization: Bearer <access_token>"
```

### Roles and Permissions

```bash
# Create role
curl -X POST http://localhost:8080/roles \
  -H "Authorization: Bearer <project_token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "moderator", "description": "Content moderation"}'

# Create permission
curl -X POST http://localhost:8080/permissions \
  -H "Authorization: Bearer <project_token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "delete_posts", "resource": "posts", "action": "delete"}'

# Assign permission to role
curl -X POST http://localhost:8080/roles/<role_id>/permissions \
  -H "Authorization: Bearer <project_token>" \
  -H "Content-Type: application/json" \
  -d '{"permission_id": "<permission_id>"}'

# Check permission
curl -X POST http://localhost:8080/permissions/check \
  -H "Authorization: Bearer <project_token>" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "<user_id>", "resource": "posts", "action": "delete"}'

# Check multiple permissions
curl -X POST http://localhost:8080/permissions/check-bulk \
  -H "Authorization: Bearer <project_token>" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "<user_id>", "permissions": ["read_posts", "write_posts", "delete_posts"]}'
```

### Members

```bash
# Add member
curl -X POST http://localhost:8080/members \
  -H "Authorization: Bearer <project_token>" \
  -H "Content-Type: application/json" \
  -d '{"user_email": "colleague@example.com", "role_name": "editor"}'

# List members
curl http://localhost:8080/members \
  -H "Authorization: Bearer <project_token>"
```

### Per-User Permission Overrides

Grant or deny permissions to specific users, overriding their role:

```bash
# Deny permission to user
curl -X POST http://localhost:8080/user-permissions \
  -H "Authorization: Bearer <project_token>" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "<user_id>", "permission_id": "<perm_id>", "granted": false}'

# Get user's effective permissions
curl http://localhost:8080/user-permissions/<user_id> \
  -H "Authorization: Bearer <project_token>"
```

## gRPC API

The gRPC server runs on port 50051.

```protobuf
service AuthService {
  rpc VerifyToken(VerifyTokenRequest) returns (VerifyTokenResponse);
  rpc CheckPermission(CheckPermissionRequest) returns (CheckPermissionResponse);
  rpc CheckPermissions(CheckPermissionsRequest) returns (CheckPermissionsResponse);
}
```

```bash
# Verify token
grpcurl -plaintext -d '{"token": "<access_token>"}' \
  localhost:50051 signet.auth.v1.AuthService/VerifyToken

# Check permission
grpcurl -plaintext -d '{"token": "<project_token>", "resource": "posts", "action": "delete"}' \
  localhost:50051 signet.auth.v1.AuthService/CheckPermission
```

## Events

Signet publishes events to Redis Streams using the outbox pattern.

### Event Types

- `user.registered` - New user
- `auth.login.success` - Login succeeded
- `auth.login.failed` - Login failed
- `auth.logout` - User logged out
- `auth.account.locked` - Account locked
- `auth.password.reset_requested` - Password reset requested
- `auth.password.reset_completed` - Password reset completed
- `project.created`, `project.updated`, `project.deleted`
- `role.created`, `role.updated`, `role.deleted`
- `permission.created`, `permission.deleted`
- `project.member.added`, `project.member.removed`

### Consuming Events

```bash
redis-cli XREAD STREAMS signet:events 0
```

```python
import redis
import json

r = redis.Redis()
last_id = '0'

while True:
    events = r.xread({'signet:events': last_id}, block=5000)
    for stream, messages in events:
        for msg_id, data in messages:
            event_type = data[b'event_type'].decode()
            payload = json.loads(data[b'data'])
            print(f"Event: {event_type}, Data: {payload}")
            last_id = msg_id
```

## Configuration

### Required

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_PRIVATE_KEY` | Base64-encoded Ed25519 private key |

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | 0.0.0.0 | Bind address |
| `PORT` | 8080 | HTTP port |
| `GRPC_ENABLED` | true | Enable gRPC |
| `GRPC_PORT` | 50051 | gRPC port |
| `GRPC_TLS_CERT_PATH` | - | TLS certificate path |
| `GRPC_TLS_KEY_PATH` | - | TLS private key path |
| `ENVIRONMENT` | development | development/staging/production |
| `REQUEST_TIMEOUT_SECS` | 30 | Request timeout |
| `MAX_BODY_SIZE` | 1048576 | Max body bytes |

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMITING_ENABLED` | true (prod) | Enable rate limiting |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | 60 | Request limit |
| `MAX_FAILED_LOGIN_ATTEMPTS` | 5 | Before lockout |
| `LOCKOUT_DURATION_MINS` | 15 | Lockout time |
| `MIN_PASSWORD_LENGTH` | 8 | Min password length |
| `REQUIRE_PASSWORD_COMPLEXITY` | true (prod) | Require mixed chars |
| `PASSWORD_HASH_COST` | 12 | Argon2 cost |
| `ROTATE_REFRESH_TOKENS` | true | Issue new refresh token on refresh |

### JWT

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_ACCESS_TOKEN_EXPIRY_SECS` | 3600 | Access token lifetime |
| `JWT_REFRESH_TOKEN_EXPIRY_SECS` | 604800 | Refresh token lifetime |
| `JWT_ISSUER` | - | Token issuer |
| `JWT_AUDIENCE` | - | Token audience |

### Redis

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | - | Redis connection URL |
| `REDIS_POOL_SIZE` | 10 | Pool size |
| `REDIS_CONNECTION_TIMEOUT_SECS` | 5 | Connection timeout |

### Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | debug/info | Log level |
| `LOG_FORMAT` | pretty/json | Log format |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | - | OpenTelemetry endpoint |
| `OTEL_SERVICE_NAME` | signet | Service name |
| `METRICS_ENABLED` | true | Enable metrics |

### CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `CORS_ALLOWED_ORIGINS` | * (dev) | Allowed origins |
| `CORS_ALLOWED_METHODS` | GET,POST,PUT,DELETE,OPTIONS | Allowed HTTP methods |
| `CORS_ALLOWED_HEADERS` | Content-Type,Authorization,X-Request-ID | Allowed headers |
| `CORS_ALLOW_CREDENTIALS` | true | Allow credentials |
| `CORS_MAX_AGE_SECS` | 3600 | Preflight cache |

### Generating Keys

```bash
cargo run --example generate_keys
```

## Development

### Testing

```bash
cargo test --lib          # Unit tests
make test                 # Full test suite
make test-quick           # Quick test run
```

### Code Quality

```bash
cargo fmt                 # Format
cargo clippy              # Lint
cargo audit               # Security audit
make lint                 # Format + clippy
```

### Migrations

```bash
diesel migration run              # Run migrations
diesel migration generate <name>  # Create migration
```

## Project Structure

```
src/
  auth/           JWT, password hashing, lockout
  cache/          Redis caching, token revocation
  events/         Outbox and Redis publisher
  grpc/           gRPC service
  handlers/       HTTP handlers
  middleware/     Auth, rate limiting, metrics
  telemetry/      Tracing, metrics
  config.rs       Configuration
  models.rs       Database models
  schema.rs       Diesel schema

proto/            Protocol buffers
migrations/       Database migrations
tests/            Integration tests
```

## Security

- **Passwords**: Argon2id (memory-hard, GPU-resistant)
- **JWTs**: Ed25519 signatures (128-bit security)
- **Refresh tokens**: Stored as SHA-256 hashes
- **Rate limiting**: Protects login endpoints
- **Account lockout**: After failed attempts
- **Token revocation**: Redis-backed, per-token and per-user

## Client Libraries

Official client libraries for integrating with Signet:

| Language | Package |
|----------|---------|
| Go | [clients/go](./clients/go) |

## License

MIT
