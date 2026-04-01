# GT Id

A minimalist OpenID Connect provider in Rust. Single binary with SQLite.

## Why?

You want to add login to a small project. A proper one. With OAuth2, PKCE, ID tokens, refresh tokens - the full OIDC stack that every library understands.

Your options:
- **Keycloak** - Java process, needs PostgreSQL, XML configuration, realm concepts. For a project with three users.
- **Authentik** - Python, Redis, PostgreSQL, Docker Compose with five services. Nice UI, but you just wanted login.
- **Zitadel** - Go, CockroachDB. Enterprise features you'll never need.
- **Auth0/Clerk** - Cloud, vendor lock-in, costs from user X.
- and many others

GT Id is the alternative when you don't need any of that: a single binary, one SQLite file, one `.env`. Done. Multiple clients are managed through the admin panel.

## Features

- **OIDC-compliant** - Discovery, JWKS, Authorization Code Flow, Token Endpoint, UserInfo
- **PKCE mandatory** (S256) - no insecure fallback, code_challenge 43–128 characters validated (RFC 7636)
- **Ed25519 signatures** - ephemeral keys with key rotation support
- **Multi-client** - manage any number of clients via admin panel, secrets hashed with Argon2id
- **Client auth** - `client_secret_basic` and `client_secret_post`
- **Token Revocation** (RFC 7009) with cascade revocation of the entire token family
- **Token Introspection** (RFC 7662) - resource servers can validate tokens
- **Refresh Token Rotation** - old token is automatically revoked on use
- **Refresh Token Chain Tracking** - on token reuse the entire family is revoked
- **Auth Code Replay Detection** - on code reuse all derived tokens are revoked
- **at_hash in ID Token** - binds access token to ID token (OIDC Core 3.1.3.6)
- **Client binding** - auth codes and refresh tokens are bound to the client_id
- **Nonce mandatory** - prevents ID token replay attacks
- **Scope downscoping** - clients can request a subset of scopes on refresh
- **Grant type restriction** - configurable which grant types are allowed
- **RP-Initiated Logout** - with id_token_hint and post_logout_redirect_uri validation
- **Session fixation protection** - old sessions are invalidated on login
- **Admin panel** - create, edit, delete users and clients
- **Roles** - configurable, included in the ID token as `roles` claim
- **Account lockout + rate limiting** - brute force protection
- **CSRF protection** - double-submit cookie with SHA256 and SameSite=Strict
- **Security headers** - CSP, HSTS (1 year), X-Frame-Options, Referrer-Policy, Cache-Control
- **Constant-time comparisons** - `subtle` crate against timing attacks on credentials and PKCE
- **email_verified claim** - included in ID token per OIDC Core
- **Security event logging** - structured tracing for failed logins, lockouts, token replay, admin operations
- **Redirect URI validation** - only http/https schemes allowed on client creation
- **i18n (DE/EN)** - UI language auto-detected from `Accept-Language` header, powered by Mozilla Project Fluent
- **Per-language content** - email templates and legal pages (imprint, privacy) editable per language in the admin panel, public pages served in the visitor's language with German fallback

## What it doesn't do (by design)

- Implicit/Hybrid Flow (authorization code only)
- Social Login / Federation
- Multi-Tenancy
- SCIM / User Provisioning

## Quickstart

```bash
# Create .env (see Configuration)
nano .env
# Adjust: PUBLIC_UI_URI, SECURE_COOKIES, etc.

# Start
cargo run

# UI:  http://localhost:3001 (Login, Consent, Admin)
# API: http://localhost:3000 (OIDC endpoints)

# On first launch, open http://localhost:3001 to create the initial admin account.
# Then create a client in the admin panel: http://localhost:3001/admin/clients/create
```

## OIDC Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | Discovery |
| `/jwks` | GET | JSON Web Key Set (current + previous key) |
| `/authorize-url?client_id=...` | GET | Ready-made authorize URL incl. PKCE, state, nonce |
| `/token` | POST | Token exchange (auth code + refresh) |
| `/userinfo` | GET | User claims via Bearer token |
| `/revoke` | POST | Token Revocation (RFC 7009) with cascade |
| `/introspect` | POST | Token Introspection (RFC 7662) |
| `/logout` | GET | RP-Initiated Logout (OIDC) |

## Configuration (.env)

| Variable | Description | Default |
|----------|-------------|---------|
| `ISSUER_URI` | OIDC Issuer URL | `http://localhost:3000` |
| `PUBLIC_UI_URI` | Public UI URL (for authorize redirects) | `http://localhost:3001` |
| `API_LISTEN_PORT` | Port for API (OIDC) | `3000` |
| `UI_LISTEN_PORT` | Port for UI (Login, Admin) | `3001` |
| `DATABASE_URI` | SQLite path | `sqlite:gtid.db` |
| `ROLES` | Comma-separated roles | `member` |
| `LOCKOUT_MAX_ATTEMPTS` | Failed attempts before lockout | `3` |
| `LOCKOUT_DURATION_SECS` | Lockout duration in seconds | `3600` |
| `SESSION_LIFETIME_SECS` | Session lifetime in seconds | `86400` (24h) |
| `SECURE_COOKIES` | Secure flag for HTTPS cookies | `true` |
| `ALLOWED_GRANT_TYPES` | Allowed grant types (comma-separated) | `authorization_code,refresh_token` |
| `KEY_ROTATION_INTERVAL_SECS` | Ed25519 key rotation interval in seconds | `86400` (24h) |
| `CORS_ALLOWED_ORIGINS` | Allowed CORS origins (comma-separated) | *none* (no cross-origin) |
| `MAX_REQUEST_BODY_BYTES` | Max request body size in bytes | `65536` (64 KB) |
| `TRUSTED_PROXIES` | Trust X-Forwarded-For header for client IP | `false` |
| `ACCESS_TOKEN_EXPIRY_SECS` | Access token lifetime in seconds | `900` (15 min) |
| `ID_TOKEN_EXPIRY_SECS` | ID token lifetime in seconds | `600` (10 min) |
| `REFRESH_TOKEN_EXPIRY_DAYS` | Refresh token lifetime in days | `30` |

## Security Architecture

### Token Security

```
Auth Code ──┬──> Access Token (JWT, 15 min default, at_hash in ID token)
            ├──> ID Token (JWT, 10 min default, with at_hash + nonce)
            └──> Refresh Token ──> new Refresh Token ──> ...
                 (30 days default) (same token_family)
```

**Token family:** All refresh tokens derived from the same auth code form a family. On suspected token theft (reuse of an already revoked token) the entire family is revoked.

**Auth Code Replay:** If an already redeemed auth code is presented again, all derived tokens are immediately revoked (OAuth Security BCP).

### Key Rotation

Ed25519 keys are held in memory. On rotation the current key becomes the previous key and a new one is generated. The JWKS endpoint serves both keys so clients can still validate tokens signed with the old key.

### Security Measures

For detailed security patterns and guidelines for contributors, see [SECURITY.md](SECURITY.md).

| Attack | Protection |
|--------|------------|
| Timing attacks | Argon2id for client secrets, `subtle::ConstantTimeEq` for URI comparisons |
| Brute force | Rate limiting (IP + User-Agent) + account lockout |
| Session fixation | All old sessions are invalidated on login |
| CSRF | Double-submit cookie (SHA256, SameSite=Strict) |
| Token substitution | at_hash binds access token to ID token |
| Token theft | Refresh token chain tracking with family revocation |
| Code replay | One-time codes with cascade revocation on reuse |
| Open redirect | Exact match of redirect_uri against registered client URIs |
| ID token replay | Nonce mandatory |
| Scope escalation | Downscoping allowed, upscoping prevented |
| Clickjacking | X-Frame-Options: DENY + CSP frame-ancestors 'none' |
| MITM | HSTS with 1 year + includeSubDomains |
| Cross-origin abuse | CORS with explicit origin allowlist (default: none) |
| Oversized payloads | Request body size limit (default: 64 KB) |
| Page caching | Cache-Control: no-store on all API and UI responses |
| Open redirect | Redirect URI scheme validation (http/https only) |
| Missing audit trail | Structured security event logging (login, lockout, admin ops, token replay) |

## Architecture

```
gtid (single binary, ~3 MB)
  |
  +-- UI (:3001) ---- Login, Consent, Admin, Profile, RP-Logout
  |                    Templates embedded, no filesystem needed
  |
  +-- API (:3000) --- OIDC endpoints, JWKS, Token, UserInfo, Revoke, Introspect
  |
  +-- SQLite -------- Users, Clients, Sessions, Auth Codes, Refresh Tokens (with client_id + token_family)
  |
  +-- Ed25519 ------- KeyStore with rotation (current + previous key)
```

> **Note:** The Ed25519 key is generated in memory on each start and never written to disk. This means: after a restart all previously issued tokens become invalid and users must log in again.

Both ports always bind to `127.0.0.1`. For external access place a reverse proxy (nginx, Caddy) with TLS in front.

## Integration

See [HOWTO.md](HOWTO.md) for a step-by-step guide with curl examples.

Any OIDC-compliant library can use GT Id via discovery:

```
http://localhost:3000/.well-known/openid-configuration
```

## License

MIT
