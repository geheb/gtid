# Architecture

Architecture guidelines for GT Id. New features and changes must follow these rules.

---

## Overview

GT Id is an OpenID Connect provider built with Axum (Rust). The server consists of two separate HTTP listeners:

- **API** (OAuth2/OIDC endpoints): Token, UserInfo, JWKS, Discovery, Authorize-URL, Revoke, Introspect
- **UI** (browser-facing): Login, Consent, Admin panel, Profile, Setup, 2FA, Password reset

Both run on separate ports with different middleware stacks (API: CORS, no cookie layer; UI: cookie layer, CSRF, CSP).

---

## Project Structure

```
src/
  main.rs                  # Entrypoint: load .env, tracing, start_server()
  lib.rs                   # AppState, start_server(), background tasks, router setup
  config.rs                # AppConfig - all configuration from environment variables
  errors.rs                # AppError enum - centralized error handling
  datetime.rs              # Chrono helpers (SQLite format)
  i18n.rs                  # Internationalization (rust-i18n)

  crypto/                  # Cryptography - no unsafe, no custom algorithms
    constant_time.rs       # Constant-time comparisons (subtle)
    hash.rs                # SHA-256 hashing
    id.rs                  # UUID v6 generation
    jwt.rs                 # JWT creation/validation (EdDSA only)
    keys.rs                # KeyStore with rotation (Ed25519)
    password.rs            # Argon2id hashing + dummy verify
    pkce.rs                # PKCE S256 verification
    totp.rs                # TOTP encryption/decryption (AES-256-GCM)

  entities/                # Data structures (sqlx::FromRow)
    user.rs, client.rs, session.rs, auth_code.rs, refresh_token.rs, ...

  repositories/            # Database access (one repository per entity)
    db.rs                  # Pool init, migrations, SQLite pragmas
    user.rs, client.rs, session.rs, auth_code.rs, ...
    mod.rs                 # test_helpers (in-memory pools)

  middleware/              # Axum middleware
    bot_trap.rs            # Honeypot fallback for unknown paths
    content_type.rs        # Content-Type whitelist
    csrf.rs                # Double-submit CSRF
    language.rs            # Accept-Language detection
    lockout.rs             # Account lockout after failed attempts
    pending_2fa.rs         # In-memory 2FA state
    pending_redirect.rs    # In-memory redirect state
    rate_limit.rs          # IP+UA rate limiting
    security_headers.rs    # CSP, HSTS, Cache-Control, etc.
    session.rs             # Session extractor (AdminUser, AuthenticatedUser)
    tracked_store.rs       # TrackedStore<V> - capacity-bounded DashMap

  routes/
    router.rs              # build_api_router(), build_ui_router()
    ctx.rs                 # Template contexts (Serialize structs)
    helpers.rs             # client_ip
    mod.rs                 # Re-exports

    api/                   # OAuth2/OIDC endpoints
      auth.rs              # Login/Logout
      authorize.rs         # /authorize GET+POST (consent)
      authorize_url.rs     # /authorize-url (client-authenticated)
      token.rs             # /token (code->token exchange, refresh)
      userinfo.rs          # /userinfo
      well_known.rs        # /.well-known/openid-configuration
      jwks.rs              # /jwks
      revoke.rs            # /revoke
      introspect.rs        # /introspect
      profile.rs           # /profile (self-service)

    ui/                    # Admin + UI pages
      clients.rs           # Client management
      users.rs             # User management
      dashboard.rs         # Admin dashboard
      setup.rs             # Initial setup
      totp.rs              # 2FA setup/verify pages
      confirm_email.rs     # Email confirmation
      password_reset.rs    # Password reset
      static_files.rs      # CSS/JS (embedded, cache-busting)
      ...
```

---

## Architecture Rules

### 1. Two Separate Servers

API and UI run on separate ports with separate middleware stacks. This is intentional and stays.

- **API**: Stateless, no cookie layer, CORS layer, returns JSON
- **UI**: Cookie layer, CSRF protection, CSP, returns HTML
- New API endpoints go in `routes/api/`, new UI pages in `routes/ui/`
- Router registration happens in `routes/router.rs`

### 2. Shared State via AppState

`AppState` is the central, immutable state container. It is built once in `start_server()` and passed as `Arc<AppState>` to both routers.

- New repositories or stores are added as fields in `AppState`
- No global/static mutable state - everything goes through `AppState`
- In-memory stores use `TrackedStore<V>` with a defined capacity

### 3. Repository Pattern

Each database entity has its own repository (`repositories/*.rs`) holding a `SqlitePool`.

- Repositories are the only layer that executes SQL
- All queries use `sqlx::query!` with bind parameters
- No SQL in route handlers or middleware
- New entities: model in `entities/`, repository in `repositories/`, migration in `repositories/db.rs`

### 4. Four Separate SQLite Databases

Data is split across four databases:

| Database | Contents |
|----------|----------|
| `users` | Users, sessions, email confirmations, password resets, trusted devices, email changes |
| `clients` | OAuth2 clients, auth codes, refresh tokens, consent grants |
| `emails` | Email templates, email queue |
| `config` | Legal pages (imprint, privacy) |

**Why four databases instead of one?**

- **Avoid write contention**: SQLite allows only one writer at a time (even in WAL mode). Splitting the data means a write to the email queue does not block concurrent writes to sessions or clients. Each database has its own WAL and therefore its own write lock.
- **Limit blast radius**: A corrupt or accidentally deleted database file only affects one domain. User data, client configuration, and email templates can be backed up and restored independently.
- **Separation of concerns**: The four databases mirror four independent domains. User data contains sensitive PII (password hashes, TOTP secrets), client data contains OAuth2 configuration, email data is operational (queue, templates), and config data is editorial (legal pages). This allows different backup cycles and retention policies per domain.
- **Independent migrations**: Each database has its own migration function (`run_users_migrations`, `run_clients_migrations`, etc.). Schema changes in one domain do not touch the others.

**Trade-off**: There are no cross-database foreign keys in SQLite. Relationships between databases (e.g. `user_id` in `auth_codes`) are resolved at the application level - the field is a plain text column, not a FK. Consistency on deletions must be ensured in code.

New tables go into the thematically matching database.

### 5. Template Rendering

- Tera with `include_str!` - templates are embedded at compile time
- One context struct per page in `routes/ctx.rs` with `#[derive(Serialize)]`
- All contexts include `BaseCtx` (i18n, asset hashes) via `#[serde(flatten)]`
- No dynamic template loading at runtime

### 6. Cryptography

- All crypto operations live in `crypto/` - not scattered across the codebase
- No `unsafe`, no custom algorithms
- JWT: EdDSA only, algorithm is not configurable
- Password hashing: Argon2id (64 MB, 3 iterations, 4 parallelism)
- TOTP secrets: AES-256-GCM encrypted in the database
- Secret comparisons: always `constant_time_eq` / `constant_time_str_eq`

### 7. Error Handling

- `AppError` enum in `errors.rs` is the central error type
- Route handlers return `Result<..., AppError>`
- `AppError::Internal` and `AppError::Database` log details, return only generic messages to the client
- `expect()` only in startup code, never in request handlers
- `From` impls for sqlx::Error, jsonwebtoken::Error, tera::Error, argon2::Error

### 8. Middleware Order

The middleware order in `lib.rs` is security-relevant (Axum: bottom-to-top execution):

```
Bot-Trap Guard          <- outermost layer (runs first)
TraceLayer
Security Headers / CSP
Cookie Manager (UI only)
RequestBodyLimitLayer
Content-Type Validation
CORS (API only)
Bot-Trap Fallback       <- innermost layer
```

New middleware is inserted according to this scheme. Security middleware (rate limiting, auth checks) must run before route logic.

### 9. Background Tasks

Background tasks run as `tokio::spawn` tasks, started in `start_server()`:

- **Cleanup** (hourly): Expired sessions, auth codes, refresh tokens, trusted devices, email changes, confirmation tokens, password reset tokens
- **Key rotation**: Ed25519 keys rotate at a configurable interval
- **Email worker**: Polls the email queue, sends via SMTP

New periodic tasks follow the same pattern: `tokio::spawn` + `tokio::time::interval`.

### 10. Configuration

- All configuration comes from environment variables (`AppConfig::from_env()`)
- `.env` is loaded at startup (`dotenvy`)
- No config files, no YAML/TOML
- Secrets (TOTP key, SMTP password) come exclusively from the environment, never from the database
- `AppConfig` implements `Debug` manually with `[REDACTED]` for secrets

### 11. Tests

- E2E tests in `tests/e2e/` start a real server (`start_server()`) with port 0
- Unit tests live in their respective modules
- Test helpers in `repositories/mod.rs::test_helpers` provide in-memory SQLite pools
- No database mocking - tests run against real SQLite (in-memory)

### 12. Internationalization

- `rust-i18n` with locale files in `locales/`
- `I18n` struct is passed to templates via `BaseCtx`
- Language is determined from the `Accept-Language` header (`middleware/language.rs`)
- Supported languages: `de`, `en`

### 13. Static Assets

- CSS and JS are embedded via `include_str!` / `include_bytes!`
- Cache-busting via SHA-256 content hash as query parameter (`?v=...`)
- Static files: `Cache-Control: public, max-age=604800, immutable`
- Dynamic responses: `Cache-Control: no-store`

### 14. Form Parsing

- No `serde::Deserialize` on user input - forms are read with `form_urlencoded::parse()`
- Fields are extracted and validated individually
- `Vec<(String, String)>` instead of `HashMap` (HashDoS protection)
- No nested or polymorphic data structures from user input

### 15. H2C Support

Both servers support HTTP/2 Cleartext (h2c) via `hyper-util` `AutoBuilder`. This allows HTTP/2 behind a reverse proxy without TLS termination at the application server.

---

## Conventions

- **Naming**: snake_case for everything (modules, functions, variables). Structs in PascalCase
- **Visibility**: Prefer `pub(crate)` or `pub(super)`, use `pub` only when necessary
- **Errors**: `?` operator with `AppError` instead of `.unwrap()` in request code
- **IDs**: UUID v6 via `crypto::id::new_id()` for all new entities
- **Time format**: SQLite-compatible ISO 8601 (`datetime('now')`, Chrono `to_sqlite()`)
- **Token pattern**: CSPRNG generation, SHA-256 hashed in DB, plaintext only sent to the user

