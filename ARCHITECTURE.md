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
gtid/                           # Cargo workspace
├── Cargo.toml                   # workspace members = [shared, api, ui, server]
├── .rust-version               # Pinned toolchain
├── clippy.toml                # Clippy configuration
├── .editorconfig              # Editor settings
│
├── shared/                    # Shared library (used by api, ui, server)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs             # AppStateCore, re-exports
│       ├── config.rs          # AppConfig
│       ├── errors.rs          # AppError
│       ├── datetime.rs        # Chrono helpers
│       ├── i18n.rs          # Internationalization
│       ├── limits.rs          # Size limits
│       ├── oauth.rs          # OIDC helpers
│       │
│       ├── crypto/            # Cryptography - no unsafe, no custom algorithms
│       │   ├── constant_time.rs
│       │   ├── hash.rs
│       │   ├── id.rs
│       │   ├── jwt.rs
│       │   ├── keys.rs
│       │   ├── password.rs
│       │   ├── pkce.rs
│       │   └── totp.rs
│       │
│       ├── entities/          # sqlx::FromRow
│       │   └── ...
│       │
│       ├── repositories/      # One repo per entity
│       │   ├── db.rs
│       │   └── ...
│       │
│       ├── models/           # Business models
│       │   └── ...
│       │
│       ├── middleware/       # Axum middleware
│       │   ├── bot_trap.rs
│       │   ├── content_type.rs
│       │   ├── csrf.rs
│       │   ├── language.rs
│       │   ├── lockout.rs
│       │   ├── pending_2fa.rs
│       │   ├── pending_redirect.rs
│       │   ├── rate_limit.rs
│       │   ├── security_headers.rs
│       │   ├── session.rs
│       │   └── tracked_store.rs
│       │
│       ├── routes/          # Shared route helpers
│       │   └── helpers.rs
│       │
│       └── email/          # Email handling
│           ├── mod.rs
│           ├── worker.rs
│           ├── sender.rs
│           └── smtp_sender.rs
│
├── api/                     # API crate (stateless, JSON)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── router.rs        # build_api_router()
│       ├── helpers.rs
│       └── handlers/
│           ├── jwks.rs
│           ├── well_known.rs
│           ├── userinfo.rs
│           ├── users.rs
│           ├── revoke.rs
│           ├── token.rs
│           ├── introspect.rs
│           └── authorize_url.rs
│
├── ui/                     # UI crate (stateful, HTML)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs           # AppState
│       ├── router.rs        # build_ui_router()
│       ├── ctx.rs          # Template contexts
│       ├── middleware/
│       │   ├── session.rs
│       │   ├── csrf.rs
│       │   └── security_headers.rs
│       ├── handlers/
│       │   ├── auth.rs
│       │   ├── authorize.rs
│       │   ├── clients.rs
│       │   ├── dashboard.rs
│       │   ├── users.rs
│       │   ├── profile.rs
│       │   ├── setup.rs
│       │   ├── totp.rs
│       │   ├── confirm_email.rs
│       │   ├── confirm_email_change.rs
│       │   ├── password_reset.rs
│       │   ├── email_templates.rs
│       │   ├── legal.rs
│       │   ├── static_files.rs
│       │   └── helpers.rs
│       └── static/           # Embedded templates + assets
│
└── server/                  # Binary crate
    ├── Cargo.toml
    └── src/
        ├── main.rs
        └── lib.rs          # start_server()
    └── tests/e2e/
        ├── main.rs
        ├── flow.rs
        └── security.rs
```

---

## Architecture Rules

### 1. Two Separate Servers

API and UI run on separate ports with separate middleware stacks. This is intentional and stays.

- **API**: Stateless, no cookie layer, CORS layer, returns JSON
- **UI**: Cookie layer, CSRF protection, CSP, returns HTML
- New API endpoints go in `api/src/handlers/`, new UI pages in `ui/src/handlers/`
- Router registration happens in respective `router.rs`

### 2. Shared State via AppStateCore

`AppStateCore` is the central, immutable state container in `shared`. It is built once in `start_server()` and passed as `Arc<AppStateCore>` to both routers.

- `gtid_ui::AppState` wraps `AppStateCore` and adds UI-only concerns (templates, CSRF, session store)
- New repositories or stores are added as fields in `AppStateCore`
- No global/static mutable state - everything goes through `AppState*`
- In-memory stores use `TrackedStore<V>` with a defined capacity

### 3. Repository Pattern

Each database entity has its own repository (`shared/src/repositories/*.rs`) holding a `SqlitePool`.

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

- Tera with `include_str!` - templates are embedded at compile time in `ui/src/static/`
- One context struct per page in `ui/src/ctx.rs` with `#[derive(Serialize)]`
- All contexts include `BaseCtx` (i18n, asset hashes) via `#[serde(flatten)]`
- No dynamic template loading at runtime

### 6. Cryptography

- All crypto operations live in `shared/src/crypto/` - not scattered across the codebase
- No `unsafe`, no custom algorithms
- JWT: EdDSA only, algorithm is not configurable
- Password hashing: Argon2id (64 MB, 3 iterations, 4 parallelism)
- TOTP secrets: AES-256-GCM encrypted in the database
- Secret comparisons: always `constant_time_eq` / `constant_time_str_eq`

### 7. Error Handling

- `AppError` enum in `shared/src/errors.rs` is the central error type
- Route handlers return `Result<..., AppError>`
- `AppError::Internal` logs details, returns only generic messages to the client (includes database errors via `From<sqlx::Error>`)
- `expect()` only in startup code, never in request handlers
- `From` impls for sqlx::Error, jsonwebtoken::Error, tera::Error, argon2::Error

### 8. Middleware Order

The middleware order in `lib.rs` / `router.rs` is security-relevant (Axum: bottom-to-top execution):

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

- E2E tests in `server/tests/e2e/` start a real server (`start_server()`) with port 0
- Unit tests live in their respective modules
- Test helpers in `shared/src/repositories/mod.rs::test_helpers` provide in-memory SQLite pools
- No database mocking - tests run against real SQLite (in-memory)

### 12. Internationalization

- `rust-i18n` with locale files in `shared/locales/`
- `I18n` struct is passed to templates via `BaseCtx`
- Language is determined from the `Accept-Language` header (`shared/src/middleware/language.rs`)
- Supported languages: `de`, `en`

### 13. Static Assets

- CSS and JS are embedded via `include_str!` / `include_bytes!` in `ui/src/static/`
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
- **Comments**: Code should be self-explanatory; comments are only added when necessary to explain *why* something is done, not *what* it does
- **Workspace**: All crates use the same edition, dependencies via path references in Cargo.toml