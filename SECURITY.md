# Security Patterns for GT Id

Established security patterns for this project. Follow these when adding new features.
If you discover a security issue in this library, please practice [responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure) by privately contacting me at gethomast@proton.me
I ask that you show some common decency and empathy by contacting me before taking up arms on social media or attempting to create a CVE.

---

## 1. Memory Safety & Panic Discipline

**Pattern:** Never use `unsafe`, `unchecked` methods, or raw pointers. Rely on Rust's guarantees (bounds checking, ownership, borrowing) for all memory operations.

### `expect()` - only for invariants, never for runtime input

`expect()` is acceptable when failure means a programming error or broken environment - never for anything that depends on user input or runtime state.

**Allowed** (startup/compile-time invariants):
- Startup checks: `users.has_admin().await.expect("Failed to check for admin users")`
- Embedded resources: `serde_json::from_str(include_str!(...)).expect(...)`
- Database setup: migrations, WAL mode, foreign keys
- Key generation at startup

**Forbidden:**
- Any code path reachable by a user request - use `Result`/`?` instead
- Parsing user-supplied values - return `AppError::BadRequest`
- Database queries during request handling - propagate errors

### `unchecked` methods - never

Never use `get_unchecked`, `from_utf8_unchecked`, `unwrap_unchecked`, or similar. Always use the checked variant, even if you believe the index or data is valid.

### `Instant::now()` - use `checked_duration_since`, never `duration_since`

`Instant` is monotonic, but on some platforms (VM live migration, suspend/resume, WSL clock drift) an earlier `Instant` can appear *later* than a current one. `duration_since()` panics in that case. `elapsed()` internally uses `duration_since` but Rust guarantees it saturates to zero - safe to use for simple expiry checks.

**Use `checked_duration_since`** when comparing two stored `Instant` values:
```rust
// correct - returns None instead of panicking
now.checked_duration_since(*t).is_some_and(|d| d < window)
```

**Use `elapsed()`** for simple "has this expired?" checks on a single stored `Instant`:
```rust
// correct - saturates to zero, never panics
if banned_at.elapsed() >= BAN_DURATION { /* expired */ }
```

**Never use:**
```rust
// dangerous - panics if clock drifts
now.duration_since(earlier)
```

**Rule:** If a dependency requires `unsafe` in your code, find an alternative crate. Every `expect()` must have a descriptive message and must only appear in startup/initialization code. Always use `checked_duration_since` or `elapsed()` - never `duration_since` on `Instant`.

---

## 2. Input Boundaries

**Pattern:** Enforce size limits at two layers - global middleware and per-field validation.

- **Global:** `RequestBodyLimitLayer` on every router (default 64 KB)
- **Per-field:** Validate length before processing (e.g. `id_token_hint ≤ 2048`, `state ≤ 1024`, `code_challenge 43–128`)
- **Content-Type:** Whitelist allowed types in middleware, reject everything else (including `multipart/form-data`)
- **Redirect URI validation:** Exact match against registered client URIs using constant-time comparison. Only `http`/`https` schemes allowed - rejects path traversal (`..`, `\`) on client creation. Prevents open redirect attacks

**Rule:** Every new endpoint inherits the global body limit. Every new user-facing string field needs an explicit length check. Never trust `X-Forwarded-For` without `TRUSTED_PROXIES=true`. New redirect targets must be validated against registered URIs.

---

## 3. Deserialization

**Pattern:** Never deserialize untrusted input directly into complex types.

- Parse forms with `form_urlencoded::parse()` → extract typed fields manually → validate downstream
- Keep deserialized structs flat - only primitives (`String`, `i64`, `bool`, `Option<String>`, `Vec<String>`)
- Use `Vec<(String, String)>` for form fields, never `HashMap` (prevents HashDoS)
- Never use `#[serde(untagged)]` or `#[serde(tag)]` on user-facing types (prevents type confusion)
- Never use `serde_json::from_str/from_slice` on user input

**Rule:** If a new feature needs JSON input from users, deserialize into a struct with only primitive fields and validate every field after extraction.

---

## 4. JWT / Token Handling

**Pattern:** Pin the algorithm, validate all claims, support key rotation.

- Algorithm: `EdDSA` only - hardcoded, not configurable per-token
- Always validate: `iss`, `aud`, `exp`
- Key rotation: JWKS serves current + previous key so clients can still verify during rotation
- Limit token size at the boundary before parsing (2048 bytes for hints)
- **at_hash:** Access token hash is included in the ID token - binds both tokens together, prevents token substitution (OIDC Core 3.1.3.6)
- **Nonce mandatory:** Every authorization request must include a nonce, included in the ID token to prevent replay
- **Token family tracking:** All refresh tokens derived from the same auth code form a family. Reuse of a revoked refresh token triggers cascade revocation of the entire family
- **Auth code replay detection:** If an already redeemed auth code is presented again, all derived tokens are immediately revoked
- **Scope downscoping:** Clients may request a subset of scopes on refresh - upscoping is rejected
- **Refresh token rotation:** On each refresh, the old token is revoked and a new one is issued. `rotated_at` records when the old token was consumed - this creates an audit trail and distinguishes "revoked because rotated" from "revoked because of detected theft". Only tokens with `rotated_at IS NULL` are eligible for rotation (idempotency guard)
- **Expired token cleanup:** Revoked and expired refresh tokens are opportunistically deleted on each new `create()` call (`WHERE expires_at < datetime('now') AND revoked = 1`)

**Rule:** Never accept an algorithm from the token itself. Never skip issuer or audience validation. New token types must follow the same claim validation pattern. Never allow scope escalation on token refresh.

---

## 5. Cookies & Sessions

**Pattern:** Defense-in-depth with cookie attributes and session lifecycle management.

- All session cookies: `HttpOnly`, `SameSite=Strict`, `Secure` (in production)
- Cookie values are opaque lookup keys, never deserialized
- **Session fixation protection:** On login, all previous sessions for the user are invalidated before creating a new one - prevents an attacker from fixating a session ID before authentication

**Rule:** Never store structured data in cookies. Always invalidate existing sessions on login.

---

## 6. CSRF Protection

**Pattern:** Double-submit cookie with derived form token. Every state-changing request must be verified.

### How it works

1. **Cookie:** A random 32-byte secret (`__csrf`, `HttpOnly`, `SameSite=Strict`, 1 hour lifetime)
2. **Form token:** `SHA256("gtid-csrf:" + cookie_secret)` - embedded as hidden field in every form
3. **Verification:** On POST, `verify_csrf()` recomputes the hash from the cookie and compares it to the submitted token using `constant_time_eq`

The attacker cannot forge the form token because:
- `HttpOnly` prevents JavaScript from reading the cookie secret
- `SameSite=Strict` prevents the browser from sending the cookie on cross-site requests
- The form token is derived, not identical to the cookie - no value reuse across layers

### Integration

- **GET handlers:** Extract `CsrfToken` (auto-generates cookie if missing), pass `form_token` to the template
- **POST handlers:** Call `csrf::verify_csrf(&cookies, &form.csrf_token)` before processing - reject with 400 on mismatch
- **POST handlers that re-render forms:** Call `set_new_csrf_cookie()` to rotate the secret after use

**Rule:** Every new POST/PUT/DELETE endpoint must call `verify_csrf()`. Never skip CSRF verification on state-changing requests. Never expose the cookie secret in logs or responses.

---

## 7. In-Memory Stores

**Pattern:** Every in-memory store has a hard capacity limit via `TrackedStore<V>` with `can_insert()`.

| Store | Capacity |
|-------|----------|
| LoginRateLimiter | 100,000 |
| BotTrap | 100,000 |
| AccountLockout | 50,000 |
| PendingRedirectStore | 10,000 |

**Rule:** Every new in-memory store must use `TrackedStore<V>` and define a maximum capacity. No unbounded growth from external input.

---

## 8. Database

**Pattern:** Type-safe queries with parameterized inputs. Harden storage at the SQLite level.

- All models use `#[derive(sqlx::FromRow)]` - no dynamic deserialization
- All queries use `sqlx::query!` with bind parameters - no string interpolation
- Schema enforces field types and constraints
- **`secure_delete = 1`:** Overwritten pages are zeroed before reuse - prevents recovery of deleted secrets (tokens, password hashes) from the database file
- **`temp_store = 2`:** Temporary tables and indices are kept in memory, never written to disk - prevents leaking intermediate query results to the filesystem
- **File permissions (Unix):** Database files are set to `0o600` (owner-only read/write) on startup

**Rule:** Never construct SQL from user input. Never deserialize database rows into untyped structures. Never weaken `secure_delete` or `temp_store` pragmas.

---

## 9. Password & Secret Hashing

**Pattern:** All passwords and client secrets are hashed with Argon2id before storage. Never store plaintext. Enforce password strength at the boundary.

### Argon2id configuration

- **Algorithm:** Argon2id (v0x13) - resistant to both side-channel and GPU attacks
- **Parameters:** 64 MB memory, 3 iterations, 4 parallelism (`crypto/password.rs:8`)
- **Salt:** Random per hash via `OsRng` - same password produces different hashes

### Password & Secret strength validation

`validate_password_strength()` enforces before hashing:
- Minimum length 10
- At least 1 uppercase, 1 lowercase, 1 digit, 1 special character
- Entropy check via `password_strength::estimate_strength() >= 0.7`

`validate_secret_strength()` enforces before hashing:
- Minimum length 16
- At least 1 uppercase, 1 lowercase, 2 digits, 2 special characters
- Entropy check via `password_strength::estimate_strength() >= 0.7`

### Keyed hashing for in-memory stores

`TrackedStore` uses `RapidHasher` with a **random seed per process start** for hashing IP/User-Agent keys. This prevents:
- **Hash collision attacks:** Attacker cannot predict bucket distribution without knowing the seed
- **Cross-restart correlation:** Keys hash differently after restart

**Rule:** Never store passwords or client secrets in plaintext. Always use `hash_password()` from `crypto::password`. Never weaken `validate_password_strength()` or `validate_secret_strength()` requirements. New in-memory key hashing must use a runtime-random seed, never a fixed one (except in tests).

---

## 10. Email Confirmation Tokens

**Pattern:** Confirm user email addresses via single-use, time-limited tokens. Never store the plaintext token in the database.

### Token generation

- **CSPRNG:** 32 bytes from `OsRng` via `rand::random()`, hex-encoded (64 characters, 256 bits entropy)
- **Hashed storage:** Only the SHA-256 hash of the token is stored in the database (`token_hash` column). The plaintext token is sent to the user via email and never persisted
- **If the database leaks,** an attacker cannot use the stored hashes to confirm accounts

### Token lifecycle

- **Expiry:** Configurable via `EMAIL_CONFIRM_TOKEN_EXPIRY_HOURS` (default 24h). Validated server-side with `expires_at > datetime('now')`
- **Single use:** After successful confirmation, all tokens for the user are deleted (`delete_for_user`)
- **Expired token cleanup:** Opportunistic - expired tokens are pruned on every `create()` call. No separate background job needed
- **Resend:** Admin can trigger a resend, which deletes existing tokens before creating a new one

### Abuse prevention

- **Rate limiting:** The `/confirm-email` endpoint shares the login rate limiter (IP + User-Agent based). Failed attempts count against the limit
- **Account enumeration:** Unconfirmed users receive the same generic login error as invalid credentials - an attacker cannot distinguish "wrong password" from "not confirmed"
- **Login block:** Users with `is_confirmed = false` cannot log in. The initial admin user (setup flow) is auto-confirmed

### JWT integration

- `email_verified` claim in ID tokens and `/userinfo` reflects the actual `is_confirmed` status - never hardcoded

**Rule:** Never store plaintext confirmation tokens in the database. New token types (password reset, etc.) must follow the same pattern: CSPRNG generation, SHA-256 hashed storage, configurable expiry, opportunistic cleanup.

---

## 11. Security Headers & CSP

**Pattern:** Apply security headers on every response. Use a strict Content-Security-Policy that only whitelists what is actually needed.

- **CSP** (UI router): `default-src 'self'` baseline, every directive explicitly set, `object-src 'none'`, `frame-ancestors 'none'`, `form-action` dynamically built from registered client redirect origins
- **CSP rebuild:** When clients are created, edited, or deleted, the CSP is rebuilt from the current client list and swapped via `Arc<RwLock<String>>`
- **API router:** No CSP (returns JSON only), but all other security headers apply
- **Additional headers on all responses:**

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Cache-Control` | `no-store` (API) / `no-store, no-cache, must-revalidate` (UI) |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` (UI) |

**Rule:** Never add `'unsafe-inline'` or `'unsafe-eval'` to script-src or style-src. New external resources require an explicit CSP directive. If a new feature needs form submissions to external origins, update `build_csp()` - never bypass it with a wildcard.

---

## 12. Cache Control

**Pattern:** Prevent browsers and proxies from caching sensitive responses. Allow caching only for static, non-sensitive assets with cache-busting.

### Sensitive responses - never cache

| Scope | Header |
|-------|--------|
| API responses (tokens, userinfo, JWKS, discovery) | `Cache-Control: no-store` |
| UI responses (login, consent, admin, profile) | `Cache-Control: no-store, no-cache, must-revalidate` + `Pragma: no-cache` |
| Token endpoint | `Cache-Control: no-store` (per OAuth 2.0 spec) |

Applied via middleware (`security_headers.rs`) - every response gets cache headers automatically.

### Static assets - cache with integrity

- Static files (CSS, JS): `Cache-Control: public, max-age=604800, immutable` (7 days)
- **Cache-busting:** Asset URLs include a SHA256 content hash as query string (`?v=a1b2c3d4`). When content changes, the hash changes, forcing browsers to fetch the new version
- Static content is embedded at compile time (`include_str!`) - no filesystem reads at runtime

**Rule:** Never set `Cache-Control: public` or `max-age` on responses containing user data, tokens, or session state. New API or UI endpoints inherit `no-store` from the middleware. New static assets must use `asset_hashes()` for cache-busting.

---

## 13. Timing Side-Channels

**Pattern:** Ensure every authentication/authorization code path takes the same amount of time regardless of whether the input is valid - both at the comparison level and the execution-flow level.

### Constant-time comparison

Use `crypto::constant_time::constant_time_eq` / `constant_time_str_eq` (wraps `subtle::ConstantTimeEq`) for all security-sensitive comparisons. Never use `==` on secrets.

**Where it is applied:**
- PKCE verifier vs. challenge (`crypto/pkce.rs`)
- Redirect URI matching (`routes/authorize.rs`, `routes/auth.rs`)
- Client ID binding on auth codes and refresh tokens (`routes/token.rs`)
- CSRF token verification (`middleware/csrf.rs`)

### User enumeration prevention

When a login attempt targets a non-existent user, the server must still burn the same time as a real password verification. Otherwise an attacker can distinguish "user not found" from "wrong password" by measuring response time.

**Implementation:** `crypto::password::dummy_verify()` - runs Argon2id against a pre-computed dummy hash so the timing profile matches a real verification.

### Consistent error responses

Authentication failures must return the same HTTP status and response structure regardless of the failure reason (unknown user, wrong password, locked account). Only internal logs may distinguish failure causes.

**Rule:** Every new comparison involving secrets or user-supplied security values must use `constant_time_eq`/`constant_time_str_eq`. Every new authentication path must call `dummy_verify()` when the target entity does not exist. Never expose the failure reason to the client beyond a generic error message.

---

## 14. CORS

**Pattern:** Default-deny - no cross-origin access unless explicitly configured. Never use wildcards.

- **Default:** Empty origin list = no cross-origin requests allowed
- **Configuration:** Explicit allowlist via `CORS_ALLOWED_ORIGINS` (comma-separated)
- **Methods:** Only `GET` and `POST` - no `PUT`, `DELETE`, `PATCH`
- **Headers:** Only `Authorization` and `Content-Type`
- **Preflight cache:** 1 hour (`max_age: 3600s`)
- **No wildcard (`*`):** Origins are parsed into a strict `AllowOrigin::list`

**Rule:** Never use `AllowOrigin::any()`. New methods or headers require explicit addition to `build_cors_layer()`. Every origin in `CORS_ALLOWED_ORIGINS` must be a full origin (`https://app.example.com`), never a pattern or wildcard.

---

## 15. Output Escaping (XSS Prevention)

**Pattern:** All user-controlled values must be HTML-escaped before rendering. Never build HTML from raw user input.

- **Tera templates:** Autoescape is enabled by default for `.html` templates - all `{{ variable }}` expressions are escaped automatically
- **Manual HTML outside templates:** Use `tera::escape_html()` before interpolating into HTML strings (e.g. `AppError::into_response` in `errors.rs`)
- **Never use `| safe`** in Tera templates on user-supplied values - it bypasses autoescape

**Rule:** Never construct HTML responses with `format!()` using unescaped user input. If rendering outside Tera, always call `tera::escape_html()`. Never mark user-controlled template variables as `| safe`.

---

## 16. Redacted Output

**Pattern:** Never leak secrets, internal state, or distinguishing details in logs, error responses, or debug output.

### Logs

Log security-relevant events with structured fields (`event`, `ip`, `email`, `client_id`) but never log:
- Passwords, client secrets, or full token values - log the identifier (`client_id`, `user_id`) or at most a truncated prefix / token family
- Full stack traces in production (use `tracing::error!` with a summary message)
- Database error details to the client - log them server-side, return `"Internal server error"`

### Error responses

The `AppError` enum separates internal detail from client-facing output:
- `AppError::Internal(msg)` - logs `msg`, returns only `"Internal server error"`
- `AppError::Database(e)` - logs the sqlx error, returns only `"Internal server error"`
- `AppError::Unauthorized(_)` - always returns `"Unauthorized"`, never the reason

Never include field names, SQL errors, or stack traces in HTTP responses.

### Debug trait

Implement `Debug` manually for types that hold secrets. Replace sensitive fields with `[REDACTED]`:
```rust
.field("secret_field", &"[REDACTED]")
```
If a struct has no sensitive fields (like `AppConfig` after removing admin credentials), a derived `#[derive(Debug)]` is sufficient.

**Rule:** Every new log statement must be reviewed for secret leakage. Every new error variant must return a generic message to the client. Every struct holding secrets must implement `Debug` manually with `[REDACTED]` fields.

---

## Checklist for New Features

Before merging, verify:

- [ ] No `unsafe` code or `unchecked` methods introduced
- [ ] No `expect()`/`unwrap()` in request-handling code paths
- [ ] All new user input fields have explicit length limits
- [ ] New endpoints inherit `RequestBodyLimitLayer`
- [ ] No `HashMap` populated from untrusted input
- [ ] New tokens/JWTs follow the pinned algorithm + full claim validation pattern
- [ ] State-changing endpoints are CSRF-protected
- [ ] New in-memory stores use `TrackedStore<V>` with a defined capacity
- [ ] Database queries are parameterized
- [ ] Secret comparisons use constant-time operations
- [ ] No `'unsafe-inline'` or `'unsafe-eval'` added to CSP
- [ ] New external origins go through `build_csp()`, not hardcoded
- [ ] User-controlled values in HTML escaped via Tera autoescape or `tera::escape_html()`
- [ ] No `| safe` on user-supplied template variables
- [ ] No `AllowOrigin::any()` - new origins go through `CORS_ALLOWED_ORIGINS`
- [ ] No secrets (passwords, tokens, client secrets) in log output
- [ ] Error responses return generic messages, details only in server logs
- [ ] Structs holding secrets implement `Debug` with `[REDACTED]`
- [ ] New token types use CSPRNG generation + SHA-256 hashed storage + configurable expiry
- [ ] No plaintext tokens stored in the database
