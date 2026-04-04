# GT Id - OIDC Integration Guide

## Architecture

GT Id runs on **two ports** (always localhost):
- **UI** (`UI_LISTEN_PORT`, default `3001`) - Login, Consent, Admin Panel
- **API** (`API_LISTEN_PORT`, default `3000`) - OIDC Endpoints

## Development

```bash
# Linux / macOS
bash dev/run.sh

# Windows (PowerShell)
.\dev\run.ps1
```

Starts Mailpit (if not already running) and runs the application. Mailpit UI is available at `http://localhost:8025`.

## OIDC Discovery

```
GET http://localhost:3000/.well-known/openid-configuration
```

Returns all endpoints automatically. Any OIDC-compliant library can work with this.

## JWKS (JSON Web Key Set)

```
GET http://localhost:3000/jwks
```

Returns the public Ed25519 key for **token verification**. The key is generated in memory on each start - after a restart the key and `kid` (Key ID) change. OIDC clients should therefore not cache the JWKS endpoint indefinitely.

**Fetch JWKS:**
```bash
curl -s http://localhost:3000/jwks
```

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "...",
      "x": "..."
    }
  ]
}
```

**Decode token payload (without signature verification):**
```bash
# id_token or access_token - payload is the middle part (Base64)
echo "$ID_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

## Authentication (Authorization Code Flow + PKCE)

### 0. Create a Client

Clients are managed through the admin panel: `http://localhost:3001/admin/clients/create`

When creating a client, `client_id`, `client_secret`, `client_redirect_uri` and optionally `client_post_logout_redirect_uri` are specified. The secret is stored hashed with Argon2id.

### 1. Get Authorize URL

```bash
AUTH=$(curl -s "http://localhost:3000/authorize-url?client_id=my-app")
AUTHORIZE_URL=$(echo "$AUTH" | jq -r .authorize_url)
CODE_VERIFIER=$(echo "$AUTH" | jq -r .code_verifier)
```

Optionally with scope:
```bash
AUTH=$(curl -s "http://localhost:3000/authorize-url?client_id=my-app&scope=openid+email+profile")
```

Response:
```json
{
  "authorize_url": "http://localhost:3001/authorize?response_type=code&client_id=...&redirect_uri=...&scope=openid&state=...&code_challenge=...&code_challenge_method=S256&nonce=...",
  "code_verifier": "..."
}
```

Redirect the user to `AUTHORIZE_URL`. The user logs in and gives consent. Then redirect to:
```
http://localhost:8080/callback?code={AUTH_CODE}&state={STATE}
```

### 2. Exchange Code for Token

**Option A - client_secret_post (form-encoded):**
```bash
curl -X POST http://localhost:3000/token \
  -d grant_type=authorization_code \
  -d code={AUTH_CODE} \
  -d redirect_uri=http://localhost:8080/callback \
  -d client_id=my-app \
  -d client_secret=a-secure-secret \
  -d code_verifier={CODE_VERIFIER}
```

**Option B - client_secret_basic (HTTP Basic Auth):**
```bash
curl -X POST http://localhost:3000/token \
  -u "my-app:a-secure-secret" \
  -d grant_type=authorization_code \
  -d code={AUTH_CODE} \
  -d redirect_uri=http://localhost:8080/callback \
  -d code_verifier={CODE_VERIFIER}
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "id_token": "eyJ...",
  "refresh_token": "...",
  "scope": "openid email profile"
}
```

The `id_token` contains among others:
```json
{
  "sub": "user-id",
  "email": "user@example.com",
  "name": "Max Mustermann",
  "roles": ["admin", "member"]
}
```

### 3. Fetch Userinfo

```bash
curl -H "Authorization: Bearer {ACCESS_TOKEN}" http://localhost:3000/userinfo
```

```json
{
  "sub": "user-id",
  "email": "user@example.com",
  "name": "Max Mustermann",
  "roles": ["admin", "member"]
}
```

### 4. Refresh Token

```bash
curl -X POST http://localhost:3000/token \
  -d grant_type=refresh_token \
  -d refresh_token={REFRESH_TOKEN} \
  -d client_id=my-app \
  -d client_secret=a-secure-secret
```

Note: The refresh response returns `access_token`, `refresh_token`, `expires_in` and `scope` but **no `id_token`** (per OIDC spec, `id_token` is only issued on the initial authorization_code exchange).

### 5. Revoke Token (RFC 7009)

```bash
curl -X POST http://localhost:3000/revoke \
  -u "my-app:a-secure-secret" \
  -d token={REFRESH_TOKEN}
```

Optionally specify `token_type_hint=refresh_token`. Always returns `200 OK`, even if the token was invalid or already revoked.

## Integration

GT Id generates a new Ed25519 key on each start. Frameworks typically cache the JWKS endpoint for up to 12 hours. After a GT Id restart, token validation will fail because the `kid` (Key ID) no longer matches. Make sure to reduce the refresh interval for /jwks accordingly.

## .env Configuration (Roles)

```env
ROLES=member           # Comma-separated, e.g. ROLES=member,editor,viewer
                       # "admin" is always included and doesn't need to be specified
```

## .env Configuration (SMTP / Email Queue)

GT Id includes a background email queue that processes pending emails every 30 seconds. Emails are sent via SMTP. If `SMTP_HOST` is not set, email sending is disabled and the worker exits silently.

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587                      # Default: 587
SMTP_USERNAME=user@example.com
SMTP_PASSWORD=secret
SMTP_FROM=noreply@example.com      # Default: noreply@localhost
SMTP_STARTTLS=true                 # Default: true
```

**Backoff on failure:** If an email fails to send, it is retried with exponential backoff (60s, 120s, 240s, ... capped at 1 hour). The error is stored in `last_error` for inspection.

**Local testing with Mailpit:**
```bash
docker compose -f dev/mailpit/docker-compose.yml up -d
```
Then set `SMTP_HOST=localhost`, `SMTP_PORT=1025`, `SMTP_STARTTLS=false`. Emails appear in the Mailpit UI at `http://localhost:8025`.
