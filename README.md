# Loupe — a forensic lens on single sign-on

Loupe tests your SSO server. It always acts as a **relying party / service
provider** and supports **OpenID Connect** and **SAML 2.0**. Beyond performing
logins, it shows exactly what was sent to and received from the provider — every
claim, assertion, and signature — lets you customize protocol parameters before
starting, stores named configuration **profiles**, and keeps a searchable
**login history**.

## Features

- **OIDC (relying party):** Authorization Code + PKCE, token exchange, ID-token
  validation (signature via JWKS, `iss` / `aud` / `exp` / `nonce`), userinfo.
- **SAML 2.0 (service provider, SP-initiated):** builds and optionally signs the
  `AuthnRequest` (HTTP-Redirect and HTTP-POST bindings), validates the
  `SAMLResponse` (signature, audience, time conditions, `InResponseTo`),
  decrypts encrypted assertions.
- **Profiles:** named configs per protocol, with OIDC discovery import, SAML IdP
  metadata import, automatic SP certificate/key generation, SP metadata export,
  and JSON export/import.
- **Pre-login review:** every request parameter is shown and editable before the
  login starts.
- **Custom request headers:** injected into the app's server-to-server calls to
  the provider (token, userinfo, jwks, discovery, metadata phases).
- **Inspection & history:** each attempt records the parameters used, decoded
  artifacts (tokens/claims/assertion/XML), granular validation results, and the
  full captured HTTP exchanges — browsable later from History.
- **Secrets encrypted at rest** with AES-256-GCM.

## Quick start (local)

```sh
# 1. Start PostgreSQL
docker compose up -d db

# 2. Configure
cp .env.example .env
# set any passphrase in .env as MASTER_KEY (hashed to an AES-256 key)

# 3. Run (loads .env into the environment first)
export $(grep -v '^#' .env | xargs) && go run ./cmd/loupe
```

Open http://localhost:8080, create a profile, and start a login.

### Callback / ACS URLs

Register these at your identity provider (derived from `BASE_URL`):

- OIDC redirect URI: `<base>/oidc/callback`
- SAML ACS URL: `<base>/saml/acs`
- SAML SP metadata: `<base>/profiles/{id}/saml/metadata`

If your provider requires a public HTTPS callback, point `BASE_URL`
at a tunnel (e.g. ngrok) or reverse proxy.

## Configuration

All settings come from environment variables; see `.env.example`.

| Variable | Purpose |
| --- | --- |
| `LISTEN_ADDR` | HTTP bind address (default `:8080`) |
| `BASE_URL` | Externally reachable base URL |
| `POSTGRES_DSN` | PostgreSQL DSN |
| `MASTER_KEY` | passphrase for encrypting secrets (hashed to an AES-256 key) |

## Testing

```sh
go test ./...
```

The `internal/oidc` and `internal/saml` packages contain end-to-end tests that
run against in-process mock providers (signed ID tokens / signed SAML
responses), covering the full validation logic without external services.

## Architecture

- `cmd/loupe` — entrypoint.
- `internal/config` — environment configuration.
- `internal/store` — PostgreSQL pool + embedded goose migrations.
- `internal/crypto` — AES-GCM secret encryption, SP cert/key generation.
- `internal/httpx` — capturing HTTP transport (custom headers + exchange log).
- `internal/inspect` — capture model (exchanges, validations).
- `internal/profile` — profile CRUD, import/export, discovery/metadata import.
- `internal/inflight` — short-lived login-correlation state.
- `internal/oidc` / `internal/saml` — protocol implementations.
- `internal/history` — attempts, details, exchanges persistence.
- `internal/web` — HTML UI (Go templates + HTMX) and HTTP endpoints.
