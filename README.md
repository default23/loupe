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
- **Two storage backends:** external **PostgreSQL** (default) or an embedded,
  file-backed **SQLite** database bundled into the container — no external
  service required.

## Screenshots

**Login history** — every attempt, filterable by profile, protocol and status.

![Login history](docs/screenshots/history.png)

**Profiles** — named OIDC/SAML configurations.

![Profiles](docs/screenshots/profiles.png)

**Pre-login review** — inspect and edit every request parameter (including
freshly generated `state` / `nonce` / PKCE) before the login starts.

![OIDC review screen](docs/screenshots/review-oidc.png)

**OIDC inspection** — validations, decoded ID-token claims and headers,
userinfo, the raw token response, the exact parameters used, and the captured
server-to-server HTTP exchanges.

![OIDC inspection result](docs/screenshots/result-oidc.png)

**SAML inspection** — signature/audience/time/`InResponseTo` validations, the
decoded assertion and attributes, and the syntax-highlighted `SAMLResponse` XML.

![SAML inspection result](docs/screenshots/result-saml.png)

## Quick start (local)

The fastest way to try Loupe is the embedded **SQLite** backend — no database to
start:

```sh
DB_DRIVER=sqlite SQLITE_PATH=loupe.db MASTER_KEY=any-passphrase go run ./cmd/loupe
```

Or run against **PostgreSQL** (the default backend):

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

## Run with Docker

A prebuilt multi-arch image (`linux/amd64` and `linux/arm64`) is published to
Docker Hub as [`default23/loupe`](https://hub.docker.com/r/default23/loupe).
`latest` always tracks the `master` branch; released versions are tagged (e.g.
`default23/loupe:v1.2.3`).

Loupe needs a `MASTER_KEY` and a storage backend. The simplest deployment uses
the **embedded SQLite** database — no external service. Mount a volume at `/data`
so the database survives container restarts:

```sh
docker run --rm -p 8080:8080 \
  -e DB_DRIVER=sqlite \
  -e SQLITE_PATH="/data/loupe.db" \
  -e MASTER_KEY="any-passphrase" \
  -e BASE_URL="http://localhost:8080" \
  -v loupe_data:/data \
  default23/loupe:latest
```

Or run it against an existing **PostgreSQL** (the default backend):

```sh
docker run --rm -p 8080:8080 \
  -e POSTGRES_DSN="postgres://loupe:loupe@host.docker.internal:5432/loupe?sslmode=disable" \
  -e MASTER_KEY="any-passphrase" \
  -e BASE_URL="http://localhost:8080" \
  default23/loupe:latest
```

Migrations run automatically on startup, so no manual DB setup is needed (SQLite
creates the file itself; Postgres just needs an empty database).

### docker-compose

**SQLite (standalone, no database service).** The simplest setup — a single
container with a persistent volume. Save it as `compose.yaml` and run
`docker compose up`:

```yaml
services:
  loupe:
    image: default23/loupe:latest
    ports:
      - "8080:8080"
    environment:
      LISTEN_ADDR: ":8080"
      BASE_URL: "http://localhost:8080"
      DB_DRIVER: "sqlite"
      SQLITE_PATH: "/data/loupe.db"
      MASTER_KEY: "change-me"   # any non-empty passphrase; keep it stable
    volumes:
      - loupe_data:/data

volumes:
  loupe_data:
```

**PostgreSQL.** Brings up Loupe together with its database:

```yaml
services:
  loupe:
    image: default23/loupe:latest
    ports:
      - "8080:8080"
    environment:
      LISTEN_ADDR: ":8080"
      BASE_URL: "http://localhost:8080"
      POSTGRES_DSN: "postgres://loupe:loupe@db:5432/loupe?sslmode=disable"
      MASTER_KEY: "change-me"   # any non-empty passphrase; keep it stable
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: loupe
      POSTGRES_PASSWORD: loupe
      POSTGRES_DB: loupe
    volumes:
      - loupe_pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U loupe"]
      interval: 5s
      timeout: 3s
      retries: 10

volumes:
  loupe_pgdata:
```

To pin a specific release, replace `default23/loupe:latest` with a version tag.
Keep `MASTER_KEY` stable across restarts — rotating it makes previously stored
secrets undecryptable.

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
| `DB_DRIVER` | Storage backend: `postgres` (default) or `sqlite` |
| `POSTGRES_DSN` | PostgreSQL DSN (when `DB_DRIVER=postgres`) |
| `SQLITE_PATH` | SQLite database file path (when `DB_DRIVER=sqlite`, default `loupe.db`) |
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
- `internal/store` — dialect-aware `database/sql` wrapper (PostgreSQL or SQLite)
  + embedded goose migrations.
- `internal/crypto` — AES-GCM secret encryption, SP cert/key generation.
- `internal/httpx` — capturing HTTP transport (custom headers + exchange log).
- `internal/inspect` — capture model (exchanges, validations).
- `internal/profile` — profile CRUD, import/export, discovery/metadata import.
- `internal/inflight` — short-lived login-correlation state.
- `internal/oidc` / `internal/saml` — protocol implementations.
- `internal/history` — attempts, details, exchanges persistence.
- `internal/web` — HTML UI (Go templates + HTMX) and HTTP endpoints.
