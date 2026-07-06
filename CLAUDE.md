# CLAUDE.md

Guidance for AI agents working in this repository.

## What this is

**Loupe** — an SSO **relying party / service provider** tester, written in Go.
It drives
logins against an external SSO server over **OpenID Connect** and **SAML 2.0**,
then shows exactly what was sent and received. Core value is *inspection*:
per-attempt captured HTTP exchanges, decoded artifacts, and granular validation
results, all persisted as browsable **history**. Users configure named
**profiles** and can edit every request parameter on a **review** screen before
each login. It is a single-user local tool (no auth on the app itself).

Module path: `github.com/default23/loupe`. Single binary; all templates and
static assets are `embed`ded.

## Build / run / test

Go is **1.26** and may not be on `PATH` in this environment — it lives at
`~/sdk/go1.26.4/bin/go`. Prefix commands with `export PATH=$PATH:$HOME/sdk/go1.26.4/bin`.

```sh
# Postgres backend (default)
docker compose up -d db                       # Postgres on :5432 (user/pass/db = loupe)
export POSTGRES_DSN="postgres://loupe:loupe@localhost:5432/loupe?sslmode=disable"
export MASTER_KEY="any-passphrase"   # required to store secrets
go run ./cmd/loupe                           # serves on :8080

# SQLite backend (embedded, no external DB)
export DB_DRIVER=sqlite SQLITE_PATH=loupe.db MASTER_KEY="any-passphrase"
go run ./cmd/loupe

go build ./... && go vet ./... && go test ./...
```

Migrations run automatically on startup (goose, embedded). The full test suite
needs **no** database — `internal/oidc` and `internal/saml` run against
in-process mock providers with real signed tokens/responses. Only manual
end-to-end runs of the web app need a database (Postgres or a throwaway SQLite file).

## Configuration (env)

`LISTEN_ADDR` (`:8080`), `BASE_URL` (derives `/oidc/callback` and
`/saml/acs`, must match what's registered at the IdP), `MASTER_KEY` (any
passphrase, hashed to an AES-256 key). Storage backend is chosen by `DB_DRIVER`:
`postgres` (default) reads `POSTGRES_DSN`; `sqlite` reads `SQLITE_PATH`
(default `loupe.db`, file-backed, no external service). See
`internal/config/config.go` — parsed with `github.com/caarlos0/env/v11` via
`env`/`envDefault` struct tags. The `docker compose --profile standalone up
loupe` service runs the SQLite backend with a persistent `/data` volume.

## Architecture (layered; higher imports lower, no cycles)

```
cmd/loupe ─ wires everything, graceful shutdown
internal/
  config      env config (DB_DRIVER selects postgres|sqlite)
  store       database/sql wrapper (dialect-aware $N rebind) + embedded goose
              migrations (migrations/{postgres,sqlite}/*.sql); pgx stdlib and
              modernc.org/sqlite drivers
  crypto      AES-256-GCM (Cipher) + GenerateSPKeyPair (RSA self-signed)
  inspect     capture model: Exchange, Validation, Recorder
  httpx       capturing http.Client: injects headers by phase, records exchanges
  profile     Profile domain + Repo (CRUD), discovery/metadata import, SP metadata, export
  inflight    short-lived login state (single-use, correlates callback/ACS)
  history     Attempt + Details + Exchanges persistence
  oidc        OIDC RP flow (uses httpx client + go-oidc verifier)
  saml        SAML SP flow (uses gosaml2 + goxmldsig)
  web         handlers + html/template + HTMX (templates/, static/)
```

Key libraries: `jackc/pgx/v5` (stdlib driver), `modernc.org/sqlite` (pure-Go),
`pressly/goose/v3`, `coreos/go-oidc/v3` + `golang.org/x/oauth2`,
`russellhaering/gosaml2` + `goxmldsig`, `beevik/etree`.

## Data model (one migration per dialect: `internal/store/migrations/{postgres,sqlite}/00001_init.sql`)

Both backends go through `database/sql` behind `store.DB`, which rewrites `$N`
placeholders to `?` for SQLite (reordering args, since some queries reference
`$1` after `$2`). Queries pass `time.Now()` from Go rather than SQL `now()` so
they are dialect-neutral. Postgres types map to SQLite as: `JSONB`→`TEXT`,
`BYTEA`→`BLOB`, `TIMESTAMPTZ`→`TIMESTAMP`, `BIGINT … IDENTITY`→`INTEGER … AUTOINCREMENT`.
When adding schema changes, add a **new** `NNNNN_*.sql` to **both** dialect dirs.

- `profiles` — `config` JSONB (non-secret), `secrets` BYTEA (AES-GCM JSON blob),
  `custom_headers` JSONB. Secret material (client_secret, SP private key, secret
  header values) lives **only** in the encrypted blob; secret header values are
  stripped from `custom_headers` and keyed by index inside `secrets` (see
  `profile.Repo.encode`).
- `in_flight_logins` — PK `state`; correlates by `state` (OIDC/SAML RelayState)
  and by `request_id` (SAML `InResponseTo`). Rows are single-use (`DELETE …
  RETURNING` in `inflight.Take`).
- `login_attempts` (+ `profile_name` snapshot), `attempt_details`
  (params_used / artifacts / validations JSONB), `http_exchanges`.

Add schema changes as a **new** `NNNNN_*.sql` goose file in **both**
`migrations/postgres/` and `migrations/sqlite/`, never edit the applied one.

## How the flows work

- **Review → Start → Callback/ACS.** `GET /login/{id}` renders editable params
  (fresh state/nonce/PKCE for OIDC; AuthnRequest fields + XML preview for SAML).
  `POST /login/{id}/start` persists in-flight state and redirects/POSTs to the
  IdP. The IdP returns to `GET /oidc/callback` or `POST /saml/acs`, which runs
  the flow, persists an attempt, and redirects to `/history/{attemptId}` (the
  result page, shared with history detail).
- **OIDC** (`internal/oidc`): manual token exchange (full control over client
  auth method), ID-token validated via `go-oidc` verifier against the JWKS
  (signature, iss, aud, exp) plus a separate nonce check; userinfo call.
- **SAML** (`internal/saml`): `gosaml2` builds/signs the AuthnRequest and
  validates the response; audience/time come from `WarningInfo`, `InResponseTo`
  is checked manually against the stored request ID.

## Conventions & gotchas (learned the hard way)

- **Custom headers apply only to server-to-server calls** (token/userinfo/jwks/
  discovery/metadata), never to browser redirects. SAML logins make no
  server-to-server calls, so their `http_exchanges` are empty — expected.
- **Two header sources:** the profile's persisted `CustomHeaders`, plus
  **per-login "session headers"** entered on the review page. Session headers are
  parsed with `parseHeaders` (same `hdr[i].*` field names), stored in the
  in-flight record under `Params["session_headers"]`, and at the OIDC callback
  are appended after the profile headers (so same name+phase overrides). They
  only affect OIDC (SAML has no outbound calls). See `web/login.go`.
- **JSON/XML syntax highlighting** is a self-contained `static/highlight.js`
  (no deps) applied to `<pre data-lang="json|xml|auto">`; it re-escapes text
  before setting innerHTML (XSS-safe). XML shown in the UI is indented via an
  etree **copy** — never indent the real signed/sent AuthnRequest doc.
- **Master key rotation invalidates existing secrets.** A profile's `secrets`
  blob only decrypts with the key that wrote it; a new key makes `profile.Get`
  fail for profiles that have secrets. Decrypt failure surfaces a clear error.
- **SAML response signing in tests/mocks: sign the whole `Response` envelope,
  not just the assertion.** goxmldsig `findSignature` traverses recursively, so
  a nested assertion-only signature makes response-level validation pick the
  wrong element and fail. See `internal/saml/saml_test.go` and the mock in the
  scratchpad for the working pattern.
- **SP metadata XML**: the `ds` namespace belongs on `KeyInfo` (see
  `profile/spmeta.go`), not on `X509Certificate`.
- **Templates**: each page is parsed as `base.html` + one page file, executed
  via `ExecuteTemplate(w, "base.html", data)` (`web.Server.render`). Pages define
  `{{block "content"}}`. Helpers registered in `funcMap`: `join`, `contains`,
  `seq`, `add`, `prettyJSON`, `asString`. Nullable `*int64` (e.g. `Attempt.ProfileID`)
  must be rendered via helper methods (`HasProfile`, `ProfileIDVal`) — a raw
  pointer prints its address.
- **Routing** is stdlib `net/http.ServeMux` (Go 1.22 method+pattern). More
  specific static routes (`/profiles/import`) coexist with `/profiles/{id}`.
- **Secrets are never exported** (`profile.ToExport` strips them) and are masked
  in listings; the edit form round-trips them via form fields.
- Run `gofmt -w internal cmd` after edits (`gofmt … ./...` globs are invalid).

## Manual end-to-end testing

A mock IdP (OIDC discovery/token/jwks/userinfo + SAML SSO with signed responses)
and Python drivers were used during development; recreate them under the
scratchpad if needed. The pattern: create a profile pointing at the mock, drive
`GET /login/{id}` → `POST /start` → follow redirects to the callback/ACS →
assert on the `/history/{id}` result page. The signed-response construction in
`internal/saml/saml_test.go` is the reference for building a valid SAMLResponse.

## Not yet implemented (possible extensions)

OIDC implicit/hybrid, client-credentials/device flows, refresh on the result
page; SAML IdP-initiated SSO and Single Logout; built-in HTTPS listener;
per-profile `EXTERNAL_BASE_URL` override; multi-user auth.
