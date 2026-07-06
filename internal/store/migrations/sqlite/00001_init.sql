-- +goose Up

-- Named configuration profiles: one per protocol target.
CREATE TABLE profiles (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL,
    protocol       TEXT NOT NULL CHECK (protocol IN ('oidc', 'saml')),
    config         TEXT NOT NULL DEFAULT '{}',   -- non-secret protocol settings (JSON)
    secrets        BLOB,                          -- AES-GCM encrypted JSON blob
    custom_headers TEXT NOT NULL DEFAULT '[]',    -- [{name, value, applies_to:[...]}] (JSON)
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Short-lived state correlating a started login with its callback/ACS.
CREATE TABLE in_flight_logins (
    state             TEXT PRIMARY KEY,
    profile_id        INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    protocol          TEXT NOT NULL,
    code_verifier     TEXT,        -- OIDC PKCE
    nonce             TEXT,        -- OIDC
    relay_state       TEXT,        -- SAML
    request_id        TEXT,        -- SAML AuthnRequest ID (InResponseTo correlation)
    customized_params TEXT NOT NULL DEFAULT '{}',
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at        TIMESTAMP NOT NULL
);
CREATE INDEX in_flight_logins_request_id_idx ON in_flight_logins (request_id);

-- One row per login attempt (started/success/failed).
CREATE TABLE login_attempts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id        INTEGER REFERENCES profiles(id) ON DELETE SET NULL,
    profile_name      TEXT NOT NULL,   -- snapshot, survives profile deletion
    protocol          TEXT NOT NULL,
    status            TEXT NOT NULL,   -- started|success|failed
    external_base_url TEXT,
    error             TEXT,
    summary           TEXT NOT NULL DEFAULT '{}',  -- subject, issuer, counts (JSON)
    started_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at       TIMESTAMP
);
CREATE INDEX login_attempts_profile_idx ON login_attempts (profile_id);
CREATE INDEX login_attempts_started_idx ON login_attempts (started_at DESC);

-- Decoded protocol artifacts and validation outcomes for an attempt.
CREATE TABLE attempt_details (
    attempt_id  INTEGER PRIMARY KEY REFERENCES login_attempts(id) ON DELETE CASCADE,
    params_used TEXT NOT NULL DEFAULT '{}',   -- final (possibly edited) params (JSON)
    artifacts   TEXT NOT NULL DEFAULT '{}',   -- tokens/claims/assertion/xml (JSON)
    validations TEXT NOT NULL DEFAULT '[]'     -- [{name, ok, detail}] (JSON)
);

-- Captured server-to-server HTTP exchanges for an attempt.
CREATE TABLE http_exchanges (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id   INTEGER REFERENCES login_attempts(id) ON DELETE CASCADE,
    seq          INTEGER NOT NULL,
    phase        TEXT,           -- discovery|token|userinfo|jwks|metadata
    method       TEXT,
    url          TEXT,
    req_headers  TEXT,
    req_body     TEXT,
    status       INTEGER,
    resp_headers TEXT,
    resp_body    TEXT,
    duration_ms  INTEGER,
    ts           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX http_exchanges_attempt_idx ON http_exchanges (attempt_id, seq);

-- +goose Down
DROP TABLE IF EXISTS http_exchanges;
DROP TABLE IF EXISTS attempt_details;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS in_flight_logins;
DROP TABLE IF EXISTS profiles;
