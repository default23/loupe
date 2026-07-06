-- +goose Up
-- +goose StatementBegin

-- Named configuration profiles: one per protocol target.
CREATE TABLE profiles (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name           TEXT NOT NULL,
    protocol       TEXT NOT NULL CHECK (protocol IN ('oidc', 'saml')),
    config         JSONB NOT NULL DEFAULT '{}'::jsonb,   -- non-secret protocol settings
    secrets        BYTEA,                                 -- AES-GCM encrypted JSON blob
    custom_headers JSONB NOT NULL DEFAULT '[]'::jsonb,    -- [{name, value, applies_to:[...]}]
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Short-lived state correlating a started login with its callback/ACS.
CREATE TABLE in_flight_logins (
    state             TEXT PRIMARY KEY,
    profile_id        BIGINT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    protocol          TEXT NOT NULL,
    code_verifier     TEXT,        -- OIDC PKCE
    nonce             TEXT,        -- OIDC
    relay_state       TEXT,        -- SAML
    request_id        TEXT,        -- SAML AuthnRequest ID (InResponseTo correlation)
    customized_params JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL
);
CREATE INDEX in_flight_logins_request_id_idx ON in_flight_logins (request_id);

-- One row per login attempt (started/success/failed).
CREATE TABLE login_attempts (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    profile_id        BIGINT REFERENCES profiles(id) ON DELETE SET NULL,
    profile_name      TEXT NOT NULL,   -- snapshot, survives profile deletion
    protocol          TEXT NOT NULL,
    status            TEXT NOT NULL,   -- started|success|failed
    external_base_url TEXT,
    error             TEXT,
    summary           JSONB NOT NULL DEFAULT '{}'::jsonb,  -- subject, issuer, counts
    started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at       TIMESTAMPTZ
);
CREATE INDEX login_attempts_profile_idx ON login_attempts (profile_id);
CREATE INDEX login_attempts_started_idx ON login_attempts (started_at DESC);

-- Decoded protocol artifacts and validation outcomes for an attempt.
CREATE TABLE attempt_details (
    attempt_id  BIGINT PRIMARY KEY REFERENCES login_attempts(id) ON DELETE CASCADE,
    params_used JSONB NOT NULL DEFAULT '{}'::jsonb,   -- final (possibly edited) params
    artifacts   JSONB NOT NULL DEFAULT '{}'::jsonb,   -- tokens/claims/assertion/xml
    validations JSONB NOT NULL DEFAULT '[]'::jsonb     -- [{name, ok, detail}]
);

-- Captured server-to-server HTTP exchanges for an attempt.
CREATE TABLE http_exchanges (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    attempt_id   BIGINT REFERENCES login_attempts(id) ON DELETE CASCADE,
    seq          INT NOT NULL,
    phase        TEXT,           -- discovery|token|userinfo|jwks|metadata
    method       TEXT,
    url          TEXT,
    req_headers  JSONB,
    req_body     TEXT,
    status       INT,
    resp_headers JSONB,
    resp_body    TEXT,
    duration_ms  BIGINT,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX http_exchanges_attempt_idx ON http_exchanges (attempt_id, seq);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS http_exchanges;
DROP TABLE IF EXISTS attempt_details;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS in_flight_logins;
DROP TABLE IF EXISTS profiles;
-- +goose StatementEnd
