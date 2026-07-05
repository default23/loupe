// Package inflight persists short-lived login state that correlates a started
// login with its callback (OIDC) or ACS POST (SAML).
package inflight

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when no matching in-flight record exists.
var ErrNotFound = errors.New("in-flight login not found or expired")

// Record is the persisted state of an in-progress login.
type Record struct {
	State        string
	ProfileID    int64
	Protocol     string
	CodeVerifier string
	Nonce        string
	RelayState   string
	RequestID    string
	Params       map[string]any
	ExpiresAt    time.Time
}

// Repo persists in-flight logins.
type Repo struct {
	pool *pgxpool.Pool
}

// NewRepo builds an in-flight repository.
func NewRepo(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

// Save inserts (or replaces) an in-flight record.
func (r *Repo) Save(ctx context.Context, rec *Record) error {
	params, _ := json.Marshal(rec.Params)
	_, err := r.pool.Exec(ctx,
		`INSERT INTO in_flight_logins
		   (state, profile_id, protocol, code_verifier, nonce, relay_state, request_id, customized_params, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (state) DO UPDATE SET
		   profile_id = EXCLUDED.profile_id,
		   protocol = EXCLUDED.protocol,
		   code_verifier = EXCLUDED.code_verifier,
		   nonce = EXCLUDED.nonce,
		   relay_state = EXCLUDED.relay_state,
		   request_id = EXCLUDED.request_id,
		   customized_params = EXCLUDED.customized_params,
		   expires_at = EXCLUDED.expires_at`,
		rec.State, rec.ProfileID, rec.Protocol, rec.CodeVerifier, rec.Nonce,
		rec.RelayState, rec.RequestID, params, rec.ExpiresAt)
	return err
}

// Take fetches a record by state and deletes it (single-use), enforcing expiry.
func (r *Repo) Take(ctx context.Context, state string) (*Record, error) {
	return r.takeBy(ctx, "state", state)
}

// TakeByRequestID fetches and deletes a SAML record by AuthnRequest ID.
func (r *Repo) TakeByRequestID(ctx context.Context, requestID string) (*Record, error) {
	return r.takeBy(ctx, "request_id", requestID)
}

func (r *Repo) takeBy(ctx context.Context, col, val string) (*Record, error) {
	var (
		rec    Record
		params []byte
	)
	// DELETE ... RETURNING makes the lookup single-use and atomic.
	err := r.pool.QueryRow(ctx,
		`DELETE FROM in_flight_logins WHERE `+col+` = $1
		 RETURNING state, profile_id, protocol, code_verifier, nonce, relay_state, request_id, customized_params, expires_at`,
		val).
		Scan(&rec.State, &rec.ProfileID, &rec.Protocol, &rec.CodeVerifier, &rec.Nonce,
			&rec.RelayState, &rec.RequestID, &params, &rec.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if time.Now().After(rec.ExpiresAt) {
		return nil, ErrNotFound
	}
	_ = json.Unmarshal(params, &rec.Params)
	return &rec, nil
}

// DeleteExpired removes stale records (housekeeping).
func (r *Repo) DeleteExpired(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM in_flight_logins WHERE expires_at < now()`)
	return err
}
