package history

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/default23/loupe/internal/inspect"
	"github.com/default23/loupe/internal/store"
)

// ErrNotFound is returned when an attempt does not exist.
var ErrNotFound = errors.New("attempt not found")

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

// Repo persists login attempts.
type Repo struct {
	db *store.DB
}

// NewRepo builds a history repository.
func NewRepo(db *store.DB) *Repo { return &Repo{db: db} }

// Start inserts a new attempt in the "started" state, filling ID and StartedAt.
func (r *Repo) Start(ctx context.Context, a *Attempt) error {
	summaryJSON, _ := json.Marshal(a.Summary)
	now := time.Now().UTC()
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO login_attempts (profile_id, profile_name, protocol, status, external_base_url, summary, started_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		a.ProfileID, a.ProfileName, a.Protocol, StatusStarted, a.ExternalBaseURL, summaryJSON, now).
		Scan(&a.ID)
	if err != nil {
		return err
	}
	a.StartedAt = now
	return nil
}

// Finish updates the terminal status, error, and summary of an attempt.
func (r *Repo) Finish(ctx context.Context, id int64, status, errMsg string, summary Summary) error {
	summaryJSON, _ := json.Marshal(summary)
	_, err := r.db.ExecContext(ctx,
		`UPDATE login_attempts
		    SET status = $2, error = $3, summary = $4, finished_at = $5
		  WHERE id = $1`,
		id, status, errMsg, summaryJSON, time.Now().UTC())
	return err
}

// SaveDetails upserts the decoded artifacts and validations for an attempt.
func (r *Repo) SaveDetails(ctx context.Context, attemptID int64, d Details) error {
	params, _ := json.Marshal(orEmptyObj(d.ParamsUsed))
	artifacts, _ := json.Marshal(orEmptyObj(d.Artifacts))
	validations, _ := json.Marshal(orEmptyArr(d.Validations))
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO attempt_details (attempt_id, params_used, artifacts, validations)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (attempt_id) DO UPDATE
		   SET params_used = EXCLUDED.params_used,
		       artifacts = EXCLUDED.artifacts,
		       validations = EXCLUDED.validations`,
		attemptID, params, artifacts, validations)
	return err
}

// SaveExchanges bulk-inserts captured HTTP exchanges for an attempt.
func (r *Repo) SaveExchanges(ctx context.Context, attemptID int64, exs []inspect.Exchange) error {
	if len(exs) == 0 {
		return nil
	}
	return r.db.WithTx(ctx, func(tx *store.Tx) error {
		for _, e := range exs {
			reqH, _ := json.Marshal(e.ReqHeaders)
			respH, _ := json.Marshal(e.RespHeaders)
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO http_exchanges
				   (attempt_id, seq, phase, method, url, req_headers, req_body, status, resp_headers, resp_body, duration_ms, ts)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
				attemptID, e.Seq, e.Phase, e.Method, e.URL, reqH, e.ReqBody, e.Status, respH, e.RespBody, e.DurationMS, e.Time); err != nil {
				return err
			}
		}
		return nil
	})
}

// List returns attempts matching the filter, newest first.
func (r *Repo) List(ctx context.Context, f Filter) ([]Attempt, error) {
	q := `SELECT id, profile_id, profile_name, protocol, status, external_base_url,
	             COALESCE(error, ''), summary, started_at, finished_at
	        FROM login_attempts`
	var conds []string
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("%s $%d", cond, len(args)))
	}
	if f.ProfileID != nil {
		add("profile_id =", *f.ProfileID)
	}
	if f.Protocol != "" {
		add("protocol =", f.Protocol)
	}
	if f.Status != "" {
		add("status =", f.Status)
	}
	if len(conds) > 0 {
		q += " WHERE " + joinAnd(conds)
	}
	q += " ORDER BY started_at DESC"
	if f.Limit > 0 {
		args = append(args, f.Limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Attempt
	for rows.Next() {
		a, err := scanAttempt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Get loads a full attempt: base record, details, and exchanges.
func (r *Repo) Get(ctx context.Context, id int64) (*FullAttempt, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT id, profile_id, profile_name, protocol, status, external_base_url,
		        COALESCE(error, ''), summary, started_at, finished_at
		   FROM login_attempts WHERE id = $1`, id)
	a, err := scanAttempt(row)
	if errors.Is(err, store.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	full := &FullAttempt{Attempt: a}

	// Details (may be absent).
	var params, artifacts, validations []byte
	err = r.db.QueryRowContext(ctx,
		`SELECT params_used, artifacts, validations FROM attempt_details WHERE attempt_id = $1`, id).
		Scan(&params, &artifacts, &validations)
	if err != nil && !errors.Is(err, store.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		_ = json.Unmarshal(params, &full.Details.ParamsUsed)
		_ = json.Unmarshal(artifacts, &full.Details.Artifacts)
		_ = json.Unmarshal(validations, &full.Details.Validations)
	}

	// Exchanges.
	exRows, err := r.db.QueryContext(ctx,
		`SELECT seq, phase, method, url, req_headers, req_body, status, resp_headers, resp_body, duration_ms, ts
		   FROM http_exchanges WHERE attempt_id = $1 ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	defer exRows.Close()
	for exRows.Next() {
		var (
			e           inspect.Exchange
			reqH, respH []byte
		)
		if err := exRows.Scan(&e.Seq, &e.Phase, &e.Method, &e.URL, &reqH, &e.ReqBody,
			&e.Status, &respH, &e.RespBody, &e.DurationMS, &e.Time); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(reqH, &e.ReqHeaders)
		_ = json.Unmarshal(respH, &e.RespHeaders)
		full.Exchanges = append(full.Exchanges, e)
	}
	return full, exRows.Err()
}

// scanAttempt scans a row from either Query or QueryRow into an Attempt.
func scanAttempt(row scanner) (Attempt, error) {
	var (
		a           Attempt
		summaryJSON []byte
	)
	err := row.Scan(&a.ID, &a.ProfileID, &a.ProfileName, &a.Protocol, &a.Status,
		&a.ExternalBaseURL, &a.Error, &summaryJSON, &a.StartedAt, &a.FinishedAt)
	if err != nil {
		return a, err
	}
	_ = json.Unmarshal(summaryJSON, &a.Summary)
	return a, nil
}

func orEmptyObj(m map[string]any) any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func orEmptyArr(v []inspect.Validation) any {
	if v == nil {
		return []inspect.Validation{}
	}
	return v
}

func joinAnd(conds []string) string {
	out := ""
	for i, c := range conds {
		if i > 0 {
			out += " AND "
		}
		out += c
	}
	return out
}
