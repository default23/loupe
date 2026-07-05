package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/default23/loupe/internal/crypto"
)

// ErrNotFound is returned when a profile does not exist.
var ErrNotFound = errors.New("profile not found")

// Repo persists profiles in PostgreSQL, encrypting secrets with the cipher.
type Repo struct {
	pool   *pgxpool.Pool
	cipher *crypto.Cipher
}

// NewRepo builds a profile repository. cipher may be nil, in which case
// operations that require storing/reading secrets fail with crypto.ErrNoKey.
func NewRepo(pool *pgxpool.Pool, cipher *crypto.Cipher) *Repo {
	return &Repo{pool: pool, cipher: cipher}
}

// List returns profile summaries ordered by name.
func (r *Repo) List(ctx context.Context) ([]Summary, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, name, protocol, updated_at FROM profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Summary
	for rows.Next() {
		var s Summary
		if err := rows.Scan(&s.ID, &s.Name, &s.Protocol, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Get loads a full profile including decrypted secrets.
func (r *Repo) Get(ctx context.Context, id int64) (*Profile, error) {
	var (
		p           Profile
		configJSON  []byte
		headersJSON []byte
		secretsBlob []byte
	)
	err := r.pool.QueryRow(ctx,
		`SELECT id, name, protocol, config, custom_headers, secrets, created_at, updated_at
		   FROM profiles WHERE id = $1`, id).
		Scan(&p.ID, &p.Name, &p.Protocol, &configJSON, &headersJSON, &secretsBlob, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var cfg persistedConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	p.OIDC, p.SAML = cfg.OIDC, cfg.SAML

	if len(headersJSON) > 0 {
		if err := json.Unmarshal(headersJSON, &p.CustomHeaders); err != nil {
			return nil, fmt.Errorf("decode headers: %w", err)
		}
	}

	if len(secretsBlob) > 0 {
		if err := r.cipher.DecryptJSON(secretsBlob, &p.Secrets); err != nil {
			return nil, err
		}
		// Merge secret header values back into their headers by index.
		for i := range p.CustomHeaders {
			if p.CustomHeaders[i].Secret {
				p.CustomHeaders[i].Value = p.Secrets.HeaderValues[strconv.Itoa(i)]
			}
		}
	}

	return &p, nil
}

// Create inserts a new profile, returning its assigned ID.
func (r *Repo) Create(ctx context.Context, p *Profile) error {
	configJSON, headersJSON, secretsBlob, err := r.encode(p)
	if err != nil {
		return err
	}
	err = r.pool.QueryRow(ctx,
		`INSERT INTO profiles (name, protocol, config, custom_headers, secrets)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at, updated_at`,
		p.Name, p.Protocol, configJSON, headersJSON, secretsBlob).
		Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	return err
}

// Update saves changes to an existing profile.
func (r *Repo) Update(ctx context.Context, p *Profile) error {
	configJSON, headersJSON, secretsBlob, err := r.encode(p)
	if err != nil {
		return err
	}
	ct, err := r.pool.Exec(ctx,
		`UPDATE profiles
		    SET name = $2, protocol = $3, config = $4, custom_headers = $5,
		        secrets = $6, updated_at = now()
		  WHERE id = $1`,
		p.ID, p.Name, p.Protocol, configJSON, headersJSON, secretsBlob)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a profile.
func (r *Repo) Delete(ctx context.Context, id int64) error {
	ct, err := r.pool.Exec(ctx, `DELETE FROM profiles WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// encode splits a profile into its stored columns, moving secret material into
// an encrypted blob and stripping secret header values from the plaintext.
func (r *Repo) encode(p *Profile) (configJSON, headersJSON []byte, secretsBlob []byte, err error) {
	// Build the secrets bundle, pulling secret header values out by index.
	secrets := p.Secrets
	if secrets.HeaderValues == nil {
		secrets.HeaderValues = map[string]string{}
	}
	storedHeaders := make([]CustomHeader, len(p.CustomHeaders))
	for i, h := range p.CustomHeaders {
		sh := h
		if h.Secret {
			secrets.HeaderValues[strconv.Itoa(i)] = h.Value
			sh.Value = ""
		}
		storedHeaders[i] = sh
	}
	if len(secrets.HeaderValues) == 0 {
		secrets.HeaderValues = nil
	}

	cfg := persistedConfig{OIDC: p.OIDC, SAML: p.SAML}
	if configJSON, err = json.Marshal(cfg); err != nil {
		return nil, nil, nil, err
	}
	if headersJSON, err = json.Marshal(storedHeaders); err != nil {
		return nil, nil, nil, err
	}

	if secrets.needsStorage() {
		if r.cipher == nil {
			return nil, nil, nil, crypto.ErrNoKey
		}
		if secretsBlob, err = r.cipher.EncryptJSON(secrets); err != nil {
			return nil, nil, nil, err
		}
	}
	return configJSON, headersJSON, secretsBlob, nil
}
