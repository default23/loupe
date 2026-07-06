// Package config loads runtime configuration from environment variables.
package config

import (
	"fmt"
	"strings"

	"github.com/caarlos0/env/v11"
)

// Database driver identifiers.
const (
	DriverPostgres = "postgres"
	DriverSQLite   = "sqlite"
)

// Config holds all runtime settings for the RP tester. Fields are populated
// from the environment via struct tags (github.com/caarlos0/env).
type Config struct {
	// ListenAddr is the address the HTTP server binds to, e.g. ":8080".
	ListenAddr string `env:"LISTEN_ADDR" envDefault:":8080"`
	// ExternalBaseURL is the externally reachable base URL of this app.
	// redirect_uri (OIDC) and the ACS URL (SAML) are derived from it, so it
	// must match what is registered at the identity provider.
	ExternalBaseURL string `env:"BASE_URL" envDefault:"http://localhost:8080"`
	// DBDriver selects the storage backend: "postgres" (default, external
	// PostgreSQL) or "sqlite" (embedded, file-backed — no external service).
	DBDriver string `env:"DB_DRIVER" envDefault:"postgres"`
	// DatabaseURL is the PostgreSQL connection string (used when DBDriver=postgres).
	DatabaseURL string `env:"POSTGRES_DSN" envDefault:"postgres://loupe:loupe@localhost:5432/loupe?sslmode=disable"`
	// SQLitePath is the path to the SQLite database file (used when DBDriver=sqlite).
	SQLitePath string `env:"SQLITE_PATH" envDefault:"loupe.db"`
	// MasterKeyB64 is the master key passphrase used to derive the AES key that
	// encrypts secrets at rest. May be empty until secrets are first used.
	MasterKeyB64 string `env:"MASTER_KEY"`
}

// Load parses configuration from the environment, applying defaults.
func Load() (*Config, error) {
	cfg, err := env.ParseAs[Config]()
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.ExternalBaseURL = strings.TrimRight(cfg.ExternalBaseURL, "/")
	cfg.DBDriver = strings.ToLower(strings.TrimSpace(cfg.DBDriver))
	return &cfg, nil
}

// Validate checks that required fields are present and well-formed.
func (c *Config) Validate() error {
	if c.ExternalBaseURL == "" {
		return fmt.Errorf("BASE_URL must be set")
	}
	switch c.DBDriver {
	case DriverPostgres:
		if c.DatabaseURL == "" {
			return fmt.Errorf("POSTGRES_DSN must be set when DB_DRIVER=postgres")
		}
	case DriverSQLite:
		if c.SQLitePath == "" {
			return fmt.Errorf("SQLITE_PATH must be set when DB_DRIVER=sqlite")
		}
	default:
		return fmt.Errorf("DB_DRIVER must be %q or %q, got %q", DriverPostgres, DriverSQLite, c.DBDriver)
	}
	return nil
}
