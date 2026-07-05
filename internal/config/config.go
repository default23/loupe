// Package config loads runtime configuration from environment variables.
package config

import (
	"fmt"
	"strings"

	"github.com/caarlos0/env/v11"
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
	// DatabaseURL is the PostgreSQL connection string.
	DatabaseURL string `env:"POSTGRES_DSN" envDefault:"postgres://loupe:loupe@localhost:5432/loupe?sslmode=disable"`
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
	return &cfg, nil
}

// Validate checks that required fields are present and well-formed.
func (c *Config) Validate() error {
	if c.ExternalBaseURL == "" {
		return fmt.Errorf("BASE_URL must be set")
	}
	if c.DatabaseURL == "" {
		return fmt.Errorf("POSTGRES_DSN must be set")
	}
	return nil
}
