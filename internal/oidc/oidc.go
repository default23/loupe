// Package oidc implements the OpenID Connect relying-party flow: building the
// authorization request, exchanging the code, validating the ID token, and
// calling userinfo. Every server-to-server call goes through a capturing HTTP
// client so the exchanges can be inspected.
package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/default23/loupe/internal/profile"
)

// Config is the effective OIDC configuration for a login.
type Config struct {
	Issuer                  string
	AuthorizationEndpoint   string
	TokenEndpoint           string
	UserinfoEndpoint        string
	JWKSURI                 string
	ClientID                string
	ClientSecret            string
	TokenEndpointAuthMethod string
}

// ConfigFromProfile builds a Config from a profile's OIDC settings.
func ConfigFromProfile(p *profile.Profile) Config {
	return Config{
		Issuer:                  p.OIDC.Issuer,
		AuthorizationEndpoint:   p.OIDC.AuthorizationEndpoint,
		TokenEndpoint:           p.OIDC.TokenEndpoint,
		UserinfoEndpoint:        p.OIDC.UserinfoEndpoint,
		JWKSURI:                 p.OIDC.JWKSURI,
		ClientID:                p.OIDC.ClientID,
		ClientSecret:            p.Secrets.OIDCClientSecret,
		TokenEndpointAuthMethod: p.OIDC.TokenEndpointAuthMethod,
	}
}

// Param is an ordered authorization-request parameter.
type Param struct {
	Key   string
	Value string
}

// Start holds the computed authorization request, ready to review and edit.
type Start struct {
	AuthorizationEndpoint string
	Params                []Param
	CodeVerifier          string
}

// BuildStart computes default authorization parameters (state, nonce, PKCE, …).
func BuildStart(p *profile.Profile, redirectURI string) (*Start, error) {
	c := p.OIDC
	state := randToken(24)
	nonce := randToken(24)

	responseType := c.ResponseType
	if responseType == "" {
		responseType = "code"
	}

	params := []Param{
		{"response_type", responseType},
		{"client_id", c.ClientID},
		{"redirect_uri", redirectURI},
		{"scope", strings.Join(c.Scopes, " ")},
		{"state", state},
		{"nonce", nonce},
	}

	verifier := ""
	switch c.PKCEMethod {
	case "", "S256":
		verifier = randToken(48)
		params = append(params,
			Param{"code_challenge", pkceChallengeS256(verifier)},
			Param{"code_challenge_method", "S256"})
	case "plain":
		verifier = randToken(48)
		params = append(params,
			Param{"code_challenge", verifier},
			Param{"code_challenge_method", "plain"})
	case "none":
		// no PKCE
	}

	if c.Prompt != "" {
		params = append(params, Param{"prompt", c.Prompt})
	}
	if c.ACRValues != "" {
		params = append(params, Param{"acr_values", c.ACRValues})
	}
	for _, kv := range c.ExtraAuthParams {
		params = append(params, Param{kv.Key, kv.Value})
	}

	return &Start{
		AuthorizationEndpoint: c.AuthorizationEndpoint,
		Params:                params,
		CodeVerifier:          verifier,
	}, nil
}

// URL renders the full authorization URL from the (possibly edited) params.
func (s *Start) URL() string {
	q := url.Values{}
	for _, p := range s.Params {
		q.Add(p.Key, p.Value)
	}
	sep := "?"
	if strings.Contains(s.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return s.AuthorizationEndpoint + sep + q.Encode()
}

// ParamValue returns the value of a named param.
func (s *Start) ParamValue(key string) string {
	for _, p := range s.Params {
		if p.Key == key {
			return p.Value
		}
	}
	return ""
}

func pkceChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
