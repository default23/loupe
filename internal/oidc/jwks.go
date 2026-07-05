package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// JWKSKey is a display-friendly summary of one key in a JWK Set.
type JWKSKey struct {
	Kid        string
	Kty        string
	Alg        string
	Use        string
	Bits       int
	Thumbprint string // RFC 7638 SHA-256 thumbprint, base64url
}

// ParseJWKS parses a JWK Set (JSON) and summarizes each key. Standalone: no
// Profile or network needed.
func ParseJWKS(jwksJSON string) ([]JWKSKey, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(jwksJSON), &set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, fmt.Errorf("no keys found in JWKS")
	}
	out := make([]JWKSKey, 0, len(set.Keys))
	for _, k := range set.Keys {
		info := JWKSKey{Kid: k.KeyID, Alg: k.Algorithm, Use: k.Use}
		switch key := k.Key.(type) {
		case *rsa.PublicKey:
			info.Kty, info.Bits = "RSA", key.N.BitLen()
		case *ecdsa.PublicKey:
			info.Kty, info.Bits = "EC", key.Curve.Params().BitSize
		case ed25519.PublicKey:
			info.Kty, info.Bits = "OKP", len(key)*8
		case []byte:
			info.Kty, info.Bits = "oct", len(key)*8
		default:
			info.Kty = fmt.Sprintf("%T", k.Key)
		}
		if tp, err := k.Thumbprint(crypto.SHA256); err == nil {
			info.Thumbprint = base64.RawURLEncoding.EncodeToString(tp)
		}
		out = append(out, info)
	}
	return out, nil
}
