package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/default23/loupe/internal/inspect"
)

// allowedJWSAlgs are the signature algorithms VerifyToken will accept. go-jose
// v4 requires the caller to whitelist algorithms up front (defence against alg
// confusion); we allow the common HMAC / RSA / ECDSA / RSA-PSS families.
var allowedJWSAlgs = []jose.SignatureAlgorithm{
	jose.HS256, jose.HS384, jose.HS512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
}

// VerifyToken checks a JWT's signature and time-based claims without any Profile
// or login-flow context, for the standalone JWT decoder tool. Signature is
// verified against a pasted JWKS (JSON) when jwksJSON is non-empty, or against a
// shared secret when secret is non-empty; if neither is given the signature check
// is reported as skipped. It always checks exp / nbf when those claims are present.
func VerifyToken(rawJWT, jwksJSON, secret string) []inspect.Validation {
	var vals []inspect.Validation

	tok, err := jose.ParseSigned(rawJWT, allowedJWSAlgs)
	if err != nil {
		return []inspect.Validation{{Name: "parse JWS", OK: false, Detail: err.Error()}}
	}
	if len(tok.Signatures) == 0 {
		return []inspect.Validation{{Name: "parse JWS", OK: false, Detail: "token carries no signature"}}
	}
	alg := tok.Signatures[0].Header.Algorithm
	kid := tok.Signatures[0].Header.KeyID

	switch {
	case secret != "":
		// Verify HMAC ourselves rather than via go-jose, which rejects secrets
		// shorter than the hash size (RFC 7518 §3.2). A testing tool, like
		// jwt.io, should verify against any secret the user pastes.
		vals = append(vals, signatureValidation(alg, verifyHMAC(rawJWT, alg, secret)))

	case jwksJSON != "":
		var jwks jose.JSONWebKeySet
		if jerr := json.Unmarshal([]byte(jwksJSON), &jwks); jerr != nil {
			vals = append(vals, inspect.Validation{Name: "parse JWKS", OK: false, Detail: jerr.Error()})
			break
		}
		keys := jwks.Key(kid)
		// Tolerate a single-key JWKS whose key omits "kid" (or a token with no kid).
		if len(keys) == 0 && len(jwks.Keys) == 1 {
			keys = jwks.Keys
		}
		if len(keys) == 0 {
			vals = append(vals, inspect.Validation{
				Name: "key match (kid)", OK: false,
				Detail: fmt.Sprintf("no key with kid=%q in JWKS (%d keys)", kid, len(jwks.Keys)),
			})
			break
		}
		verr := errors.New("no JWKS key verified the signature")
		for _, k := range keys {
			if _, e := tok.Verify(k); e == nil {
				verr = nil
				break
			} else {
				verr = e
			}
		}
		vals = append(vals, signatureValidation(alg, verr))

	default:
		vals = append(vals, inspect.Validation{
			Name: "signature", OK: false,
			Detail: "skipped: paste a JWKS or secret to verify the signature",
		})
	}

	vals = append(vals, timeClaimValidations(rawJWT)...)
	return vals
}

// verifyHMAC checks an HS256/384/512 signature against a shared secret of any
// length (unlike go-jose, which enforces RFC 7518's minimum key size).
func verifyHMAC(rawJWT, alg, secret string) error {
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return errors.New("not a compact JWS (need three dot-separated segments)")
	}
	var newHash func() hash.Hash
	switch alg {
	case "HS256":
		newHash = sha256.New
	case "HS384":
		newHash = sha512.New384
	case "HS512":
		newHash = sha512.New
	default:
		return fmt.Errorf("secret verification supports HS256/384/512 only; token uses %q", alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature segment: %w", err)
	}
	mac := hmac.New(newHash, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return errors.New("HMAC signature does not match")
	}
	return nil
}

func signatureValidation(alg string, err error) inspect.Validation {
	if err != nil {
		return inspect.Validation{Name: fmt.Sprintf("signature (%s)", alg), OK: false, Detail: err.Error()}
	}
	return inspect.Validation{Name: fmt.Sprintf("signature (%s)", alg), OK: true}
}

// timeClaimValidations checks exp and nbf against the current time when present.
func timeClaimValidations(rawJWT string) []inspect.Validation {
	_, claims, err := DecodeJWT(rawJWT)
	if err != nil || claims == nil {
		return nil
	}
	now := time.Now()
	var out []inspect.Validation
	if exp, ok := numericDate(claims["exp"]); ok {
		out = append(out, inspect.Validation{
			Name: "not expired (exp)", OK: now.Before(exp),
			Detail: "exp=" + exp.UTC().Format(time.RFC3339),
		})
	}
	if nbf, ok := numericDate(claims["nbf"]); ok {
		out = append(out, inspect.Validation{
			Name: "active (nbf)", OK: !now.Before(nbf),
			Detail: "nbf=" + nbf.UTC().Format(time.RFC3339),
		})
	}
	return out
}

// numericDate converts a JWT NumericDate claim (seconds since epoch, decoded as
// a JSON number → float64) to a time.Time.
func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC(), true
}
