package oidc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/default23/loupe/internal/inspect"
)

func hs256(t *testing.T, claims map[string]any, secret string) string {
	t.Helper()
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	hj, _ := json.Marshal(header)
	cj, _ := json.Marshal(claims)
	signingInput := b64url(hj) + "." + b64url(cj)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64url(mac.Sum(nil))
}

// hasOK reports whether some validation whose Name contains sub has OK == want.
func hasOK(vals []inspect.Validation, sub string, want bool) bool {
	for _, v := range vals {
		if strings.Contains(v.Name, sub) && v.OK == want {
			return true
		}
	}
	return false
}

// hasSkipped reports whether a signature validation was reported as skipped.
func hasSkipped(vals []inspect.Validation) bool {
	for _, v := range vals {
		if strings.Contains(v.Name, "signature") && strings.Contains(v.Detail, "skipped") {
			return true
		}
	}
	return false
}

func TestVerifyTokenRS256ViaJWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "k1"
	claims := map[string]any{
		"sub": "alice",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
		"nbf": float64(time.Now().Add(-time.Minute).Unix()),
	}
	tok := signRS256(t, claims, key, kid)
	jwks, _ := json.Marshal(jwksDoc(&key.PublicKey, kid))

	vals := VerifyToken(tok, string(jwks), "")
	if !hasOK(vals, "signature", true) {
		t.Fatalf("expected signature ok, got %+v", vals)
	}
	if !hasOK(vals, "not expired", true) {
		t.Fatalf("expected exp ok, got %+v", vals)
	}
	if !hasOK(vals, "active (nbf)", true) {
		t.Fatalf("expected nbf ok, got %+v", vals)
	}
}

func TestVerifyTokenRS256TamperedFails(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "k1"
	tok := signRS256(t, map[string]any{"sub": "a"}, key, kid)
	// JWKS advertises a different public key for the same kid.
	jwks, _ := json.Marshal(jwksDoc(&other.PublicKey, kid))

	vals := VerifyToken(tok, string(jwks), "")
	if !hasOK(vals, "signature", false) {
		t.Fatalf("expected signature failure with wrong key, got %+v", vals)
	}
}

func TestVerifyTokenHS256(t *testing.T) {
	tok := hs256(t, map[string]any{"sub": "a"}, "s3cret")
	if !hasOK(VerifyToken(tok, "", "s3cret"), "signature", true) {
		t.Fatal("expected HS256 signature ok with correct secret")
	}
	if !hasOK(VerifyToken(tok, "", "wrong"), "signature", false) {
		t.Fatal("expected HS256 signature failure with wrong secret")
	}
}

func TestVerifyTokenExpired(t *testing.T) {
	tok := hs256(t, map[string]any{
		"sub": "a",
		"exp": float64(time.Now().Add(-time.Hour).Unix()),
	}, "s")
	if !hasOK(VerifyToken(tok, "", "s"), "not expired", false) {
		t.Fatal("expected expired token to fail the exp check")
	}
}

func TestVerifyTokenNoVerifierSkips(t *testing.T) {
	tok := hs256(t, map[string]any{"sub": "a"}, "s")
	vals := VerifyToken(tok, "", "")
	if !hasSkipped(vals) {
		t.Fatalf("expected a skipped signature validation, got %+v", vals)
	}
}
