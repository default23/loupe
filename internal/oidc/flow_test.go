package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/default23/loupe/internal/httpx"
	"github.com/default23/loupe/internal/inspect"
)

// TestOIDCFlowAgainstMockProvider exercises Exchange, VerifyIDToken, and
// Userinfo end-to-end against an in-process OIDC provider, and confirms that
// custom headers are injected and every exchange is recorded.
func TestOIDCFlowAgainstMockProvider(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const (
		kid      = "test-key"
		clientID = "client-abc"
		nonce    = "nonce-xyz"
		code     = "the-code"
		verifier = "verifier-123"
	)

	var issuer string
	mux := http.NewServeMux()

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksDoc(&key.PublicKey, kid))
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "authorization_code" || r.FormValue("code") != code {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if r.FormValue("code_verifier") != verifier {
			http.Error(w, "bad pkce", http.StatusBadRequest)
			return
		}
		if u, p, ok := r.BasicAuth(); !ok || u != clientID || p != "secret" {
			http.Error(w, "bad client auth", http.StatusUnauthorized)
			return
		}
		now := time.Now()
		claims := map[string]any{
			"iss":   issuer,
			"aud":   clientID,
			"sub":   "user-1",
			"nonce": nonce,
			"email": "u@example.com",
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
		}
		idToken := signRS256(t, claims, key, kid)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at-1",
			"id_token":     idToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "openid email",
		})
	})

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-1" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "user-1", "email": "u@example.com"})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	issuer = srv.URL

	cfg := Config{
		Issuer:                  issuer,
		TokenEndpoint:           issuer + "/token",
		UserinfoEndpoint:        issuer + "/userinfo",
		JWKSURI:                 issuer + "/jwks",
		ClientID:                clientID,
		ClientSecret:            "secret",
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	rec := inspect.NewRecorder()
	client := httpx.NewClient([]httpx.Header{
		{Name: "X-Trace", Value: "t1", Phases: []string{"token", "userinfo", "jwks"}},
	}, rec)
	ctx := context.Background()

	tr, err := Exchange(ctx, client, cfg, code, "http://localhost/cb", verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tr.IDToken == "" || tr.AccessToken != "at-1" {
		t.Fatalf("unexpected token response: %+v", tr)
	}

	vals, _, claims := VerifyIDToken(ctx, client, cfg, tr.IDToken, nonce)
	for _, v := range vals {
		if !v.OK {
			t.Errorf("validation %q failed: %s", v.Name, v.Detail)
		}
	}
	if claims["email"] != "u@example.com" {
		t.Errorf("expected email claim, got %v", claims["email"])
	}

	ui, err := Userinfo(ctx, client, cfg, tr.AccessToken)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	if ui["email"] != "u@example.com" {
		t.Errorf("expected userinfo email, got %v", ui["email"])
	}

	exs := rec.Exchanges()
	if len(exs) < 3 {
		t.Fatalf("expected >=3 recorded exchanges, got %d", len(exs))
	}
	for _, e := range exs {
		if e.ReqHeaders.Get("X-Trace") != "t1" {
			t.Errorf("custom header not injected on %s %s", e.Method, e.URL)
		}
	}
}

func TestVerifyIDTokenNonceMismatch(t *testing.T) {
	// A token with no issuer/jwks configured: signature check is skipped, but
	// the nonce mismatch must still be reported.
	claims := map[string]any{"nonce": "actual"}
	raw := unsecuredJWT(t, claims)
	vals, _, _ := VerifyIDToken(context.Background(), http.DefaultClient, Config{}, raw, "expected")
	var nonceVal *inspect.Validation
	for i := range vals {
		if vals[i].Name == "nonce matches" {
			nonceVal = &vals[i]
		}
	}
	if nonceVal == nil || nonceVal.OK {
		t.Fatalf("expected nonce validation to fail, got %+v", vals)
	}
}

// --- test helpers ---

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwksDoc(pub *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": kid,
			"n":   b64url(pub.N.Bytes()),
			"e":   b64url(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
}

func signRS256(t *testing.T, claims map[string]any, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	hj, _ := json.Marshal(header)
	cj, _ := json.Marshal(claims)
	signingInput := b64url(hj) + "." + b64url(cj)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + b64url(sig)
}

func unsecuredJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "none", "typ": "JWT"}
	hj, _ := json.Marshal(header)
	cj, _ := json.Marshal(claims)
	return b64url(hj) + "." + b64url(cj) + "."
}
