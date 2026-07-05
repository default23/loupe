package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/default23/loupe/internal/httpx"
	"github.com/default23/loupe/internal/inspect"
)

// TokenResponse is the parsed response from the token endpoint.
type TokenResponse struct {
	AccessToken  string         `json:"access_token"`
	IDToken      string         `json:"id_token"`
	RefreshToken string         `json:"refresh_token"`
	TokenType    string         `json:"token_type"`
	Scope        string         `json:"scope"`
	ExpiresIn    int            `json:"expires_in"`
	Raw          map[string]any `json:"-"`
}

// Exchange trades an authorization code for tokens at the token endpoint.
func Exchange(ctx context.Context, client *http.Client, cfg Config, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(
		httpx.WithPhase(ctx, "token"), http.MethodPost, cfg.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	switch cfg.TokenEndpointAuthMethod {
	case "client_secret_post":
		form.Set("client_id", cfg.ClientID)
		form.Set("client_secret", cfg.ClientSecret)
		req.Body = io.NopCloser(strings.NewReader(form.Encode()))
		req.ContentLength = int64(len(form.Encode()))
	case "none":
		form.Set("client_id", cfg.ClientID)
		req.Body = io.NopCloser(strings.NewReader(form.Encode()))
		req.ContentLength = int64(len(form.Encode()))
	default: // client_secret_basic
		req.SetBasicAuth(url.QueryEscape(cfg.ClientID), url.QueryEscape(cfg.ClientSecret))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}
	_ = json.Unmarshal(body, &tr.Raw)
	return &tr, nil
}

// VerifyIDToken validates the ID token signature and claims against the JWKS,
// and checks the nonce. It returns granular validation results plus the decoded
// header and claims (verified when possible, otherwise unverified).
func VerifyIDToken(ctx context.Context, client *http.Client, cfg Config, rawIDToken, expectedNonce string) (vals []inspect.Validation, header, claims map[string]any) {
	header, claims, _ = DecodeJWT(rawIDToken)

	if rawIDToken == "" {
		return []inspect.Validation{{Name: "id_token present", OK: false, Detail: "no id_token in token response"}}, header, claims
	}
	if cfg.Issuer == "" || cfg.JWKSURI == "" {
		vals = append(vals, inspect.Validation{
			Name: "id_token signature & claims", OK: false,
			Detail: "skipped: issuer or jwks_uri not configured",
		})
	} else {
		vctx := coreoidc.ClientContext(httpx.WithPhase(ctx, "jwks"), client)
		ks := coreoidc.NewRemoteKeySet(vctx, cfg.JWKSURI)
		verifier := coreoidc.NewVerifier(cfg.Issuer, ks, &coreoidc.Config{ClientID: cfg.ClientID})
		idt, err := verifier.Verify(vctx, rawIDToken)
		if err != nil {
			vals = append(vals, inspect.Validation{
				Name: "id_token signature & claims (iss, aud, exp)", OK: false, Detail: err.Error(),
			})
		} else {
			vals = append(vals, inspect.Validation{
				Name: "id_token signature & claims (iss, aud, exp)", OK: true,
				Detail: fmt.Sprintf("issuer=%s aud=%v", idt.Issuer, idt.Audience),
			})
			var verified map[string]any
			if err := idt.Claims(&verified); err == nil {
				claims = verified
			}
		}
	}

	// Nonce check (independent of signature verification).
	gotNonce, _ := claims["nonce"].(string)
	vals = append(vals, inspect.Validation{
		Name:   "nonce matches",
		OK:     expectedNonce != "" && gotNonce == expectedNonce,
		Detail: fmt.Sprintf("expected=%s got=%s", expectedNonce, gotNonce),
	})

	return vals, header, claims
}

// Userinfo calls the userinfo endpoint with the access token.
func Userinfo(ctx context.Context, client *http.Client, cfg Config, accessToken string) (map[string]any, error) {
	if cfg.UserinfoEndpoint == "" || accessToken == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(
		httpx.WithPhase(ctx, "userinfo"), http.MethodGet, cfg.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned %d: %s", resp.StatusCode, string(body))
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse userinfo: %w", err)
	}
	return out, nil
}

// DecodeJWT decodes (without verifying) the header and payload of a JWT.
func DecodeJWT(token string) (header, payload map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, nil, fmt.Errorf("not a JWT")
	}
	header = decodeSegment(parts[0])
	payload = decodeSegment(parts[1])
	return header, payload, nil
}

func decodeSegment(seg string) map[string]any {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}
