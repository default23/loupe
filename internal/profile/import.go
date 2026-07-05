package profile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// SAML binding URIs.
const (
	BindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingHTTPPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// oidcDiscoveryDoc is the subset of the OpenID Connect discovery document we use.
type oidcDiscoveryDoc struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// FetchOIDCDiscovery retrieves and parses an OpenID Connect discovery document.
// issuerOrURL may be the issuer (the .well-known path is appended) or a full
// discovery URL.
func FetchOIDCDiscovery(ctx context.Context, client *http.Client, issuerOrURL string) (*OIDCConfig, error) {
	url := strings.TrimRight(issuerOrURL, "/")
	if !strings.Contains(url, "/.well-known/") {
		url += "/.well-known/openid-configuration"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var doc oidcDiscoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse discovery: %w", err)
	}

	return &OIDCConfig{
		Issuer:                doc.Issuer,
		DiscoveryURL:          url,
		AuthorizationEndpoint: doc.AuthorizationEndpoint,
		TokenEndpoint:         doc.TokenEndpoint,
		UserinfoEndpoint:      doc.UserinfoEndpoint,
		JWKSURI:               doc.JWKSURI,
		Scopes:                doc.ScopesSupported,
	}, nil
}

// SAML metadata XML structures (matched by local element name, namespace-agnostic).
type samlEntityDescriptor struct {
	EntityID         string               `xml:"entityID,attr"`
	IDPSSODescriptor samlIDPSSODescriptor `xml:"IDPSSODescriptor"`
}

type samlIDPSSODescriptor struct {
	KeyDescriptors       []samlKeyDescriptor `xml:"KeyDescriptor"`
	SingleSignOnServices []samlEndpoint      `xml:"SingleSignOnService"`
	SingleLogoutServices []samlEndpoint      `xml:"SingleLogoutService"`
}

type samlKeyDescriptor struct {
	Use      string `xml:"use,attr"`
	X509Cert string `xml:"KeyInfo>X509Data>X509Certificate"`
}

type samlEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// ParseSAMLMetadata parses IdP metadata XML into SAMLConfig fields.
func ParseSAMLMetadata(data []byte) (*SAMLConfig, error) {
	var ed samlEntityDescriptor
	if err := xml.Unmarshal(data, &ed); err != nil {
		return nil, fmt.Errorf("parse metadata: %w", err)
	}
	if ed.EntityID == "" {
		return nil, fmt.Errorf("metadata has no entityID (is this an IdP EntityDescriptor?)")
	}

	cfg := &SAMLConfig{IdPEntityID: ed.EntityID}

	// Prefer HTTP-Redirect for SSO; fall back to the first available endpoint.
	for _, ep := range ed.IDPSSODescriptor.SingleSignOnServices {
		if cfg.IdPSSOURL == "" || ep.Binding == BindingHTTPRedirect {
			cfg.IdPSSOURL = ep.Location
			if ep.Binding == BindingHTTPRedirect {
				cfg.IdPSSOBinding = "redirect"
			} else if ep.Binding == BindingHTTPPOST {
				cfg.IdPSSOBinding = "post"
			}
		}
	}
	if cfg.IdPSSOBinding == "" {
		cfg.IdPSSOBinding = "redirect"
	}

	if len(ed.IDPSSODescriptor.SingleLogoutServices) > 0 {
		cfg.IdPSLOURL = ed.IDPSSODescriptor.SingleLogoutServices[0].Location
	}

	// Collect signing certificates (use="signing" or unspecified).
	for _, kd := range ed.IDPSSODescriptor.KeyDescriptors {
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		if p := CertToPEM(kd.X509Cert); p != "" {
			cfg.IdPCertsPEM = append(cfg.IdPCertsPEM, p)
		}
	}

	return cfg, nil
}

// FetchSAMLMetadata retrieves and parses IdP metadata from a URL.
func FetchSAMLMetadata(ctx context.Context, client *http.Client, url string) (*SAMLConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata returned %d", resp.StatusCode)
	}
	return ParseSAMLMetadata(body)
}

// CertToPEM wraps a bare base64 DER certificate (as found in SAML metadata) in
// PEM armor. It tolerates surrounding whitespace and already-PEM input.
func CertToPEM(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "BEGIN CERTIFICATE") {
		return raw
	}
	// Strip internal whitespace from the base64 body.
	compact := strings.Join(strings.Fields(raw), "")
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
