package web

import (
	"bytes"
	"html/template"
	"strings"
	"testing"

	"github.com/default23/loupe/internal/crypto"
	"github.com/default23/loupe/internal/oidc"
	"github.com/default23/loupe/internal/saml"
)

// parsePage parses a page template the same way NewServer does.
func parsePage(t *testing.T, page string) *template.Template {
	t.Helper()
	tmpl, err := template.New("base.html").Funcs(funcMap()).
		ParseFS(templatesFS, "templates/base.html", "templates/"+page)
	if err != nil {
		t.Fatalf("parse %s: %v", page, err)
	}
	return tmpl
}

// TestAllPagesParse guards against template syntax errors, which otherwise only
// surface at server startup.
func TestAllPagesParse(t *testing.T) {
	for _, p := range pages {
		parsePage(t, p)
	}
}

// TestToolFragmentsExecute renders each tool's result fragment with representative
// data, catching template/field mismatches without needing a database.
func TestToolFragmentsExecute(t *testing.T) {
	kp, err := crypto.GenerateSPKeyPair("t")
	if err != nil {
		t.Fatal(err)
	}
	certInfo, err := crypto.InspectCert(kp.CertPEM)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		page, block string
		data        any
	}{
		{"tool_jwt.html", "jwt_result", &jwtReadout{
			Decoded:     true,
			Header:      map[string]any{"alg": "RS256"},
			Claims:      map[string]any{"sub": "a"},
			Timestamps:  []kv{{K: "exp", V: "2026"}},
			Validations: []checkRow{{Name: "signature", State: "ok"}, {Name: "sig", State: "warn"}},
			VerifyNote:  "note",
		}},
		{"tool_jwt.html", "jwt_result", &jwtReadout{Error: "bad"}},
		{"tool_saml_response.html", "saml_response_result", &samlResponseReadout{
			Decoded:     true,
			XML:         "<x/>",
			NameID:      "u",
			Attributes:  map[string][]string{"email": {"a@b"}},
			Validations: []checkRow{{Name: "signature", State: "ok"}},
		}},
		{"tool_saml_authnrequest.html", "authn_request_result", &authnRequestReadout{
			Info: &saml.AuthnRequestInfo{
				XML: "<x/>", Binding: "redirect", ID: "_1", Issuer: "sp",
				RequestedAuthnContext: []string{"ctx"}, Signed: true,
			},
		}},
		{"tool_encode.html", "encode_result", &encodeReadout{Output: "aGk="}},
		{"tool_cert.html", "cert_result", &certReadout{Info: certInfo}},
		{"tool_cert.html", "keypair_result", &certReadout{KeyPair: kp}},
		{"tool_jwks.html", "jwks_result", &jwksReadout{
			Keys: []oidc.JWKSKey{{Kid: "k1", Kty: "RSA", Alg: "RS256", Use: "sig", Bits: 2048, Thumbprint: "tp"}},
		}},
	}

	for _, c := range cases {
		tmpl := parsePage(t, c.page)
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, c.block, c.data); err != nil {
			t.Errorf("execute %s/%s: %v", c.page, c.block, err)
			continue
		}
		if strings.TrimSpace(buf.String()) == "" {
			t.Errorf("%s/%s produced empty output", c.page, c.block)
		}
	}
}
