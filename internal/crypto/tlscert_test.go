package crypto

import (
	"strings"
	"testing"
)

func TestParseCertChainSingle(t *testing.T) {
	kp, err := GenerateSPKeyPair("loupe-sp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ParseCertChain(kp.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	c := certs[0]
	if !c.SelfSigned {
		t.Error("expected self-signed cert")
	}
	if c.Label != "Certificate (self-signed)" {
		t.Errorf("Label = %q", c.Label)
	}
	if c.PublicKeyBits != 2048 {
		t.Errorf("PublicKeyBits = %d, want 2048", c.PublicKeyBits)
	}
	var cn string
	for _, f := range c.SubjectParts {
		if f.Field == "Common Name" {
			cn = f.Value
		}
	}
	if cn != "loupe-sp.example.com" {
		t.Errorf("subject CN = %q", cn)
	}
	if got := strings.Count(c.SHA256Fingerprint, ":"); got != 31 {
		t.Errorf("SHA256 fingerprint has %d separators, want 31", got)
	}
	if !strings.Contains(c.PEM, "BEGIN CERTIFICATE") {
		t.Error("re-encoded PEM missing")
	}
}

func TestParseCertChainMultiple(t *testing.T) {
	a, err := GenerateSPKeyPair("leaf.example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateSPKeyPair("intermediate.example.com")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ParseCertChain(a.CertPEM + "\n" + b.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}
	if certs[0].Label != "Leaf" {
		t.Errorf("first label = %q, want Leaf", certs[0].Label)
	}
	if certs[0].Position != 0 || certs[1].Position != 1 {
		t.Errorf("positions = %d,%d", certs[0].Position, certs[1].Position)
	}
}

func TestParseCertChainErrors(t *testing.T) {
	if _, err := ParseCertChain("not a pem"); err == nil {
		t.Error("expected error for non-PEM input")
	}
	if _, err := ParseCertChain(""); err == nil {
		t.Error("expected error for empty input")
	}
	badPEM := "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"
	if _, err := ParseCertChain(badPEM); err == nil {
		t.Error("expected parse error for malformed cert body")
	}
}

func TestNormalizeHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantAddr string
		wantErr  bool
	}{
		{"idp.example.com", "idp.example.com:443", false},
		{"idp.example.com:8443", "idp.example.com:8443", false},
		{"https://idp.example.com", "", true},
		{"idp.example.com/path", "", true},
		{"", "", true},
		{"host:abc", "", true},
	}
	for _, tc := range cases {
		_, addr, err := normalizeHostPort(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", tc.in, err)
		}
		if addr != tc.wantAddr {
			t.Errorf("%q: addr = %q, want %q", tc.in, addr, tc.wantAddr)
		}
	}
}
