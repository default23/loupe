package crypto

import (
	"strings"
	"testing"
)

func TestInspectCertSelfSigned(t *testing.T) {
	kp, err := GenerateSPKeyPair("loupe-sp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	info, err := InspectCert(kp.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(info.Subject, "loupe-sp.example.com") {
		t.Errorf("Subject = %q", info.Subject)
	}
	if !info.SelfSigned {
		t.Error("expected self-signed cert")
	}
	if info.Expired || info.NotYetValid {
		t.Errorf("fresh 10-year cert reported invalid: expired=%v notYetValid=%v", info.Expired, info.NotYetValid)
	}
	if info.PublicKeyBits != 2048 {
		t.Errorf("PublicKeyBits = %d, want 2048", info.PublicKeyBits)
	}
	// Fingerprints are colon-separated uppercase hex.
	if got := strings.Count(info.SHA256Fingerprint, ":"); got != 31 {
		t.Errorf("SHA256 fingerprint has %d separators, want 31: %q", got, info.SHA256Fingerprint)
	}
	if len(info.KeyUsage) == 0 {
		t.Error("expected some key usage flags")
	}
}

func TestInspectCertErrors(t *testing.T) {
	if _, err := InspectCert("not a pem"); err == nil {
		t.Error("expected error for non-PEM input")
	}
	badPEM := "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"
	if _, err := InspectCert(badPEM); err == nil {
		t.Error("expected parse error for malformed cert body")
	}
}
