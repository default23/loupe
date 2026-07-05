package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// CertInfo is a human-readable summary of an X.509 certificate for the
// certificate-inspector tool.
type CertInfo struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	Version            int
	NotBefore          string
	NotAfter           string
	Expired            bool
	NotYetValid        bool
	SelfSigned         bool
	IsCA               bool
	DNSNames           []string
	IPAddresses        []string
	KeyUsage           []string
	ExtKeyUsage        []string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	PublicKeyBits      int
	SHA1Fingerprint    string
	SHA256Fingerprint  string
}

// InspectCert parses a single PEM-encoded X.509 certificate and summarizes it.
// Standalone: no Profile or network needed.
func InspectCert(pemStr string) (*CertInfo, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found — expected -----BEGIN CERTIFICATE-----")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	now := time.Now()
	info := &CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		Version:            cert.Version,
		NotBefore:          cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           cert.NotAfter.UTC().Format(time.RFC3339),
		Expired:            now.After(cert.NotAfter),
		NotYetValid:        now.Before(cert.NotBefore),
		SelfSigned:         cert.Subject.String() == cert.Issuer.String(),
		IsCA:               cert.IsCA,
		DNSNames:           cert.DNSNames,
		KeyUsage:           keyUsageStrings(cert.KeyUsage),
		ExtKeyUsage:        extKeyUsageStrings(cert.ExtKeyUsage),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:      publicKeyBits(cert.PublicKey),
		SHA1Fingerprint:    fingerprint(sha1Sum(cert.Raw)),
		SHA256Fingerprint:  fingerprint(sha256Sum(cert.Raw)),
	}
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	return info, nil
}

func sha1Sum(b []byte) []byte   { s := sha1.Sum(b); return s[:] }
func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func publicKeyBits(pub any) int {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	default:
		return 0
	}
}

func fingerprint(sum []byte) string {
	hexStr := hex.EncodeToString(sum)
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		parts = append(parts, strings.ToUpper(hexStr[i:i+2]))
	}
	return strings.Join(parts, ":")
}

func keyUsageStrings(u x509.KeyUsage) []string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "DigitalSignature"},
		{x509.KeyUsageContentCommitment, "ContentCommitment"},
		{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
		{x509.KeyUsageDataEncipherment, "DataEncipherment"},
		{x509.KeyUsageKeyAgreement, "KeyAgreement"},
		{x509.KeyUsageCertSign, "CertSign"},
		{x509.KeyUsageCRLSign, "CRLSign"},
		{x509.KeyUsageEncipherOnly, "EncipherOnly"},
		{x509.KeyUsageDecipherOnly, "DecipherOnly"},
	}
	var out []string
	for _, n := range names {
		if u&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func extKeyUsageStrings(us []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:             "Any",
		x509.ExtKeyUsageServerAuth:      "ServerAuth",
		x509.ExtKeyUsageClientAuth:      "ClientAuth",
		x509.ExtKeyUsageCodeSigning:     "CodeSigning",
		x509.ExtKeyUsageEmailProtection: "EmailProtection",
		x509.ExtKeyUsageTimeStamping:    "TimeStamping",
		x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
	}
	var out []string
	for _, u := range us {
		if n, ok := names[u]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("ExtKeyUsage(%d)", u))
		}
	}
	return out
}
