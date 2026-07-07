package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// NameField is one component of a distinguished name, kept ordered for display.
type NameField struct {
	Field string
	Value string
}

// CertExtension is a raw X.509 extension summarized for the readout.
type CertExtension struct {
	OID      string
	Name     string
	Critical bool
}

// FullCertInfo is a comprehensive, human-readable dump of a single X.509
// certificate for the "Parse TLS Certificate" tool. Unlike CertInfo it breaks
// the subject/issuer into fields and surfaces every extension of interest.
type FullCertInfo struct {
	// Position within a parsed chain (0-based) and a friendly role label.
	Position int
	Label    string

	SubjectDN    string
	IssuerDN     string
	SubjectParts []NameField
	IssuerParts  []NameField

	SerialHex string
	SerialDec string
	Version   int

	NotBefore  string
	NotAfter   string
	ValidFor   string
	ExpiryNote string

	Expired     bool
	NotYetValid bool
	SelfSigned  bool
	IsCA        bool

	BasicConstraintsValid bool
	MaxPathLen            int
	HasMaxPathLen         bool

	DNSNames       []string
	IPAddresses    []string
	EmailAddresses []string
	URIs           []string

	KeyUsage    []string
	ExtKeyUsage []string

	SignatureAlgorithm string
	PublicKeyAlgorithm string
	PublicKeyBits      int
	PublicKeyDetail    string

	SubjectKeyID   string
	AuthorityKeyID string

	OCSPServers []string
	IssuingURLs []string
	CRLPoints   []string
	Policies    []string

	Extensions []CertExtension

	SHA1Fingerprint   string
	SHA256Fingerprint string

	PEM string
}

// ParseCertChain parses one or more concatenated PEM CERTIFICATE blocks and
// returns a full readout per certificate, in the order presented. Standalone:
// no Profile or network needed.
func ParseCertChain(pemStr string) ([]*FullCertInfo, error) {
	rest := []byte(strings.TrimSpace(pemStr))
	if len(rest) == 0 {
		return nil, fmt.Errorf("no input — paste a PEM certificate")
	}

	var certs []*x509.Certificate
	sawBlock := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sawBlock = true
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate #%d: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}

	if !sawBlock {
		return nil, fmt.Errorf("no PEM block found — expected -----BEGIN CERTIFICATE-----")
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE block found in the PEM input")
	}
	return summarizeChain(certs), nil
}

// FetchTLSCertChain dials a TLS server and returns a full readout of the
// certificate chain it presents. hostport may omit the port (defaults to 443).
// Verification is intentionally skipped so expired/misconfigured chains can
// still be inspected — this tool reports on the certificate, it does not trust it.
func FetchTLSCertChain(ctx context.Context, hostport string) ([]*FullCertInfo, error) {
	host, addr, err := normalizeHostPort(hostport)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, //nolint:gosec // inspection tool: we report on the chain, never trust it
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	defer conn.Close()

	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("server %s presented no certificates", addr)
	}
	return summarizeChain(certs), nil
}

// normalizeHostPort validates a user-supplied host[:port], defaulting the port
// to 443, and returns the SNI host plus a dialable address. It rejects schemes
// and paths so a URL isn't silently mis-dialed.
func normalizeHostPort(input string) (host, addr string, err error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", "", fmt.Errorf("no host — enter a host or host:port")
	}
	if strings.Contains(s, "://") || strings.ContainsAny(s, "/?#") {
		return "", "", fmt.Errorf("enter a bare host or host:port, not a URL")
	}

	host, port, splitErr := net.SplitHostPort(s)
	if splitErr != nil {
		// No port present (or malformed); assume the input is a bare host.
		host, port = s, "443"
	}
	if host == "" {
		return "", "", fmt.Errorf("missing host in %q", input)
	}
	if _, convErr := strconv.Atoi(port); convErr != nil {
		return "", "", fmt.Errorf("invalid port %q", port)
	}
	return host, net.JoinHostPort(host, port), nil
}

// summarizeChain builds a full readout per certificate and labels chain roles.
func summarizeChain(certs []*x509.Certificate) []*FullCertInfo {
	out := make([]*FullCertInfo, 0, len(certs))
	for i, c := range certs {
		info := summarizeCert(c)
		info.Position = i
		info.Label = chainLabel(i, len(certs), c)
		out = append(out, info)
	}
	return out
}

// chainLabel names a certificate's role for display.
func chainLabel(idx, total int, c *x509.Certificate) string {
	selfSigned := bytesEqualName(c.RawSubject, c.RawIssuer)
	switch {
	case total == 1:
		if selfSigned {
			return "Certificate (self-signed)"
		}
		return "Certificate"
	case idx == 0:
		return "Leaf"
	case idx == total-1 && selfSigned:
		return "Root"
	default:
		return "Intermediate"
	}
}

func bytesEqualName(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// summarizeCert renders a single certificate into a FullCertInfo.
func summarizeCert(cert *x509.Certificate) *FullCertInfo {
	now := time.Now()
	info := &FullCertInfo{
		SubjectDN:             cert.Subject.String(),
		IssuerDN:              cert.Issuer.String(),
		SubjectParts:          nameFields(cert.Subject),
		IssuerParts:           nameFields(cert.Issuer),
		SerialHex:             serialHex(cert.SerialNumber),
		SerialDec:             cert.SerialNumber.String(),
		Version:               cert.Version,
		NotBefore:             cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:              cert.NotAfter.UTC().Format(time.RFC3339),
		ValidFor:              humanDuration(cert.NotAfter.Sub(cert.NotBefore)),
		ExpiryNote:            expiryNote(now, cert.NotBefore, cert.NotAfter),
		Expired:               now.After(cert.NotAfter),
		NotYetValid:           now.Before(cert.NotBefore),
		SelfSigned:            bytesEqualName(cert.RawSubject, cert.RawIssuer),
		IsCA:                  cert.IsCA,
		BasicConstraintsValid: cert.BasicConstraintsValid,
		DNSNames:              cert.DNSNames,
		IPAddresses:           ipStrings(cert.IPAddresses),
		EmailAddresses:        cert.EmailAddresses,
		URIs:                  uriStrings(cert.URIs),
		KeyUsage:              keyUsageStrings(cert.KeyUsage),
		ExtKeyUsage:           fullExtKeyUsage(cert),
		SignatureAlgorithm:    cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:    cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:         publicKeyBits(cert.PublicKey),
		PublicKeyDetail:       publicKeyDetail(cert.PublicKey),
		SubjectKeyID:          colonHex(cert.SubjectKeyId),
		AuthorityKeyID:        colonHex(cert.AuthorityKeyId),
		OCSPServers:           cert.OCSPServer,
		IssuingURLs:           cert.IssuingCertificateURL,
		CRLPoints:             cert.CRLDistributionPoints,
		Policies:              policyStrings(cert),
		Extensions:            extensionSummaries(cert.Extensions),
		SHA1Fingerprint:       fingerprint(sha1Sum(cert.Raw)),
		SHA256Fingerprint:     fingerprint(sha256Sum(cert.Raw)),
		PEM:                   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}
	if cert.BasicConstraintsValid && cert.IsCA {
		info.HasMaxPathLen = cert.MaxPathLen > 0 || cert.MaxPathLenZero
		info.MaxPathLen = cert.MaxPathLen
	}
	return info
}

// nameFields breaks a pkix.Name into an ordered, non-empty field list.
func nameFields(n pkix.Name) []NameField {
	var out []NameField
	add := func(field, value string) {
		if value != "" {
			out = append(out, NameField{Field: field, Value: value})
		}
	}
	addAll := func(field string, values []string) {
		if len(values) > 0 {
			out = append(out, NameField{Field: field, Value: strings.Join(values, ", ")})
		}
	}
	add("Common Name", n.CommonName)
	addAll("Organization", n.Organization)
	addAll("Organizational Unit", n.OrganizationalUnit)
	addAll("Country", n.Country)
	addAll("Province / State", n.Province)
	addAll("Locality", n.Locality)
	addAll("Street Address", n.StreetAddress)
	addAll("Postal Code", n.PostalCode)
	add("Serial Number", n.SerialNumber)
	return out
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func uriStrings(uris []*url.URL) []string {
	out := make([]string, 0, len(uris))
	for _, u := range uris {
		out = append(out, u.String())
	}
	return out
}

// fullExtKeyUsage renders both known and unknown extended key usages.
func fullExtKeyUsage(cert *x509.Certificate) []string {
	out := extKeyUsageStrings(cert.ExtKeyUsage)
	for _, oid := range cert.UnknownExtKeyUsage {
		out = append(out, oid.String())
	}
	return out
}

func policyStrings(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.PolicyIdentifiers))
	for _, oid := range cert.PolicyIdentifiers {
		out = append(out, oid.String())
	}
	return out
}

// publicKeyDetail adds algorithm-specific colour: RSA exponent or EC curve.
func publicKeyDetail(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("exponent %d", k.E)
	case *ecdsa.PublicKey:
		return k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return ""
	}
}

// serialHex renders a serial as colon-separated uppercase hex, matching how
// most cert viewers display it.
func serialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	b := n.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	return colonHex(b)
}

// colonHex formats bytes as colon-separated uppercase hex ("AB:CD:…").
func colonHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	hexStr := hex.EncodeToString(b)
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		parts = append(parts, strings.ToUpper(hexStr[i:i+2]))
	}
	return strings.Join(parts, ":")
}

// extKnownNames maps common extension OIDs to readable names.
var extKnownNames = map[string]string{
	"2.5.29.14":               "Subject Key Identifier",
	"2.5.29.15":               "Key Usage",
	"2.5.29.17":               "Subject Alternative Name",
	"2.5.29.18":               "Issuer Alternative Name",
	"2.5.29.19":               "Basic Constraints",
	"2.5.29.31":               "CRL Distribution Points",
	"2.5.29.32":               "Certificate Policies",
	"2.5.29.35":               "Authority Key Identifier",
	"2.5.29.37":               "Extended Key Usage",
	"1.3.6.1.5.5.7.1.1":       "Authority Information Access",
	"1.3.6.1.4.1.11129.2.4.2": "Signed Certificate Timestamps",
}

func extensionSummaries(exts []pkix.Extension) []CertExtension {
	out := make([]CertExtension, 0, len(exts))
	for _, e := range exts {
		oid := e.Id.String()
		out = append(out, CertExtension{
			OID:      oid,
			Name:     extKnownNames[oid],
			Critical: e.Critical,
		})
	}
	return out
}

// humanDuration renders a duration in whole days (and years for long spans).
func humanDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days < 0 {
		days = -days
	}
	if days >= 365 {
		years := days / 365
		remDays := days % 365
		if remDays == 0 {
			return fmt.Sprintf("%d years", years)
		}
		return fmt.Sprintf("%d years, %d days", years, remDays)
	}
	return fmt.Sprintf("%d days", days)
}

// expiryNote describes validity relative to now in friendly terms.
func expiryNote(now, notBefore, notAfter time.Time) string {
	switch {
	case now.Before(notBefore):
		return "not valid until " + humanDuration(notBefore.Sub(now)) + " from now"
	case now.After(notAfter):
		return "expired " + humanDuration(now.Sub(notAfter)) + " ago"
	default:
		return "expires in " + humanDuration(notAfter.Sub(now))
	}
}
