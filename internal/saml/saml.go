// Package saml implements the SAML 2.0 service-provider flow: building and
// (optionally) signing the AuthnRequest, encoding it for the HTTP-Redirect or
// HTTP-POST binding, and validating the SAMLResponse at the ACS.
package saml

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/default23/loupe/internal/inspect"
	"github.com/default23/loupe/internal/profile"
)

// Config is the effective SAML configuration for a login.
type Config struct {
	IdPSSOURL             string
	IdPEntityID           string
	IdPCertsPEM           []string
	SPEntityID            string
	ACSURL                string
	NameIDFormat          string
	Binding               string // redirect|post
	SignAuthnRequest      bool
	ForceAuthn            bool
	IsPassive             bool
	RequestedAuthnContext []string
	SPCertPEM             string
	SPKeyPEM              string
}

// ConfigFromProfile builds a Config from a profile's SAML settings.
func ConfigFromProfile(p *profile.Profile, acsURL string) Config {
	s := p.SAML
	spEntity := s.SPEntityID
	if spEntity == "" {
		spEntity = acsURL
	}
	return Config{
		IdPSSOURL:             s.IdPSSOURL,
		IdPEntityID:           s.IdPEntityID,
		IdPCertsPEM:           s.IdPCertsPEM,
		SPEntityID:            spEntity,
		ACSURL:                acsURL,
		NameIDFormat:          s.NameIDFormat,
		Binding:               s.IdPSSOBinding,
		SignAuthnRequest:      s.SignAuthnRequest,
		ForceAuthn:            s.ForceAuthn,
		IsPassive:             s.IsPassive,
		RequestedAuthnContext: s.RequestedAuthnContext,
		SPCertPEM:             s.SPCertPEM,
		SPKeyPEM:              p.Secrets.SPPrivateKeyPEM,
	}
}

// provider builds a configured gosaml2 SAMLServiceProvider.
func (c Config) provider() (*saml2.SAMLServiceProvider, error) {
	certStore := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{}}
	for _, p := range c.IdPCertsPEM {
		cert, err := parseCert(p)
		if err != nil {
			return nil, fmt.Errorf("parse IdP certificate: %w", err)
		}
		certStore.Roots = append(certStore.Roots, cert)
	}

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      c.IdPSSOURL,
		IdentityProviderIssuer:      c.IdPEntityID,
		AssertionConsumerServiceURL: c.ACSURL,
		ServiceProviderIssuer:       c.SPEntityID,
		SignAuthnRequests:           c.SignAuthnRequest,
		AudienceURI:                 c.SPEntityID,
		NameIdFormat:                c.NameIDFormat,
		ForceAuthn:                  c.ForceAuthn,
		IsPassive:                   c.IsPassive,
		IDPCertificateStore:         certStore,
		SkipSignatureValidation:     len(certStore.Roots) == 0,
		MaximumDecompressedBodySize: 5 << 20,
		Clock:                       dsig.NewRealClock(),
	}

	if len(c.RequestedAuthnContext) > 0 {
		sp.RequestedAuthnContext = &saml2.RequestedAuthnContext{
			Comparison: "exact",
			Contexts:   c.RequestedAuthnContext,
		}
	}

	if c.SPCertPEM != "" && c.SPKeyPEM != "" {
		tlsCert, err := tls.X509KeyPair([]byte(c.SPCertPEM), []byte(c.SPKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("load SP keypair: %w", err)
		}
		signer, ok := tlsCert.PrivateKey.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("SP private key is not a crypto.Signer")
		}
		ks := &saml2.KeyStore{Signer: signer, Cert: tlsCert.Certificate[0]}
		_ = sp.SetSPSigningKeyStore(ks)
		_ = sp.SetSPKeyStore(ks)
	}

	return sp, nil
}

// Start holds a built AuthnRequest ready to send to the IdP.
type Start struct {
	RequestID   string
	Binding     string
	RedirectURL string
	PostHTML    string
	RequestXML  string
	Destination string
}

// BuildStart builds and encodes the AuthnRequest for the configured binding.
func (c Config) BuildStart(relayState string) (*Start, error) {
	sp, err := c.provider()
	if err != nil {
		return nil, err
	}

	// POST binding carries the signature inside the XML; Redirect signs the query.
	var doc *etree.Document
	if c.Binding == "post" && c.SignAuthnRequest {
		doc, err = sp.BuildAuthRequestDocument()
	} else {
		doc, err = sp.BuildAuthRequestDocumentNoSig()
	}
	if err != nil {
		return nil, fmt.Errorf("build AuthnRequest: %w", err)
	}

	requestID := doc.Root().SelectAttrValue("ID", "")

	// Indent a copy for display only — indenting the real doc would add
	// whitespace to the bytes actually sent (and break a POST signature).
	disp := etree.NewDocument()
	disp.SetRoot(doc.Root().Copy())
	disp.Indent(2)
	xmlStr, _ := disp.WriteToString()

	start := &Start{
		RequestID:   requestID,
		Binding:     c.Binding,
		RequestXML:  xmlStr,
		Destination: c.IdPSSOURL,
	}

	if c.Binding == "post" {
		body, err := sp.BuildAuthBodyPostFromDocument(relayState, doc)
		if err != nil {
			return nil, fmt.Errorf("encode POST body: %w", err)
		}
		start.PostHTML = string(body)
	} else {
		u, err := sp.BuildAuthURLRedirect(relayState, doc)
		if err != nil {
			return nil, fmt.Errorf("encode redirect URL: %w", err)
		}
		start.RedirectURL = u
	}

	return start, nil
}

// Result holds the decoded, validated SAMLResponse data.
type Result struct {
	NameID       string
	SessionIndex string
	AuthnInstant string
	Attributes   map[string][]string
	ResponseXML  string
	InResponseTo string
}

// ParseResponse validates and decodes an encoded SAMLResponse, returning the
// result, granular validations, and a fatal error if validation could not
// complete (e.g. bad signature).
func (c Config) ParseResponse(encodedResponse, expectedRequestID string) (*Result, []inspect.Validation, error) {
	sp, err := c.provider()
	if err != nil {
		return nil, nil, err
	}

	res := &Result{Attributes: map[string][]string{}}
	res.ResponseXML, res.InResponseTo = decodeResponseXML(encodedResponse)

	var vals []inspect.Validation

	info, err := sp.RetrieveAssertionInfo(encodedResponse)
	if err != nil {
		vals = append(vals, inspect.Validation{Name: "assertion validation", OK: false, Detail: err.Error()})
		return res, vals, err
	}

	// Signature. RetrieveAssertionInfo returns an error on a bad signature, so
	// reaching here means it is valid (or was skipped for lack of a cert).
	if c.SkipSig() {
		vals = append(vals, inspect.Validation{Name: "signature", OK: true, Detail: "skipped: no IdP certificate configured — signature NOT verified"})
	} else {
		vals = append(vals, inspect.Validation{Name: "signature (IdP certificate)", OK: true})
	}

	// InResponseTo correlation.
	vals = append(vals, inspect.Validation{
		Name:   "InResponseTo matches AuthnRequest",
		OK:     expectedRequestID != "" && res.InResponseTo == expectedRequestID,
		Detail: fmt.Sprintf("expected=%s got=%s", expectedRequestID, res.InResponseTo),
	})

	if w := info.WarningInfo; w != nil {
		vals = append(vals,
			inspect.Validation{Name: "audience valid", OK: !w.NotInAudience},
			inspect.Validation{Name: "time conditions valid (NotBefore/NotOnOrAfter)", OK: !w.InvalidTime},
		)
		if w.OneTimeUse {
			vals = append(vals, inspect.Validation{Name: "one-time-use condition present", OK: true, Detail: "assertion marked OneTimeUse"})
		}
	}

	res.NameID = info.NameID
	res.SessionIndex = info.SessionIndex
	if info.AuthnInstant != nil {
		res.AuthnInstant = info.AuthnInstant.String()
	}
	for name, attr := range info.Values {
		var vlist []string
		for _, v := range attr.Values {
			vlist = append(vlist, v.Value)
		}
		res.Attributes[name] = vlist
	}

	return res, vals, nil
}

// SkipSig reports whether signature validation is skipped (no IdP certs).
func (c Config) SkipSig() bool { return len(c.IdPCertsPEM) == 0 }

func decodeResponseXML(encoded string) (pretty, inResponseTo string) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", ""
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return string(raw), ""
	}
	if root := doc.Root(); root != nil {
		inResponseTo = root.SelectAttrValue("InResponseTo", "")
	}
	doc.Indent(2)
	s, _ := doc.WriteToString()
	return s, inResponseTo
}

func parseCert(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}
