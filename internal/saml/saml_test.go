package saml

import (
	"crypto/tls"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	appcrypto "github.com/default23/loupe/internal/crypto"
)

const (
	testIdPEntity = "https://idp.example.com/entity"
	testSPEntity  = "https://sp.example.com/entity"
	testACS       = "https://sp.example.com/saml/acs"
	testSSOURL    = "https://idp.example.com/sso"
)

func samlTime(offset time.Duration) string {
	return time.Now().Add(offset).UTC().Format("2006-01-02T15:04:05Z")
}

// buildSignedResponse creates a SAMLResponse with a signed assertion, using the
// given IdP key/cert, and returns it base64-encoded.
func buildSignedResponse(t *testing.T, certPEM, keyPEM, inResponseTo, audience, acs string) string {
	t.Helper()

	assertion := etree.NewElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	assertion.CreateAttr("ID", "_assertion1")
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", samlTime(0))
	assertion.CreateElement("saml:Issuer").SetText(testIdPEntity)

	subject := assertion.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nameID.SetText("user@example.com")
	sc := subject.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("InResponseTo", inResponseTo)
	scd.CreateAttr("Recipient", acs)
	scd.CreateAttr("NotOnOrAfter", samlTime(5*time.Minute))

	conditions := assertion.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", samlTime(-5*time.Minute))
	conditions.CreateAttr("NotOnOrAfter", samlTime(5*time.Minute))
	ar := conditions.CreateElement("saml:AudienceRestriction")
	ar.CreateElement("saml:Audience").SetText(audience)

	authn := assertion.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", samlTime(0))
	authn.CreateAttr("SessionIndex", "session-1")
	acx := authn.CreateElement("saml:AuthnContext")
	acx.CreateElement("saml:AuthnContextClassRef").
		SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

	attrStmt := assertion.CreateElement("saml:AttributeStatement")
	attr := attrStmt.CreateElement("saml:Attribute")
	attr.CreateAttr("Name", "email")
	attr.CreateElement("saml:AttributeValue").SetText("user@example.com")

	response := etree.NewElement("samlp:Response")
	response.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	response.CreateAttr("ID", "_response1")
	response.CreateAttr("Version", "2.0")
	response.CreateAttr("IssueInstant", samlTime(0))
	response.CreateAttr("Destination", acs)
	response.CreateAttr("InResponseTo", inResponseTo)
	respIssuer := response.CreateElement("saml:Issuer")
	respIssuer.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	respIssuer.SetText(testIdPEntity)
	status := response.CreateElement("samlp:Status")
	status.CreateElement("samlp:StatusCode").
		CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	response.AddChild(assertion)

	// Sign the whole Response envelope with the IdP key (as many IdPs do).
	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	ks := dsig.TLSCertKeyStore(tlsCert)
	ctx := dsig.NewDefaultSigningContext(ks)
	signedResponse, err := ctx.SignEnveloped(response)
	if err != nil {
		t.Fatalf("sign response: %v", err)
	}

	doc := etree.NewDocument()
	doc.SetRoot(signedResponse)
	xmlStr, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString([]byte(xmlStr))
}

func TestParseResponseValidatesSignedAssertion(t *testing.T) {
	idp, err := appcrypto.GenerateSPKeyPair(testIdPEntity)
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		IdPSSOURL:   testSSOURL,
		IdPEntityID: testIdPEntity,
		IdPCertsPEM: []string{idp.CertPEM},
		SPEntityID:  testSPEntity,
		ACSURL:      testACS,
		Binding:     "post",
	}

	const reqID = "_myrequest123"
	encoded := buildSignedResponse(t, idp.CertPEM, idp.KeyPEM, reqID, testSPEntity, testACS)

	res, vals, err := cfg.ParseResponse(encoded, reqID)
	if err != nil {
		t.Fatalf("ParseResponse returned error: %v", err)
	}
	for _, v := range vals {
		if !v.OK {
			t.Errorf("validation %q failed: %s", v.Name, v.Detail)
		}
	}
	if res.NameID != "user@example.com" {
		t.Errorf("expected NameID user@example.com, got %q", res.NameID)
	}
	if got := res.Attributes["email"]; len(got) != 1 || got[0] != "user@example.com" {
		t.Errorf("expected email attribute, got %v", res.Attributes["email"])
	}
	if res.InResponseTo != reqID {
		t.Errorf("expected InResponseTo %s, got %s", reqID, res.InResponseTo)
	}
	if res.SessionIndex != "session-1" {
		t.Errorf("expected SessionIndex session-1, got %q", res.SessionIndex)
	}
}

func TestParseResponseDetectsWrongAudienceAndInResponseTo(t *testing.T) {
	idp, err := appcrypto.GenerateSPKeyPair(testIdPEntity)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		IdPSSOURL:   testSSOURL,
		IdPEntityID: testIdPEntity,
		IdPCertsPEM: []string{idp.CertPEM},
		SPEntityID:  testSPEntity,
		ACSURL:      testACS,
		Binding:     "post",
	}

	// Wrong audience and a mismatching InResponseTo.
	encoded := buildSignedResponse(t, idp.CertPEM, idp.KeyPEM, "_other", "https://wrong.audience", testACS)

	_, vals, err := cfg.ParseResponse(encoded, "_expected")
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}
	find := func(name string) *bool {
		for i := range vals {
			if strings.Contains(vals[i].Name, name) {
				ok := vals[i].OK
				return &ok
			}
		}
		return nil
	}
	if v := find("InResponseTo"); v == nil || *v {
		t.Errorf("expected InResponseTo validation to fail")
	}
	if v := find("audience"); v == nil || *v {
		t.Errorf("expected audience validation to fail")
	}
}

func TestBuildStartSignedPost(t *testing.T) {
	sp, err := appcrypto.GenerateSPKeyPair(testSPEntity)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		IdPSSOURL:        testSSOURL,
		IdPEntityID:      testIdPEntity,
		SPEntityID:       testSPEntity,
		ACSURL:           testACS,
		Binding:          "post",
		SignAuthnRequest: true,
		SPCertPEM:        sp.CertPEM,
		SPKeyPEM:         sp.KeyPEM,
	}
	start, err := cfg.BuildStart("relay-1")
	if err != nil {
		t.Fatalf("BuildStart: %v", err)
	}
	if start.RequestID == "" {
		t.Error("expected a request ID")
	}
	if !strings.Contains(start.RequestXML, "AuthnRequest") {
		t.Error("expected AuthnRequest in XML")
	}
	if !strings.Contains(start.RequestXML, "Signature") {
		t.Error("expected a Signature in the signed POST AuthnRequest")
	}
	if !strings.Contains(start.PostHTML, "SAMLRequest") || !strings.Contains(start.PostHTML, testSSOURL) {
		t.Error("expected auto-submit POST form with SAMLRequest")
	}
}

func TestBuildStartRedirect(t *testing.T) {
	cfg := Config{
		IdPSSOURL:   testSSOURL,
		IdPEntityID: testIdPEntity,
		SPEntityID:  testSPEntity,
		ACSURL:      testACS,
		Binding:     "redirect",
	}
	start, err := cfg.BuildStart("relay-1")
	if err != nil {
		t.Fatalf("BuildStart: %v", err)
	}
	if !strings.Contains(start.RedirectURL, "SAMLRequest=") {
		t.Errorf("expected SAMLRequest in redirect URL, got %s", start.RedirectURL)
	}
	if !strings.HasPrefix(start.RedirectURL, testSSOURL) {
		t.Errorf("expected redirect to SSO URL, got %s", start.RedirectURL)
	}
}
