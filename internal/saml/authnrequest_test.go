package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"strings"
	"testing"
)

const sampleAuthnRequest = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc123" Version="2.0" IssueInstant="2026-07-05T10:00:00Z" Destination="https://idp.example.com/sso" AssertionConsumerServiceURL="https://sp.example.com/saml/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ForceAuthn="true"><saml:Issuer>https://sp.example.com</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/><samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`

func deflateBase64(t *testing.T, xml string) string {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write([]byte(xml))
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func assertCommonFields(t *testing.T, info *AuthnRequestInfo) {
	t.Helper()
	if info.ID != "_abc123" {
		t.Errorf("ID = %q, want _abc123", info.ID)
	}
	if info.Issuer != "https://sp.example.com" {
		t.Errorf("Issuer = %q", info.Issuer)
	}
	if info.Destination != "https://idp.example.com/sso" {
		t.Errorf("Destination = %q", info.Destination)
	}
	if info.ACSURL != "https://sp.example.com/saml/acs" {
		t.Errorf("ACSURL = %q", info.ACSURL)
	}
	if info.NameIDFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" {
		t.Errorf("NameIDFormat = %q", info.NameIDFormat)
	}
	if len(info.RequestedAuthnContext) != 1 ||
		!strings.Contains(info.RequestedAuthnContext[0], "PasswordProtectedTransport") {
		t.Errorf("RequestedAuthnContext = %v", info.RequestedAuthnContext)
	}
	if !strings.Contains(info.XML, "<samlp:AuthnRequest") {
		t.Errorf("pretty XML missing root element:\n%s", info.XML)
	}
}

func TestDecodeAuthnRequestPOSTBinding(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(sampleAuthnRequest))
	info, err := DecodeAuthnRequest(enc)
	if err != nil {
		t.Fatal(err)
	}
	if info.Binding != "post" {
		t.Errorf("Binding = %q, want post", info.Binding)
	}
	assertCommonFields(t, info)
}

func TestDecodeAuthnRequestRedirectBinding(t *testing.T) {
	info, err := DecodeAuthnRequest(deflateBase64(t, sampleAuthnRequest))
	if err != nil {
		t.Fatal(err)
	}
	if info.Binding != "redirect" {
		t.Errorf("Binding = %q, want redirect", info.Binding)
	}
	assertCommonFields(t, info)
}

func TestDecodeAuthnRequestURLEncoded(t *testing.T) {
	// A percent-encoded redirect SAMLRequest value should still decode.
	enc := deflateBase64(t, sampleAuthnRequest)
	urlEnc := strings.ReplaceAll(enc, "+", "%2B")
	urlEnc = strings.ReplaceAll(urlEnc, "/", "%2F")
	urlEnc = strings.ReplaceAll(urlEnc, "=", "%3D")
	info, err := DecodeAuthnRequest(urlEnc)
	if err != nil {
		t.Fatal(err)
	}
	assertCommonFields(t, info)
}

func TestDecodeAuthnRequestRejectsGarbage(t *testing.T) {
	if _, err := DecodeAuthnRequest("not-base64!!"); err == nil {
		t.Fatal("expected error for non-base64 input")
	}
	// Valid base64, valid XML, but wrong root element.
	notAR := base64.StdEncoding.EncodeToString([]byte(`<Response xmlns="x"/>`))
	if _, err := DecodeAuthnRequest(notAR); err == nil {
		t.Fatal("expected error for non-AuthnRequest root")
	}
}
