package profile

import (
	"encoding/xml"
	"strings"
)

// SP metadata XML structures (marshalled to produce SP EntityDescriptor).
type spEntityDescriptor struct {
	XMLName    xml.Name        `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID   string          `xml:"entityID,attr"`
	SPSSODescr spSSODescriptor `xml:"SPSSODescriptor"`
}

type spSSODescriptor struct {
	AuthnRequestsSigned      bool              `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned     bool              `xml:"WantAssertionsSigned,attr"`
	ProtocolSupport          string            `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors           []spKeyDescriptor `xml:"KeyDescriptor"`
	NameIDFormat             string            `xml:"NameIDFormat,omitempty"`
	AssertionConsumerService spEndpoint        `xml:"AssertionConsumerService"`
}

type spKeyDescriptor struct {
	Use     string    `xml:"use,attr"`
	KeyInfo dsKeyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type dsKeyInfo struct {
	X509Data dsX509Data `xml:"X509Data"`
}

type dsX509Data struct {
	X509Certificate string `xml:"X509Certificate"`
}

type spEndpoint struct {
	Binding   string `xml:"Binding,attr"`
	Location  string `xml:"Location,attr"`
	Index     int    `xml:"index,attr"`
	IsDefault bool   `xml:"isDefault,attr"`
}

// SPMetadataXML builds the SAML SP metadata document for a profile, using acsURL
// as the AssertionConsumerService location.
func (c *SAMLConfig) SPMetadataXML(acsURL string) ([]byte, error) {
	ed := spEntityDescriptor{
		EntityID: c.SPEntityID,
		SPSSODescr: spSSODescriptor{
			AuthnRequestsSigned:  c.SignAuthnRequest,
			WantAssertionsSigned: c.WantAssertionsSigned,
			ProtocolSupport:      "urn:oasis:names:tc:SAML:2.0:protocol",
			NameIDFormat:         c.NameIDFormat,
			AssertionConsumerService: spEndpoint{
				Binding:   BindingHTTPPOST,
				Location:  acsURL,
				Index:     0,
				IsDefault: true,
			},
		},
	}

	if cert := certBody(c.SPCertPEM); cert != "" {
		ki := dsKeyInfo{X509Data: dsX509Data{X509Certificate: cert}}
		ed.SPSSODescr.KeyDescriptors = []spKeyDescriptor{
			{Use: "signing", KeyInfo: ki},
			{Use: "encryption", KeyInfo: ki},
		}
	}

	out, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

// certBody strips PEM armor and whitespace, returning the base64 DER body.
func certBody(pemStr string) string {
	pemStr = strings.TrimSpace(pemStr)
	if pemStr == "" {
		return ""
	}
	var b strings.Builder
	for _, line := range strings.Split(pemStr, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		b.WriteString(line)
	}
	return b.String()
}
