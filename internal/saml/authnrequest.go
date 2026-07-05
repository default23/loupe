package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/beevik/etree"
)

// maxInflated bounds DEFLATE decompression to guard against decompression bombs.
const maxInflated = 5 << 20

// AuthnRequestInfo holds the decoded, human-readable form of a SAML AuthnRequest
// plus the fields most useful for inspection.
type AuthnRequestInfo struct {
	XML                   string
	Binding               string // "redirect" (DEFLATE) or "post" (raw base64)
	ID                    string
	Issuer                string
	Destination           string
	ACSURL                string
	ProtocolBinding       string
	IssueInstant          string
	ForceAuthn            string
	IsPassive             string
	NameIDFormat          string
	RequestedAuthnContext []string
	Signed                bool
}

// DecodeAuthnRequest decodes a base64-encoded SAML AuthnRequest from either
// binding. HTTP-Redirect carries raw-DEFLATE-compressed XML; HTTP-POST carries
// the XML directly. The input may still be URL-encoded (as taken straight from a
// SAMLRequest query parameter); that is unwrapped first. Standalone: no Config,
// Profile, or network needed.
func DecodeAuthnRequest(encoded string) (*AuthnRequestInfo, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fmt.Errorf("empty input")
	}
	// A pasted SAMLRequest value may be percent-encoded; unwrap only when it
	// clearly is, so we don't turn a legitimate '+' in base64 into a space.
	if strings.Contains(encoded, "%") {
		if dec, err := url.QueryUnescape(encoded); err == nil {
			encoded = strings.TrimSpace(dec)
		}
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(encoded); err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
	}

	binding := "post"
	xmlBytes := raw
	if !looksLikeXML(raw) {
		inflated, ierr := inflate(raw)
		if ierr != nil || !looksLikeXML(inflated) {
			return nil, fmt.Errorf("decoded bytes are neither XML nor DEFLATE-compressed XML")
		}
		xmlBytes = inflated
		binding = "redirect"
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, fmt.Errorf("parse XML: %w", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "AuthnRequest" {
		tag := "<none>"
		if root != nil {
			tag = root.Tag
		}
		return nil, fmt.Errorf("root element is %s, expected AuthnRequest", tag)
	}

	disp := etree.NewDocument()
	disp.SetRoot(root.Copy())
	disp.Indent(2)
	pretty, _ := disp.WriteToString()

	info := &AuthnRequestInfo{
		XML:             pretty,
		Binding:         binding,
		ID:              root.SelectAttrValue("ID", ""),
		Destination:     root.SelectAttrValue("Destination", ""),
		ACSURL:          root.SelectAttrValue("AssertionConsumerServiceURL", ""),
		ProtocolBinding: root.SelectAttrValue("ProtocolBinding", ""),
		IssueInstant:    root.SelectAttrValue("IssueInstant", ""),
		ForceAuthn:      root.SelectAttrValue("ForceAuthn", ""),
		IsPassive:       root.SelectAttrValue("IsPassive", ""),
	}
	if iss := childByLocal(root, "Issuer"); iss != nil {
		info.Issuer = strings.TrimSpace(iss.Text())
	}
	if pol := childByLocal(root, "NameIDPolicy"); pol != nil {
		info.NameIDFormat = pol.SelectAttrValue("Format", "")
	}
	if rac := childByLocal(root, "RequestedAuthnContext"); rac != nil {
		for _, ref := range rac.ChildElements() {
			if ref.Tag == "AuthnContextClassRef" {
				info.RequestedAuthnContext = append(info.RequestedAuthnContext, strings.TrimSpace(ref.Text()))
			}
		}
	}
	info.Signed = childByLocal(root, "Signature") != nil

	return info, nil
}

// childByLocal finds the first direct child element with the given local name,
// ignoring its namespace prefix (samlp:/saml: vary by IdP).
func childByLocal(el *etree.Element, local string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == local {
			return c
		}
	}
	return nil
}

func looksLikeXML(b []byte) bool {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM
	t := bytes.TrimLeft(b, " \t\r\n")
	return len(t) > 0 && t[0] == '<'
}

func inflate(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, maxInflated))
}
