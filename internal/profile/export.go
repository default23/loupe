package profile

// Export is the portable, secret-free representation of a profile.
type Export struct {
	Name          string         `json:"name"`
	Protocol      Protocol       `json:"protocol"`
	OIDC          *OIDCConfig    `json:"oidc,omitempty"`
	SAML          *SAMLConfig    `json:"saml,omitempty"`
	CustomHeaders []CustomHeader `json:"custom_headers,omitempty"`
}

// ToExport returns a secret-free export of the profile. Secret header values,
// client secrets, and SP private keys are omitted; the recipient must re-enter
// them.
func (p *Profile) ToExport() Export {
	headers := make([]CustomHeader, len(p.CustomHeaders))
	for i, h := range p.CustomHeaders {
		hh := h
		if h.Secret {
			hh.Value = "" // do not export secret values
		}
		headers[i] = hh
	}
	return Export{
		Name:          p.Name,
		Protocol:      p.Protocol,
		OIDC:          p.OIDC,
		SAML:          p.SAML,
		CustomHeaders: headers,
	}
}

// FromExport builds a new (unsaved) profile from an export. Secrets start empty.
func FromExport(e Export) *Profile {
	return &Profile{
		Name:          e.Name,
		Protocol:      e.Protocol,
		OIDC:          e.OIDC,
		SAML:          e.SAML,
		CustomHeaders: e.CustomHeaders,
	}
}
