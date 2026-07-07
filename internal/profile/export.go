package profile

// Export is the portable representation of a profile. It includes secret
// material (client secret, SP private key, secret header values) so an import
// restores a fully working profile without re-entering anything. The exported
// JSON therefore contains plaintext secrets — treat the file as sensitive.
type Export struct {
	Name          string         `json:"name"`
	Protocol      Protocol       `json:"protocol"`
	OIDC          *OIDCConfig    `json:"oidc,omitempty"`
	SAML          *SAMLConfig    `json:"saml,omitempty"`
	CustomHeaders []CustomHeader `json:"custom_headers,omitempty"`
	Secrets       *Secrets       `json:"secrets,omitempty"`
}

// ToExport returns a complete export of the profile, including secrets. Secret
// header values are kept inline on CustomHeaders, and client secret / SP private
// key are carried in Secrets so FromExport can rebuild the profile verbatim.
func (p *Profile) ToExport() Export {
	headers := make([]CustomHeader, len(p.CustomHeaders))
	copy(headers, p.CustomHeaders)

	var secrets *Secrets
	if p.Secrets.needsStorage() {
		s := p.Secrets
		secrets = &s
	}
	return Export{
		Name:          p.Name,
		Protocol:      p.Protocol,
		OIDC:          p.OIDC,
		SAML:          p.SAML,
		CustomHeaders: headers,
		Secrets:       secrets,
	}
}

// FromExport builds a new (unsaved) profile from an export, restoring secrets
// when present.
func FromExport(e Export) *Profile {
	p := &Profile{
		Name:          e.Name,
		Protocol:      e.Protocol,
		OIDC:          e.OIDC,
		SAML:          e.SAML,
		CustomHeaders: e.CustomHeaders,
	}
	if e.Secrets != nil {
		p.Secrets = *e.Secrets
	}
	return p
}
