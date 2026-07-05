// Package profile defines SSO configuration profiles and their persistence.
package profile

import "time"

// Protocol identifies which SSO protocol a profile targets.
type Protocol string

const (
	OIDC Protocol = "oidc"
	SAML Protocol = "saml"
)

// Header phases: which outbound server-to-server calls a custom header applies to.
const (
	PhaseDiscovery = "discovery"
	PhaseToken     = "token"
	PhaseUserinfo  = "userinfo"
	PhaseJWKS      = "jwks"
	PhaseMetadata  = "metadata"
)

// AllHeaderPhases lists the selectable phases for custom headers.
var AllHeaderPhases = []string{PhaseDiscovery, PhaseToken, PhaseUserinfo, PhaseJWKS, PhaseMetadata}

// CustomHeader is an extra HTTP header injected into outbound provider calls.
// Note: it applies only to server-to-server requests the app makes directly,
// not to browser redirects to the authorization endpoint / ACS.
type CustomHeader struct {
	Name      string   `json:"name"`
	Value     string   `json:"value,omitempty"`
	Secret    bool     `json:"secret"`
	AppliesTo []string `json:"applies_to"`
}

// KV is an ordered key/value pair (extra auth params keep insertion order).
type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// OIDCConfig holds non-secret OpenID Connect relying-party settings.
type OIDCConfig struct {
	Issuer                  string   `json:"issuer"`
	DiscoveryURL            string   `json:"discovery_url"`
	AuthorizationEndpoint   string   `json:"authorization_endpoint"`
	TokenEndpoint           string   `json:"token_endpoint"`
	UserinfoEndpoint        string   `json:"userinfo_endpoint"`
	JWKSURI                 string   `json:"jwks_uri"`
	ClientID                string   `json:"client_id"`
	Scopes                  []string `json:"scopes"`
	ResponseType            string   `json:"response_type"`              // "code"
	PKCEMethod              string   `json:"pkce_method"`                // S256|plain|none
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"` // client_secret_basic|client_secret_post|none
	Prompt                  string   `json:"prompt"`
	ACRValues               string   `json:"acr_values"`
	ExtraAuthParams         []KV     `json:"extra_auth_params"`
}

// SAMLConfig holds non-secret SAML 2.0 service-provider settings.
type SAMLConfig struct {
	IdPEntityID              string   `json:"idp_entity_id"`
	IdPSSOURL                string   `json:"idp_sso_url"`
	IdPSSOBinding            string   `json:"idp_sso_binding"` // redirect|post
	IdPSLOURL                string   `json:"idp_slo_url"`
	IdPCertsPEM              []string `json:"idp_certs_pem"` // IdP signing certs
	SPEntityID               string   `json:"sp_entity_id"`
	SPCertPEM                string   `json:"sp_cert_pem"` // public SP cert (non-secret)
	NameIDFormat             string   `json:"nameid_format"`
	SignAuthnRequest         bool     `json:"sign_authn_request"`
	WantAssertionsSigned     bool     `json:"want_assertions_signed"`
	AllowAssertionEncryption bool     `json:"allow_assertion_encryption"`
	ForceAuthn               bool     `json:"force_authn"`
	IsPassive                bool     `json:"is_passive"`
	RequestedAuthnContext    []string `json:"requested_authn_context"`
}

// Secrets is the encrypted-at-rest material for a profile.
type Secrets struct {
	OIDCClientSecret string            `json:"oidc_client_secret,omitempty"`
	SPPrivateKeyPEM  string            `json:"sp_private_key_pem,omitempty"`
	HeaderValues     map[string]string `json:"header_values,omitempty"` // keyed by header index
}

func (s Secrets) needsStorage() bool {
	return s.OIDCClientSecret != "" || s.SPPrivateKeyPEM != "" || len(s.HeaderValues) > 0
}

// Profile is a full configuration profile with decrypted secrets in memory.
type Profile struct {
	ID            int64
	Name          string
	Protocol      Protocol
	OIDC          *OIDCConfig
	SAML          *SAMLConfig
	CustomHeaders []CustomHeader
	Secrets       Secrets
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Summary is a lightweight profile listing without secrets.
type Summary struct {
	ID        int64
	Name      string
	Protocol  Protocol
	UpdatedAt time.Time
}

// persistedConfig is the JSON stored in the profiles.config column.
type persistedConfig struct {
	OIDC *OIDCConfig `json:"oidc,omitempty"`
	SAML *SAMLConfig `json:"saml,omitempty"`
}

// HeadersFor returns the custom headers (with values) that apply to a phase.
func (p *Profile) HeadersFor(phase string) []CustomHeader {
	var out []CustomHeader
	for _, h := range p.CustomHeaders {
		for _, a := range h.AppliesTo {
			if a == phase {
				out = append(out, h)
				break
			}
		}
	}
	return out
}
