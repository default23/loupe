package web

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/default23/loupe/internal/crypto"
	"github.com/default23/loupe/internal/profile"
)

// maxRows bounds indexed form-row parsing (headers, extra params).
const maxRows = 200

// spareRows is how many blank rows to render for adding new headers/params.
const spareRows = 3

func (s *Server) handleProfilesList(w http.ResponseWriter, r *http.Request) {
	list, err := s.profiles.List(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, "profiles_list.html", map[string]any{
		"Title":    "Profiles",
		"Profiles": list,
		"HasKey":   s.cipher != nil,
	})
}

func (s *Server) handleProfileNew(w http.ResponseWriter, r *http.Request) {
	proto := profile.Protocol(r.URL.Query().Get("protocol"))
	p := defaultProfile(proto)
	if p == nil {
		http.Error(w, "unknown protocol", http.StatusBadRequest)
		return
	}
	s.renderProfileForm(w, r, p, true, "", "")
}

func (s *Server) handleProfileCreate(w http.ResponseWriter, r *http.Request) {
	p, err := parseProfileForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch r.FormValue("action") {
	case "import":
		notice, ierr := s.applyImport(r, p)
		s.renderProfileForm(w, r, p, true, notice, ierr)
	case "gen_sp_cert":
		notice, gerr := genSPCert(p)
		s.renderProfileForm(w, r, p, true, notice, gerr)
	default:
		if err := s.saveNew(r, p); err != nil {
			s.renderProfileForm(w, r, p, true, "", err.Error())
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/profiles/%d", p.ID), http.StatusSeeOther)
	}
}

func (s *Server) handleProfileEdit(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.profiles.Get(r.Context(), id)
	if errors.Is(err, profile.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.renderProfileForm(w, r, p, false, "", "")
}

func (s *Server) handleProfileUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := parseProfileForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.ID = id

	switch r.FormValue("action") {
	case "import":
		notice, ierr := s.applyImport(r, p)
		s.renderProfileForm(w, r, p, false, notice, ierr)
	case "gen_sp_cert":
		notice, gerr := genSPCert(p)
		s.renderProfileForm(w, r, p, false, notice, gerr)
	default:
		if err := s.saveExisting(r, p); err != nil {
			s.renderProfileForm(w, r, p, false, "", err.Error())
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/profiles/%d", p.ID), http.StatusSeeOther)
	}
}

func (s *Server) handleProfileDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.profiles.Delete(r.Context(), id); err != nil && !errors.Is(err, profile.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/profiles", http.StatusSeeOther)
}

func (s *Server) handleSPMetadata(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.profiles.Get(r.Context(), id)
	if errors.Is(err, profile.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	if p.SAML == nil {
		http.Error(w, "not a SAML profile", http.StatusBadRequest)
		return
	}
	xml, err := p.SAML.SPMetadataXML(s.acsURL())
	if err != nil {
		s.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="sp-metadata-%d.xml"`, id))
	_, _ = w.Write(xml)
}

func (s *Server) handleProfileExport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.profiles.Get(r.Context(), id)
	if errors.Is(err, profile.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	data, err := json.MarshalIndent(p.ToExport(), "", "  ")
	if err != nil {
		s.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="profile-%d.json"`, id))
	_, _ = w.Write(data)
}

func (s *Server) handleProfileImportForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "profiles_import.html", map[string]any{"Title": "Import profile"})
}

func (s *Server) handleProfileImport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var exp profile.Export
	if err := json.Unmarshal([]byte(r.FormValue("json")), &exp); err != nil {
		s.render(w, r, "profiles_import.html", map[string]any{
			"Title": "Import profile",
			"Error": "invalid JSON: " + err.Error(),
			"JSON":  r.FormValue("json"),
		})
		return
	}
	p := profile.FromExport(exp)
	if err := s.saveNew(r, p); err != nil {
		s.render(w, r, "profiles_import.html", map[string]any{
			"Title": "Import profile",
			"Error": err.Error(),
			"JSON":  r.FormValue("json"),
		})
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/profiles/%d", p.ID), http.StatusSeeOther)
}

// --- save helpers ---

func (s *Server) saveNew(r *http.Request, p *profile.Profile) error {
	if err := validateProfile(p); err != nil {
		return err
	}
	ensureSPCert(p)
	return s.profiles.Create(r.Context(), p)
}

func (s *Server) saveExisting(r *http.Request, p *profile.Profile) error {
	if err := validateProfile(p); err != nil {
		return err
	}
	ensureSPCert(p)
	return s.profiles.Update(r.Context(), p)
}

func validateProfile(p *profile.Profile) error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("name is required")
	}
	switch p.Protocol {
	case profile.OIDC:
		if p.OIDC.ClientID == "" {
			return errors.New("client_id is required")
		}
		if p.OIDC.AuthorizationEndpoint == "" {
			return errors.New("authorization_endpoint is required (import discovery or fill manually)")
		}
	case profile.SAML:
		if p.SAML.IdPSSOURL == "" {
			return errors.New("IdP SSO URL is required (import metadata or fill manually)")
		}
	default:
		return errors.New("unknown protocol")
	}
	return nil
}

// ensureSPCert generates an SP keypair when signing/encryption is enabled but no
// key exists yet.
func ensureSPCert(p *profile.Profile) {
	if p.SAML == nil {
		return
	}
	if (p.SAML.SignAuthnRequest || p.SAML.AllowAssertionEncryption) && p.Secrets.SPPrivateKeyPEM == "" {
		_, _ = genSPCert(p)
	}
}

func genSPCert(p *profile.Profile) (string, string) {
	if p.SAML == nil {
		return "", "SP certificate applies to SAML profiles only"
	}
	cn := p.SAML.SPEntityID
	if cn == "" {
		cn = "loupe-sp"
	}
	kp, err := crypto.GenerateSPKeyPair(cn)
	if err != nil {
		return "", err.Error()
	}
	p.SAML.SPCertPEM = kp.CertPEM
	p.Secrets.SPPrivateKeyPEM = kp.KeyPEM
	return "Generated a new SP certificate and private key (remember to Save).", ""
}

// applyImport runs OIDC discovery or SAML metadata import, merging results into p.
func (s *Server) applyImport(r *http.Request, p *profile.Profile) (notice, errMsg string) {
	client := &http.Client{Timeout: 15e9}
	switch p.Protocol {
	case profile.OIDC:
		src := firstNonEmpty(p.OIDC.DiscoveryURL, p.OIDC.Issuer)
		if src == "" {
			return "", "enter an issuer or discovery URL first"
		}
		disc, err := profile.FetchOIDCDiscovery(r.Context(), client, src)
		if err != nil {
			return "", err.Error()
		}
		p.OIDC.Issuer = firstNonEmpty(disc.Issuer, p.OIDC.Issuer)
		p.OIDC.DiscoveryURL = disc.DiscoveryURL
		p.OIDC.AuthorizationEndpoint = disc.AuthorizationEndpoint
		p.OIDC.TokenEndpoint = disc.TokenEndpoint
		p.OIDC.UserinfoEndpoint = disc.UserinfoEndpoint
		p.OIDC.JWKSURI = disc.JWKSURI
		if len(p.OIDC.Scopes) == 0 && len(disc.Scopes) > 0 {
			p.OIDC.Scopes = disc.Scopes
		}
		return "Imported endpoints from discovery document.", ""
	case profile.SAML:
		if xmlText := strings.TrimSpace(r.FormValue("saml_metadata_xml")); xmlText != "" {
			cfg, err := profile.ParseSAMLMetadata([]byte(xmlText))
			if err != nil {
				return "", err.Error()
			}
			mergeSAMLImport(p, cfg)
			return "Imported IdP settings from pasted metadata.", ""
		}
		url := strings.TrimSpace(r.FormValue("saml_metadata_url"))
		if url == "" {
			return "", "provide a metadata URL or paste metadata XML"
		}
		cfg, err := profile.FetchSAMLMetadata(r.Context(), client, url)
		if err != nil {
			return "", err.Error()
		}
		mergeSAMLImport(p, cfg)
		return "Imported IdP settings from metadata URL.", ""
	}
	return "", "unknown protocol"
}

func mergeSAMLImport(p *profile.Profile, cfg *profile.SAMLConfig) {
	p.SAML.IdPEntityID = cfg.IdPEntityID
	p.SAML.IdPSSOURL = cfg.IdPSSOURL
	p.SAML.IdPSSOBinding = cfg.IdPSSOBinding
	p.SAML.IdPSLOURL = cfg.IdPSLOURL
	if len(cfg.IdPCertsPEM) > 0 {
		p.SAML.IdPCertsPEM = cfg.IdPCertsPEM
	}
}

// --- form parsing ---

func defaultProfile(proto profile.Protocol) *profile.Profile {
	switch proto {
	case profile.OIDC:
		return &profile.Profile{
			Protocol: profile.OIDC,
			OIDC: &profile.OIDCConfig{
				Scopes:                  []string{"openid", "profile", "email"},
				ResponseType:            "code",
				PKCEMethod:              "S256",
				TokenEndpointAuthMethod: "client_secret_basic",
			},
		}
	case profile.SAML:
		return &profile.Profile{
			Protocol: profile.SAML,
			SAML: &profile.SAMLConfig{
				IdPSSOBinding:        "redirect",
				NameIDFormat:         "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				WantAssertionsSigned: true,
			},
		}
	}
	return nil
}

func parseProfileForm(r *http.Request) (*profile.Profile, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	proto := profile.Protocol(r.FormValue("protocol"))
	p := &profile.Profile{
		Name:          strings.TrimSpace(r.FormValue("name")),
		Protocol:      proto,
		CustomHeaders: parseHeaders(r),
	}

	switch proto {
	case profile.OIDC:
		p.OIDC = &profile.OIDCConfig{
			Issuer:                  strings.TrimSpace(r.FormValue("oidc_issuer")),
			DiscoveryURL:            strings.TrimSpace(r.FormValue("oidc_discovery_url")),
			AuthorizationEndpoint:   strings.TrimSpace(r.FormValue("oidc_authorization_endpoint")),
			TokenEndpoint:           strings.TrimSpace(r.FormValue("oidc_token_endpoint")),
			UserinfoEndpoint:        strings.TrimSpace(r.FormValue("oidc_userinfo_endpoint")),
			JWKSURI:                 strings.TrimSpace(r.FormValue("oidc_jwks_uri")),
			ClientID:                strings.TrimSpace(r.FormValue("oidc_client_id")),
			Scopes:                  splitScopes(r.FormValue("oidc_scopes")),
			ResponseType:            firstNonEmpty(r.FormValue("oidc_response_type"), "code"),
			PKCEMethod:              firstNonEmpty(r.FormValue("oidc_pkce_method"), "S256"),
			TokenEndpointAuthMethod: firstNonEmpty(r.FormValue("oidc_token_auth_method"), "client_secret_basic"),
			Prompt:                  strings.TrimSpace(r.FormValue("oidc_prompt")),
			ACRValues:               strings.TrimSpace(r.FormValue("oidc_acr_values")),
			ExtraAuthParams:         parseKV(r, "kv"),
		}
		p.Secrets.OIDCClientSecret = r.FormValue("oidc_client_secret")
	case profile.SAML:
		p.SAML = &profile.SAMLConfig{
			IdPEntityID:              strings.TrimSpace(r.FormValue("saml_idp_entity_id")),
			IdPSSOURL:                strings.TrimSpace(r.FormValue("saml_idp_sso_url")),
			IdPSSOBinding:            firstNonEmpty(r.FormValue("saml_idp_sso_binding"), "redirect"),
			IdPSLOURL:                strings.TrimSpace(r.FormValue("saml_idp_slo_url")),
			IdPCertsPEM:              parseCertList(r.FormValue("saml_idp_certs")),
			SPEntityID:               strings.TrimSpace(r.FormValue("saml_sp_entity_id")),
			SPCertPEM:                strings.TrimSpace(r.FormValue("saml_sp_cert")),
			NameIDFormat:             strings.TrimSpace(r.FormValue("saml_nameid_format")),
			SignAuthnRequest:         checkbox(r, "saml_sign_authn_request"),
			WantAssertionsSigned:     checkbox(r, "saml_want_assertions_signed"),
			AllowAssertionEncryption: checkbox(r, "saml_allow_assertion_encryption"),
			ForceAuthn:               checkbox(r, "saml_force_authn"),
			IsPassive:                checkbox(r, "saml_is_passive"),
			RequestedAuthnContext:    splitLines(r.FormValue("saml_requested_authn_context")),
		}
		p.Secrets.SPPrivateKeyPEM = r.FormValue("saml_sp_private_key")
	default:
		return nil, errors.New("unknown protocol")
	}
	return p, nil
}

func parseHeaders(r *http.Request) []profile.CustomHeader {
	var out []profile.CustomHeader
	for i := 0; i < maxRows; i++ {
		px := fmt.Sprintf("hdr[%d].", i)
		if _, ok := r.Form[px+"name"]; !ok {
			break
		}
		name := strings.TrimSpace(r.FormValue(px + "name"))
		if name == "" {
			continue
		}
		out = append(out, profile.CustomHeader{
			Name:      name,
			Value:     r.FormValue(px + "value"),
			Secret:    checkbox(r, px+"secret"),
			AppliesTo: r.Form[px+"applies"],
		})
	}
	return out
}

func parseKV(r *http.Request, prefix string) []profile.KV {
	var out []profile.KV
	for i := 0; i < maxRows; i++ {
		px := fmt.Sprintf("%s[%d].", prefix, i)
		if _, ok := r.Form[px+"key"]; !ok {
			break
		}
		k := strings.TrimSpace(r.FormValue(px + "key"))
		if k == "" {
			continue
		}
		out = append(out, profile.KV{Key: k, Value: r.FormValue(px + "value")})
	}
	return out
}

// parseCertList extracts PEM CERTIFICATE blocks from text; falls back to
// wrapping bare base64 DER.
func parseCertList(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	var out []string
	rest := []byte(text)
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, string(pem.EncodeToMemory(block)))
		}
		rest = remainder
	}
	if len(out) == 0 {
		// Maybe a bare base64 cert; reuse the metadata helper via a round-trip.
		if p := profile.CertToPEM(text); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// --- misc helpers ---

func (s *Server) acsURL() string      { return s.cfg.ExternalBaseURL + "/saml/acs" }
func (s *Server) redirectURI() string { return s.cfg.ExternalBaseURL + "/oidc/callback" }

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

func (s *Server) serverError(w http.ResponseWriter, err error) {
	s.log.Error("server error", "err", err)
	http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
}

func checkbox(r *http.Request, name string) bool { return r.FormValue(name) != "" }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func splitScopes(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '\n' || r == '\t' || r == '\r' })
	return fields
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}
