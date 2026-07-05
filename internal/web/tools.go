package web

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/default23/loupe/internal/crypto"
	"github.com/default23/loupe/internal/inspect"
	"github.com/default23/loupe/internal/oidc"
	"github.com/default23/loupe/internal/profile"
	"github.com/default23/loupe/internal/saml"
	"github.com/default23/loupe/internal/toolkit"
)

// kv is a simple ordered key/value for display tables.
type kv struct{ K, V string }

// checkRow is a validation rendered with a tri-state: a skipped check (no
// verifier configured) reads as a neutral warn, not a red failure.
type checkRow struct {
	Name   string
	Detail string
	State  string // ok | fail | warn
}

// checkRows maps validations to display rows, treating "skipped" details as warn.
func checkRows(vals []inspect.Validation) []checkRow {
	out := make([]checkRow, 0, len(vals))
	for _, v := range vals {
		state := "fail"
		switch {
		case v.OK:
			state = "ok"
		case strings.Contains(v.Detail, "skipped"):
			state = "warn"
		}
		out = append(out, checkRow{Name: v.Name, Detail: v.Detail, State: state})
	}
	return out
}

// dateClaims are JWT claims rendered as human-readable timestamps.
var dateClaims = []string{"iat", "nbf", "exp", "auth_time", "updated_at"}

// --- Hub ---

func (s *Server) handleToolsIndex(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "tools_index.html", map[string]any{"Title": "Tools"})
}

// profileOptions returns lightweight options for a protocol's profile <select>.
func (s *Server) profileOptions(ctx context.Context, proto profile.Protocol) []profile.Summary {
	all, err := s.profiles.List(ctx)
	if err != nil {
		return nil
	}
	var out []profile.Summary
	for _, p := range all {
		if p.Protocol == proto {
			out = append(out, p)
		}
	}
	return out
}

// loadProfile fetches a full profile by the "profile" form value, or nil.
func (s *Server) loadProfile(ctx context.Context, r *http.Request) *profile.Profile {
	id, err := strconv.ParseInt(r.FormValue("profile"), 10, 64)
	if err != nil {
		return nil
	}
	p, err := s.profiles.Get(ctx, id)
	if err != nil {
		return nil
	}
	return p
}

// --- JWT decoder ---

type jwtReadout struct {
	Decoded     bool
	Header      map[string]any
	Claims      map[string]any
	Timestamps  []kv
	Validations []checkRow
	VerifyNote  string
	Error       string
}

func (s *Server) handleJWTPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "tool_jwt.html", map[string]any{
		"Title":    "JWT decoder",
		"Profiles": s.profileOptions(r.Context(), profile.OIDC),
	})
}

func (s *Server) handleJWTDecode(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	token := strings.TrimSpace(r.FormValue("token"))
	out := &jwtReadout{}

	if token == "" {
		s.renderPartial(w, "tool_jwt.html", "jwt_result", out)
		return
	}

	header, claims, err := oidc.DecodeJWT(token)
	if err != nil {
		out.Error = "Not a JWT: " + err.Error()
		s.renderPartial(w, "tool_jwt.html", "jwt_result", out)
		return
	}
	out.Decoded = true
	out.Header = header
	out.Claims = claims
	out.Timestamps = timestampRows(claims)

	jwks := strings.TrimSpace(r.FormValue("jwks"))
	secret := strings.TrimSpace(r.FormValue("secret"))

	// Profile integration: if no JWKS pasted, fetch it from the selected
	// profile's jwks_uri so verification is one click.
	if jwks == "" && secret == "" {
		if p := s.loadProfile(r.Context(), r); p != nil && p.OIDC != nil && p.OIDC.JWKSURI != "" {
			if body, ferr := fetchText(r.Context(), p.OIDC.JWKSURI); ferr == nil {
				jwks = body
				out.VerifyNote = "Verified against profile “" + p.Name + "” JWKS (" + p.OIDC.JWKSURI + ")"
			} else {
				out.VerifyNote = "Could not fetch profile JWKS: " + ferr.Error()
			}
		}
	}

	out.Validations = checkRows(oidc.VerifyToken(token, jwks, secret))
	s.renderPartial(w, "tool_jwt.html", "jwt_result", out)
}

// timestampRows renders known date claims as RFC3339 UTC strings.
func timestampRows(claims map[string]any) []kv {
	if claims == nil {
		return nil
	}
	var out []kv
	for _, name := range dateClaims {
		v, ok := claims[name]
		if !ok {
			continue
		}
		f, ok := v.(float64)
		if !ok {
			continue
		}
		t := time.Unix(int64(f), 0).UTC()
		label := t.Format("2006-01-02 15:04:05 UTC")
		if name == "exp" && time.Now().After(t) {
			label += " (expired)"
		}
		out = append(out, kv{K: name, V: label})
	}
	return out
}

// --- SAML Response decoder ---

type samlResponseReadout struct {
	Decoded      bool
	XML          string
	NameID       string
	SessionIndex string
	AuthnInstant string
	InResponseTo string
	Attributes   map[string][]string
	Validations  []checkRow
	Error        string
}

func (s *Server) handleSAMLResponsePage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "tool_saml_response.html", map[string]any{
		"Title":    "SAML Response decoder",
		"Profiles": s.profileOptions(r.Context(), profile.SAML),
	})
}

func (s *Server) handleSAMLResponseDecode(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	encoded := strings.TrimSpace(r.FormValue("response"))
	out := &samlResponseReadout{}
	if encoded == "" {
		s.renderPartial(w, "tool_saml_response.html", "saml_response_result", out)
		return
	}

	cfg := saml.Config{}
	if p := s.loadProfile(r.Context(), r); p != nil && p.SAML != nil {
		cfg.IdPCertsPEM = p.SAML.IdPCertsPEM
		cfg.SPEntityID = p.SAML.SPEntityID
	}
	if cert := strings.TrimSpace(r.FormValue("cert")); cert != "" {
		cfg.IdPCertsPEM = []string{cert}
	}
	if aud := strings.TrimSpace(r.FormValue("audience")); aud != "" {
		cfg.SPEntityID = aud
	}

	res, vals, _ := cfg.ParseResponse(encoded, "")
	if res != nil {
		out.Decoded = true
		out.XML = res.ResponseXML
		out.NameID = res.NameID
		out.SessionIndex = res.SessionIndex
		out.AuthnInstant = res.AuthnInstant
		out.InResponseTo = res.InResponseTo
		out.Attributes = res.Attributes
	}
	// Drop the InResponseTo correlation check — there's no originating request
	// in a standalone decode; the value is still shown in the summary.
	out.Validations = checkRows(dropValidation(vals, "InResponseTo"))
	if !out.Decoded && len(out.Validations) == 0 {
		out.Error = "Could not decode the SAML Response."
	}
	s.renderPartial(w, "tool_saml_response.html", "saml_response_result", out)
}

// --- SAML AuthnRequest decoder ---

type authnRequestReadout struct {
	Info  *saml.AuthnRequestInfo
	Error string
}

func (s *Server) handleAuthnRequestPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "tool_saml_authnrequest.html", map[string]any{"Title": "SAML AuthnRequest decoder"})
}

func (s *Server) handleAuthnRequestDecode(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	encoded := strings.TrimSpace(r.FormValue("request"))
	out := &authnRequestReadout{}
	if encoded == "" {
		s.renderPartial(w, "tool_saml_authnrequest.html", "authn_request_result", out)
		return
	}
	info, err := saml.DecodeAuthnRequest(encoded)
	if err != nil {
		out.Error = err.Error()
	} else {
		out.Info = info
	}
	s.renderPartial(w, "tool_saml_authnrequest.html", "authn_request_result", out)
}

// --- Encode / Decode ---

type encodeReadout struct {
	Op     string
	Output string
	Error  string
}

func (s *Server) handleEncodePage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "tool_encode.html", map[string]any{
		"Title":      "Encode / Decode",
		"Transforms": toolkit.Transforms,
	})
}

func (s *Server) handleEncodeApply(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	op := r.FormValue("op")
	input := r.FormValue("input")
	out := &encodeReadout{Op: op}
	if strings.TrimSpace(input) == "" {
		s.renderPartial(w, "tool_encode.html", "encode_result", out)
		return
	}
	res, err := toolkit.Apply(op, input)
	if err != nil {
		out.Error = err.Error()
	} else {
		out.Output = res
	}
	s.renderPartial(w, "tool_encode.html", "encode_result", out)
}

// --- Certificates & keys ---

type certReadout struct {
	Info    *crypto.CertInfo
	KeyPair *crypto.SPKeyPair
	Error   string
}

func (s *Server) handleCertPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "tool_cert.html", map[string]any{"Title": "Certificates & keys"})
}

func (s *Server) handleCertInspect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	pemStr := strings.TrimSpace(r.FormValue("pem"))
	out := &certReadout{}
	if pemStr == "" {
		s.renderPartial(w, "tool_cert.html", "cert_result", out)
		return
	}
	info, err := crypto.InspectCert(pemStr)
	if err != nil {
		out.Error = err.Error()
	} else {
		out.Info = info
	}
	s.renderPartial(w, "tool_cert.html", "cert_result", out)
}

func (s *Server) handleCertGenerate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	cn := strings.TrimSpace(r.FormValue("common_name"))
	if cn == "" {
		cn = "loupe-sp"
	}
	out := &certReadout{}
	kp, err := crypto.GenerateSPKeyPair(cn)
	if err != nil {
		out.Error = err.Error()
	} else {
		out.KeyPair = kp
	}
	s.renderPartial(w, "tool_cert.html", "keypair_result", out)
}

// --- JWKS viewer ---

type jwksReadout struct {
	Keys  []oidc.JWKSKey
	Error string
}

func (s *Server) handleJWKSPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "tool_jwks.html", map[string]any{"Title": "JWKS viewer"})
}

func (s *Server) handleJWKSView(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	out := &jwksReadout{}
	input := strings.TrimSpace(r.FormValue("jwks"))
	if input == "" {
		s.renderPartial(w, "tool_jwks.html", "jwks_result", out)
		return
	}
	// Accept either a JWKS URL or pasted JSON.
	body := input
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		fetched, err := fetchText(r.Context(), input)
		if err != nil {
			out.Error = "Could not fetch JWKS: " + err.Error()
			s.renderPartial(w, "tool_jwks.html", "jwks_result", out)
			return
		}
		body = fetched
	}
	keys, err := oidc.ParseJWKS(body)
	if err != nil {
		out.Error = err.Error()
	} else {
		out.Keys = keys
	}
	s.renderPartial(w, "tool_jwks.html", "jwks_result", out)
}

// --- shared helpers ---

// dropValidation returns validations whose Name does not contain sub.
func dropValidation(vals []inspect.Validation, sub string) []inspect.Validation {
	out := vals[:0:0]
	for _, v := range vals {
		if !strings.Contains(v.Name, sub) {
			out = append(out, v)
		}
	}
	return out
}

// fetchText GETs a URL and returns its body (bounded), for JWKS retrieval.
func fetchText(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
