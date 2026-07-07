package web

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/default23/loupe/internal/history"
	"github.com/default23/loupe/internal/inflight"
	"github.com/default23/loupe/internal/inspect"
	"github.com/default23/loupe/internal/profile"
	"github.com/default23/loupe/internal/saml"
)

// samlReview is the editable AuthnRequest view shown before starting a SAML login.
type samlReview struct {
	Destination           string
	SPIssuer              string
	ACSURL                string
	Binding               string
	NameIDFormat          string
	ForceAuthn            bool
	IsPassive             bool
	Sign                  bool
	RequestedAuthnContext string
	RequestXML            string
}

func (s *Server) buildSAMLReview(p *profile.Profile, prior history.Details) (any, error) {
	cfg := saml.ConfigFromProfile(p, s.acsURL())
	applyPriorSAML(&cfg, prior)
	rv := &samlReview{
		Destination:           cfg.IdPSSOURL,
		SPIssuer:              cfg.SPEntityID,
		ACSURL:                cfg.ACSURL,
		Binding:               cfg.Binding,
		NameIDFormat:          cfg.NameIDFormat,
		ForceAuthn:            cfg.ForceAuthn,
		IsPassive:             cfg.IsPassive,
		Sign:                  cfg.SignAuthnRequest,
		RequestedAuthnContext: strings.Join(cfg.RequestedAuthnContext, "\n"),
	}
	// Build a preview AuthnRequest so the user can see what will be sent.
	if start, err := cfg.BuildStart("preview"); err == nil {
		rv.RequestXML = start.RequestXML
	} else {
		rv.RequestXML = "(could not build preview: " + err.Error() + ")"
	}
	return rv, nil
}

// applyPriorSAML overrides a profile-derived SAML config with the parameters a
// prior attempt used, so "Run again" prefills the review form with those values.
func applyPriorSAML(cfg *saml.Config, d history.Details) {
	pu := d.ParamsUsed
	if pu == nil {
		return
	}
	if v, ok := pu["destination"].(string); ok && v != "" {
		cfg.IdPSSOURL = v
	}
	if v, ok := pu["sp_issuer"].(string); ok && v != "" {
		cfg.SPEntityID = v
	}
	if v, ok := pu["acs"].(string); ok && v != "" {
		cfg.ACSURL = v
	}
	if v, ok := pu["binding"].(string); ok && v != "" {
		cfg.Binding = v
	}
	if v, ok := pu["nameid_format"].(string); ok {
		cfg.NameIDFormat = v
	}
	if v, ok := pu["sign"].(bool); ok {
		cfg.SignAuthnRequest = v
	}
	if v, ok := pu["force_authn"].(bool); ok {
		cfg.ForceAuthn = v
	}
	if v, ok := pu["is_passive"].(bool); ok {
		cfg.IsPassive = v
	}
	if v, ok := pu["requested_authn_context"].(string); ok && v != "" {
		cfg.RequestedAuthnContext = splitLines(v)
	}
}

func (s *Server) startSAML(w http.ResponseWriter, r *http.Request, p *profile.Profile) {
	cfg := saml.ConfigFromProfile(p, s.acsURL())
	cfg.IdPSSOURL = firstNonEmpty(r.FormValue("saml_destination"), cfg.IdPSSOURL)
	cfg.SPEntityID = firstNonEmpty(r.FormValue("saml_sp_issuer"), cfg.SPEntityID)
	cfg.ACSURL = firstNonEmpty(r.FormValue("saml_acs"), cfg.ACSURL)
	cfg.Binding = firstNonEmpty(r.FormValue("saml_binding"), cfg.Binding)
	cfg.NameIDFormat = r.FormValue("saml_nameid_format")
	cfg.SignAuthnRequest = checkbox(r, "saml_sign")
	cfg.ForceAuthn = checkbox(r, "saml_force_authn")
	cfg.IsPassive = checkbox(r, "saml_is_passive")
	cfg.RequestedAuthnContext = splitLines(r.FormValue("saml_rac"))

	relayState := randState()
	start, err := cfg.BuildStart(relayState)
	if err != nil {
		s.serverError(w, err)
		return
	}

	rec := &inflight.Record{
		State:      relayState,
		ProfileID:  p.ID,
		Protocol:   string(profile.SAML),
		RelayState: relayState,
		RequestID:  start.RequestID,
		Params: map[string]any{
			"request_xml":   start.RequestXML,
			"destination":   cfg.IdPSSOURL,
			"binding":       cfg.Binding,
			"sign":          cfg.SignAuthnRequest,
			"acs":           cfg.ACSURL,
			"sp_issuer":     cfg.SPEntityID,
			"nameid_format": cfg.NameIDFormat,
			"force_authn":   cfg.ForceAuthn,
			"is_passive":    cfg.IsPassive,

			"requested_authn_context": strings.Join(cfg.RequestedAuthnContext, "\n"),
		},
		ExpiresAt: time.Now().Add(inflightTTL),
	}
	if err := s.inflight.Save(r.Context(), rec); err != nil {
		s.serverError(w, err)
		return
	}

	if start.Binding == "post" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>" + start.PostHTML + "</body></html>"))
		return
	}
	http.Redirect(w, r, start.RedirectURL, http.StatusFound)
}

// handleSAMLACS receives the SAMLResponse POSTed by the IdP.
func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	encoded := r.FormValue("SAMLResponse")
	relayState := r.FormValue("RelayState")
	if encoded == "" {
		s.renderCallbackError(w, r, "ACS received no SAMLResponse.")
		return
	}

	rec, err := s.inflight.Take(r.Context(), relayState)
	if errors.Is(err, inflight.ErrNotFound) {
		s.renderCallbackError(w, r, "No matching in-flight login for this ACS POST (RelayState unknown or expired).")
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}

	p, err := s.profiles.Get(r.Context(), rec.ProfileID)
	if err != nil {
		s.serverError(w, err)
		return
	}

	cfg := saml.ConfigFromProfile(p, s.acsURL())
	if v, _ := rec.Params["sp_issuer"].(string); v != "" {
		cfg.SPEntityID = v
	}
	if v, _ := rec.Params["acs"].(string); v != "" {
		cfg.ACSURL = v
	}

	ctx := r.Context()
	pid := p.ID
	attempt := &history.Attempt{
		ProfileID:       &pid,
		ProfileName:     p.Name,
		Protocol:        string(profile.SAML),
		ExternalBaseURL: s.cfg.ExternalBaseURL,
	}
	if err := s.history.Start(ctx, attempt); err != nil {
		s.serverError(w, err)
		return
	}

	result, vals, perr := cfg.ParseResponse(encoded, rec.RequestID)

	artifacts := map[string]any{
		"authn_request_xml": rec.Params["request_xml"],
	}
	var summary history.Summary
	status := history.StatusSuccess
	errMsg := ""

	if result != nil {
		artifacts["saml_response_xml"] = result.ResponseXML
		artifacts["name_id"] = result.NameID
		artifacts["session_index"] = result.SessionIndex
		artifacts["authn_instant"] = result.AuthnInstant
		artifacts["in_response_to"] = result.InResponseTo
		artifacts["attributes"] = result.Attributes
		summary = history.Summary{Subject: result.NameID, AttributeCount: len(result.Attributes)}
	}
	if perr != nil {
		status = history.StatusFailed
		errMsg = "SAML validation failed: " + perr.Error()
	} else if anyFailed(vals) {
		status = history.StatusFailed
		errMsg = "one or more validations failed"
	}

	paramsUsed := map[string]any{
		"binding":       rec.Params["binding"],
		"destination":   rec.Params["destination"],
		"sp_issuer":     rec.Params["sp_issuer"],
		"acs":           rec.Params["acs"],
		"sign":          rec.Params["sign"],
		"nameid_format": rec.Params["nameid_format"],
		"force_authn":   rec.Params["force_authn"],
		"is_passive":    rec.Params["is_passive"],
		"request_id":    rec.RequestID,

		"requested_authn_context": rec.Params["requested_authn_context"],
	}

	// SAML has no server-to-server exchanges during login; pass an empty recorder.
	s.finishAttempt(ctx, attempt.ID, status, errMsg, summary, history.Details{
		ParamsUsed:  paramsUsed,
		Artifacts:   artifacts,
		Validations: vals,
	}, inspect.NewRecorder())

	http.Redirect(w, r, fmt.Sprintf("/history/%d", attempt.ID), http.StatusSeeOther)
}

func randState() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
