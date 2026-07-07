package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/default23/loupe/internal/history"
	"github.com/default23/loupe/internal/httpx"
	"github.com/default23/loupe/internal/inflight"
	"github.com/default23/loupe/internal/inspect"
	"github.com/default23/loupe/internal/oidc"
	"github.com/default23/loupe/internal/profile"
)

const inflightTTL = 10 * time.Minute

// handleLoginReview shows the editable parameters before starting a login.
func (s *Server) handleLoginReview(w http.ResponseWriter, r *http.Request) {
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

	// "Run again" links carry ?from=<attemptId> so the review form is prefilled
	// with the exact parameters and per-session headers that attempt used.
	prior := s.priorAttempt(r, p)

	data := map[string]any{
		"Title":   "Start login — " + p.Name,
		"Profile": p,
		// Secret profile headers are shown read-only: their values live only in
		// the encrypted profile and are applied server-side, never placed in the
		// form (which would persist them unencrypted in in_flight_logins).
		"Headers":     secretHeaders(p.CustomHeaders),
		"RedirectURI": s.redirectURI(),
		"ACSURL":      s.acsURL(),
	}

	switch p.Protocol {
	case profile.OIDC:
		start := oidcStartFromDetails(prior)
		if start == nil {
			start, err = oidc.BuildStart(p, s.redirectURI())
			if err != nil {
				s.serverError(w, err)
				return
			}
		}
		data["OIDC"] = start
		// Prefill the editable header rows from the prior attempt when re-running,
		// otherwise from the profile's non-secret headers so they are visible and
		// editable for this login.
		data["AllPhases"] = profile.AllHeaderPhases
		data["SessionHeaderRows"] = sessionHeaderRows(prior, p)
	case profile.SAML:
		start, err := s.buildSAMLReview(p, prior)
		if err != nil {
			s.serverError(w, err)
			return
		}
		data["SAML"] = start
	}

	s.render(w, r, "login_review.html", data)
}

// priorAttempt loads the attempt referenced by the ?from=<id> query parameter,
// used to prefill the review form on "Run again". It returns a zero Details
// (nil ParamsUsed) when there is no usable prior attempt for this profile —
// missing/invalid id, unknown attempt, different profile, or other protocol.
func (s *Server) priorAttempt(r *http.Request, p *profile.Profile) history.Details {
	v := r.URL.Query().Get("from")
	if v == "" {
		return history.Details{}
	}
	fromID, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return history.Details{}
	}
	full, err := s.history.Get(r.Context(), fromID)
	if err != nil {
		return history.Details{}
	}
	if !full.HasProfile() || full.ProfileIDVal() != p.ID || full.Protocol != string(p.Protocol) {
		return history.Details{}
	}
	return full.Details
}

// oidcStartFromDetails rebuilds the editable OIDC authorization request from a
// prior attempt's stored parameters. Returns nil when there is nothing to
// prefill, so the caller falls back to a freshly generated request.
func oidcStartFromDetails(d history.Details) *oidc.Start {
	if d.ParamsUsed == nil {
		return nil
	}
	start := &oidc.Start{}
	if v, ok := d.ParamsUsed["authorize_url"].(string); ok {
		start.AuthorizationEndpoint = v
	}
	if v, ok := d.ParamsUsed["code_verifier"].(string); ok {
		start.CodeVerifier = v
	}
	if raw, ok := d.ParamsUsed["authorize_params"]; ok && raw != nil {
		b, err := json.Marshal(raw)
		if err == nil {
			var rows []map[string]string
			if json.Unmarshal(b, &rows) == nil {
				for _, kv := range rows {
					start.Params = append(start.Params, oidc.Param{Key: kv["key"], Value: kv["value"]})
				}
			}
		}
	}
	if len(start.Params) == 0 {
		return nil
	}
	return start
}

// sessionHeaderRows builds the indexed per-session header rows for the review
// form. When re-running a prior attempt it prefills from that attempt's session
// headers; otherwise it seeds the rows with the profile's non-secret headers so
// they are visible and editable before starting the login. Secret header values
// are never seeded here — they stay in the encrypted profile and are applied
// server-side (shown read-only above). Spare blank rows are always appended.
func sessionHeaderRows(d history.Details, p *profile.Profile) []headerRow {
	var chs []profile.CustomHeader
	if d.ParamsUsed != nil {
		if raw, ok := d.ParamsUsed["session_headers"]; ok && raw != nil {
			if b, err := json.Marshal(raw); err == nil {
				_ = json.Unmarshal(b, &chs)
			}
		}
	}
	if len(chs) == 0 {
		for _, h := range p.CustomHeaders {
			if h.Secret {
				continue
			}
			chs = append(chs, h)
		}
	}
	return buildHeaderRows(&profile.Profile{CustomHeaders: chs})
}

// secretHeaders returns only the secret headers from the given set, used to list
// them read-only on the review page (their values are applied server-side).
func secretHeaders(chs []profile.CustomHeader) []profile.CustomHeader {
	var out []profile.CustomHeader
	for _, h := range chs {
		if h.Secret {
			out = append(out, h)
		}
	}
	return out
}

// handleLoginStart persists in-flight state and redirects to the provider.
func (s *Server) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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

	switch p.Protocol {
	case profile.OIDC:
		s.startOIDC(w, r, p)
	case profile.SAML:
		s.startSAML(w, r, p)
	default:
		http.Error(w, "unknown protocol", http.StatusBadRequest)
	}
}

func (s *Server) startOIDC(w http.ResponseWriter, r *http.Request, p *profile.Profile) {
	params := parseParamRows(r, "p")
	verifier := r.FormValue("code_verifier")
	authEndpoint := firstNonEmpty(r.FormValue("authorization_endpoint"), p.OIDC.AuthorizationEndpoint)

	start := &oidc.Start{AuthorizationEndpoint: authEndpoint, Params: params, CodeVerifier: verifier}
	state := start.ParamValue("state")
	if state == "" {
		s.renderLoginError(w, r, p, "state parameter is required")
		return
	}

	rec := &inflight.Record{
		State:        state,
		ProfileID:    p.ID,
		Protocol:     string(profile.OIDC),
		CodeVerifier: verifier,
		Nonce:        start.ParamValue("nonce"),
		Params: map[string]any{
			"authorize_params": paramsToJSON(params),
			"authorize_url":    authEndpoint,
			"redirect_uri":     start.ParamValue("redirect_uri"),
			"client_id":        start.ParamValue("client_id"),
			"session_headers":  parseHeaders(r),
		},
		ExpiresAt: time.Now().Add(inflightTTL),
	}
	if err := s.inflight.Save(r.Context(), rec); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, start.URL(), http.StatusFound)
}

// handleOIDCCallback processes the redirect back from the OIDC provider.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")

	rec, err := s.inflight.Take(r.Context(), state)
	if errors.Is(err, inflight.ErrNotFound) {
		s.renderCallbackError(w, r, "No matching in-flight login for this callback (state unknown or expired).")
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

	cfg := oidc.ConfigFromProfile(p)
	if v, _ := rec.Params["client_id"].(string); v != "" {
		cfg.ClientID = v
	}
	redirectURI, _ := rec.Params["redirect_uri"].(string)

	recorder := inspect.NewRecorder()
	// Profile headers plus per-session headers; session headers are applied
	// last, so they override a profile header with the same name and phase.
	headers := append(profileHeaders(p), sessionHeadersFromParams(rec.Params)...)
	client := httpx.NewClient(headers, recorder)
	ctx := r.Context()

	pid := p.ID
	attempt := &history.Attempt{
		ProfileID:       &pid,
		ProfileName:     p.Name,
		Protocol:        string(profile.OIDC),
		ExternalBaseURL: s.cfg.ExternalBaseURL,
	}
	if err := s.history.Start(ctx, attempt); err != nil {
		s.serverError(w, err)
		return
	}

	paramsUsed := map[string]any{
		"authorize_params": rec.Params["authorize_params"],
		"authorize_url":    rec.Params["authorize_url"],
		"redirect_uri":     redirectURI,
		"code_verifier":    rec.CodeVerifier,
		"callback_query":   flatQuery(q),
		"session_headers":  rec.Params["session_headers"],
	}

	var (
		validations []inspect.Validation
		artifacts   = map[string]any{}
		summary     history.Summary
		status      = history.StatusSuccess
		errMsg      string
	)

	if e := q.Get("error"); e != "" {
		status = history.StatusFailed
		errMsg = "authorization error: " + e
		if d := q.Get("error_description"); d != "" {
			errMsg += " — " + d
		}
	} else {
		tr, exErr := oidc.Exchange(ctx, client, cfg, q.Get("code"), redirectURI, rec.CodeVerifier)
		if exErr != nil {
			status = history.StatusFailed
			errMsg = "token exchange failed: " + exErr.Error()
		} else {
			vals, header, claims := oidc.VerifyIDToken(ctx, client, cfg, tr.IDToken, rec.Nonce)
			validations = vals

			userinfo, uiErr := oidc.Userinfo(ctx, client, cfg, tr.AccessToken)
			if uiErr != nil {
				validations = append(validations, inspect.Validation{Name: "userinfo", OK: false, Detail: uiErr.Error()})
			} else if userinfo != nil {
				validations = append(validations, inspect.Validation{Name: "userinfo", OK: true})
			}

			artifacts = buildOIDCArtifacts(tr, header, claims, userinfo)
			summary = oidcSummary(claims, userinfo)

			if anyFailed(validations) {
				status = history.StatusFailed
				errMsg = "one or more validations failed"
			}
		}
	}

	s.finishAttempt(ctx, attempt.ID, status, errMsg, summary, history.Details{
		ParamsUsed:  paramsUsed,
		Artifacts:   artifacts,
		Validations: validations,
	}, recorder)

	http.Redirect(w, r, fmt.Sprintf("/history/%d", attempt.ID), http.StatusSeeOther)
}

// finishAttempt persists the terminal status, details, and exchanges.
func (s *Server) finishAttempt(ctx context.Context, id int64, status, errMsg string, summary history.Summary, details history.Details, rec *inspect.Recorder) {
	if err := s.history.Finish(ctx, id, status, errMsg, summary); err != nil {
		s.log.Error("finish attempt", "err", err)
	}
	if err := s.history.SaveDetails(ctx, id, details); err != nil {
		s.log.Error("save details", "err", err)
	}
	if err := s.history.SaveExchanges(ctx, id, rec.Exchanges()); err != nil {
		s.log.Error("save exchanges", "err", err)
	}
}

func buildOIDCArtifacts(tr *oidc.TokenResponse, header, claims, userinfo map[string]any) map[string]any {
	a := map[string]any{
		"id_token":        tr.IDToken,
		"id_token_header": header,
		"id_token_claims": claims,
		"access_token":    tr.AccessToken,
		"refresh_token":   tr.RefreshToken,
		"token_type":      tr.TokenType,
		"expires_in":      tr.ExpiresIn,
		"scope":           tr.Scope,
		"token_response":  tr.Raw,
	}
	// Access tokens are often JWTs (Keycloak, Azure AD, etc.); decode when so,
	// so the result page can show header/claims alongside the id token.
	if atHeader, atClaims, err := oidc.DecodeJWT(tr.AccessToken); err == nil {
		a["access_token_header"] = atHeader
		a["access_token_claims"] = atClaims
	}
	if userinfo != nil {
		a["userinfo"] = userinfo
	}
	return a
}

func oidcSummary(claims, userinfo map[string]any) history.Summary {
	str := func(m map[string]any, k string) string {
		if m == nil {
			return ""
		}
		v, _ := m[k].(string)
		return v
	}
	return history.Summary{
		Subject:    str(claims, "sub"),
		Issuer:     str(claims, "iss"),
		Email:      firstNonEmpty(str(claims, "email"), str(userinfo, "email")),
		ClaimCount: len(claims),
	}
}

func anyFailed(vals []inspect.Validation) bool {
	for _, v := range vals {
		if !v.OK {
			return true
		}
	}
	return false
}

// --- helpers shared by login handlers ---

func profileHeaders(p *profile.Profile) []httpx.Header {
	return toHTTPHeaders(p.CustomHeaders)
}

func toHTTPHeaders(chs []profile.CustomHeader) []httpx.Header {
	var out []httpx.Header
	for _, h := range chs {
		out = append(out, httpx.Header{Name: h.Name, Value: h.Value, Phases: h.AppliesTo})
	}
	return out
}

// sessionHeadersFromParams decodes the per-session headers stored in an
// in-flight record (round-tripped through JSON as generic values).
func sessionHeadersFromParams(params map[string]any) []httpx.Header {
	raw, ok := params["session_headers"]
	if !ok || raw == nil {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var chs []profile.CustomHeader
	if err := json.Unmarshal(b, &chs); err != nil {
		return nil
	}
	return toHTTPHeaders(chs)
}

// parseParamRows reads indexed key/value rows (prefix[i].key / prefix[i].value)
// preserving order and skipping empty keys.
func parseParamRows(r *http.Request, prefix string) []oidc.Param {
	var out []oidc.Param
	for i := 0; i < maxRows; i++ {
		px := fmt.Sprintf("%s[%d].", prefix, i)
		if _, ok := r.Form[px+"key"]; !ok {
			break
		}
		k := strings.TrimSpace(r.FormValue(px + "key"))
		if k == "" {
			continue
		}
		out = append(out, oidc.Param{Key: k, Value: r.FormValue(px + "value")})
	}
	return out
}

func paramsToJSON(params []oidc.Param) []map[string]string {
	out := make([]map[string]string, len(params))
	for i, p := range params {
		out[i] = map[string]string{"key": p.Key, "value": p.Value}
	}
	return out
}

func flatQuery(q map[string][]string) map[string]string {
	out := map[string]string{}
	for k, v := range q {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, p *profile.Profile, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "result.html", map[string]any{
		"Title": "Login error",
		"Error": msg,
	})
}

func (s *Server) renderCallbackError(w http.ResponseWriter, r *http.Request, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "result.html", map[string]any{
		"Title": "Callback error",
		"Error": msg,
	})
}
