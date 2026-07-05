package web

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/default23/loupe/internal/profile"
)

// headerRow / kvRow are indexed view models so the form can render existing
// rows plus spare blanks with stable field names.
type headerRow struct {
	I int
	H profile.CustomHeader
}

type kvRow struct {
	I  int
	KV profile.KV
}

func (s *Server) renderProfileForm(w http.ResponseWriter, r *http.Request, p *profile.Profile, isNew bool, notice, errMsg string) {
	title := "Edit profile"
	if isNew {
		title = "New " + strings.ToUpper(string(p.Protocol)) + " profile"
	}

	data := map[string]any{
		"Title":       title,
		"Profile":     p,
		"IsNew":       isNew,
		"Notice":      notice,
		"Error":       errMsg,
		"AllPhases":   profile.AllHeaderPhases,
		"HeaderRows":  buildHeaderRows(p),
		"RedirectURI": s.redirectURI(),
		"ACSURL":      s.acsURL(),
		"HasKey":      s.cipher != nil,
	}
	if p.OIDC != nil {
		data["KVRows"] = buildKVRows(p.OIDC.ExtraAuthParams)
	}
	if !isNew && p.ID > 0 {
		data["SPMetadataURL"] = fmt.Sprintf("%s/profiles/%d/saml/metadata", s.cfg.ExternalBaseURL, p.ID)
	}

	s.render(w, r, "profile_form.html", data)
}

func buildHeaderRows(p *profile.Profile) []headerRow {
	n := len(p.CustomHeaders) + spareRows
	rows := make([]headerRow, n)
	for i := 0; i < n; i++ {
		rows[i].I = i
		if i < len(p.CustomHeaders) {
			rows[i].H = p.CustomHeaders[i]
		} else {
			rows[i].H = profile.CustomHeader{AppliesTo: profile.AllHeaderPhases}
		}
	}
	return rows
}

func buildKVRows(params []profile.KV) []kvRow {
	n := len(params) + spareRows
	rows := make([]kvRow, n)
	for i := 0; i < n; i++ {
		rows[i].I = i
		if i < len(params) {
			rows[i].KV = params[i]
		}
	}
	return rows
}
