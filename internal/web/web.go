// Package web serves the HTML UI and HTTP endpoints of the RP tester.
package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/default23/loupe/internal/config"
	"github.com/default23/loupe/internal/crypto"
	"github.com/default23/loupe/internal/history"
	"github.com/default23/loupe/internal/inflight"
	"github.com/default23/loupe/internal/profile"
	"github.com/default23/loupe/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// pages lists the page templates rendered on top of base.html.
var pages = []string{
	"home.html",
	"profiles_list.html",
	"profile_form.html",
	"login_review.html",
	"result.html",
	"history_list.html",
	"profiles_import.html",
	"tools_index.html",
	"tool_jwt.html",
	"tool_saml_response.html",
	"tool_saml_authnrequest.html",
	"tool_encode.html",
	"tool_cert.html",
	"tool_jwks.html",
}

// Server holds dependencies shared across handlers.
type Server struct {
	cfg      *config.Config
	st       *store.Store
	profiles *profile.Repo
	inflight *inflight.Repo
	history  *history.Repo
	cipher   *crypto.Cipher
	log      *slog.Logger
	pages    map[string]*template.Template
}

// NewServer parses templates and wires up dependencies.
func NewServer(cfg *config.Config, st *store.Store, profiles *profile.Repo, inflightRepo *inflight.Repo, historyRepo *history.Repo, cipher *crypto.Cipher, log *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, st: st, profiles: profiles, inflight: inflightRepo, history: historyRepo, cipher: cipher, log: log, pages: map[string]*template.Template{}}
	for _, p := range pages {
		t, err := template.New("base.html").Funcs(funcMap()).
			ParseFS(templatesFS, "templates/base.html", "templates/"+p)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", p, err)
		}
		s.pages[p] = t
	}
	return s, nil
}

// Handler builds the HTTP router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /{$}", s.handleHome)

	// Profiles.
	mux.HandleFunc("GET /profiles", s.handleProfilesList)
	mux.HandleFunc("GET /profiles/new", s.handleProfileNew)
	mux.HandleFunc("POST /profiles/new", s.handleProfileCreate)
	mux.HandleFunc("GET /profiles/import", s.handleProfileImportForm)
	mux.HandleFunc("POST /profiles/import", s.handleProfileImport)
	mux.HandleFunc("GET /profiles/{id}", s.handleProfileEdit)
	mux.HandleFunc("POST /profiles/{id}", s.handleProfileUpdate)
	mux.HandleFunc("POST /profiles/{id}/delete", s.handleProfileDelete)
	mux.HandleFunc("GET /profiles/{id}/export", s.handleProfileExport)
	mux.HandleFunc("GET /profiles/{id}/saml/metadata", s.handleSPMetadata)

	// Login flow.
	mux.HandleFunc("GET /login/{id}", s.handleLoginReview)
	mux.HandleFunc("POST /login/{id}/start", s.handleLoginStart)
	mux.HandleFunc("GET /oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("POST /saml/acs", s.handleSAMLACS)

	// History.
	mux.HandleFunc("GET /history", s.handleHistoryList)
	mux.HandleFunc("GET /history/{id}", s.handleHistoryDetail)

	// Tools — standalone protocol inspectors (no login flow).
	mux.HandleFunc("GET /tools", s.handleToolsIndex)
	mux.HandleFunc("GET /tools/jwt", s.handleJWTPage)
	mux.HandleFunc("POST /tools/jwt/decode", s.handleJWTDecode)
	mux.HandleFunc("GET /tools/saml-response", s.handleSAMLResponsePage)
	mux.HandleFunc("POST /tools/saml-response/decode", s.handleSAMLResponseDecode)
	mux.HandleFunc("GET /tools/saml-authnrequest", s.handleAuthnRequestPage)
	mux.HandleFunc("POST /tools/saml-authnrequest/decode", s.handleAuthnRequestDecode)
	mux.HandleFunc("GET /tools/encode", s.handleEncodePage)
	mux.HandleFunc("POST /tools/encode/apply", s.handleEncodeApply)
	mux.HandleFunc("GET /tools/cert", s.handleCertPage)
	mux.HandleFunc("POST /tools/cert/inspect", s.handleCertInspect)
	mux.HandleFunc("POST /tools/cert/generate", s.handleCertGenerate)
	mux.HandleFunc("GET /tools/jwks", s.handleJWKSPage)
	mux.HandleFunc("POST /tools/jwks/view", s.handleJWKSView)

	return s.withLogging(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.st.Ping(r.Context()); err != nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.profiles.List(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, "home.html", map[string]any{
		"Title":           "",
		"ExternalBaseURL": s.cfg.ExternalBaseURL,
		"Profiles":        profiles,
		"RedirectURI":     s.redirectURI(),
		"ACSURL":          s.acsURL(),
		"HasKey":          s.cipher != nil,
	})
}

// render executes a page template within base.html.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	t, ok := s.pages[page]
	if !ok {
		s.log.Error("unknown template", "page", page)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "base.html", data); err != nil {
		s.log.Error("render failed", "page", page, "err", err)
	}
}

// renderPartial executes a named template block (defined inside a page's file)
// without the base.html shell, for HTMX fragment swaps.
func (s *Server) renderPartial(w http.ResponseWriter, page, block string, data any) {
	t, ok := s.pages[page]
	if !ok {
		s.log.Error("unknown template", "page", page)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, block, data); err != nil {
		s.log.Error("render partial failed", "page", page, "block", block, "err", err)
	}
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.log.Debug("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func funcMap() template.FuncMap {
	return template.FuncMap{
		"join": strings.Join,
		"prettyJSON": func(v any) string {
			b, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return fmt.Sprintf("%v", v)
			}
			return string(b)
		},
		"asString": func(v any) string {
			if v == nil {
				return ""
			}
			return fmt.Sprintf("%v", v)
		},
		"contains": func(sl []string, s string) bool {
			for _, v := range sl {
				if v == s {
					return true
				}
			}
			return false
		},
		"seq": func(a, b int) []int {
			var out []int
			for i := a; i < b; i++ {
				out = append(out, i)
			}
			return out
		},
		"add": func(a, b int) int { return a + b },
	}
}
