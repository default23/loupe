package web

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/default23/loupe/internal/history"
)

func (s *Server) handleHistoryList(w http.ResponseWriter, r *http.Request) {
	f := history.Filter{Limit: 200}
	q := r.URL.Query()
	if v := q.Get("profile_id"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			f.ProfileID = &id
		}
	}
	f.Protocol = q.Get("protocol")
	f.Status = q.Get("status")

	attempts, err := s.history.List(r.Context(), f)
	if err != nil {
		s.serverError(w, err)
		return
	}
	profiles, err := s.profiles.List(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, "history_list.html", map[string]any{
		"Title":       "History",
		"Attempts":    attempts,
		"Profiles":    profiles,
		"SelProtocol": f.Protocol,
		"SelStatus":   f.Status,
		"SelProfile":  q.Get("profile_id"),
	})
}

func (s *Server) handleHistoryDetail(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	full, err := s.history.Get(r.Context(), id)
	if errors.Is(err, history.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, "result.html", map[string]any{
		"Title":   "Login result",
		"Attempt": full,
	})
}
