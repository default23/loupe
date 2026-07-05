// Package inspect holds the capture model for a single login attempt: the
// server-to-server HTTP exchanges and protocol validation outcomes.
package inspect

import (
	"net/http"
	"sync"
	"time"
)

// Exchange is one captured outbound HTTP request/response.
type Exchange struct {
	Seq         int         `json:"seq"`
	Phase       string      `json:"phase"`
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	ReqHeaders  http.Header `json:"req_headers"`
	ReqBody     string      `json:"req_body"`
	Status      int         `json:"status"`
	RespHeaders http.Header `json:"resp_headers"`
	RespBody    string      `json:"resp_body"`
	DurationMS  int64       `json:"duration_ms"`
	Time        time.Time   `json:"time"`
	Error       string      `json:"error,omitempty"`
}

// Validation records the outcome of a single protocol check.
type Validation struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Recorder accumulates exchanges during a login flow. It is safe for
// concurrent use.
type Recorder struct {
	mu        sync.Mutex
	seq       int
	exchanges []Exchange
}

// NewRecorder returns an empty recorder.
func NewRecorder() *Recorder { return &Recorder{} }

// Add appends an exchange, assigning it the next sequence number.
func (r *Recorder) Add(e Exchange) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.Seq = r.seq
	r.seq++
	r.exchanges = append(r.exchanges, e)
}

// Exchanges returns a copy of the recorded exchanges.
func (r *Recorder) Exchanges() []Exchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Exchange, len(r.exchanges))
	copy(out, r.exchanges)
	return out
}
