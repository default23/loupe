// Package httpx provides an HTTP transport that injects per-phase custom
// headers into outbound provider calls and records every request/response into
// an inspect.Recorder.
package httpx

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/default23/loupe/internal/inspect"
)

// maxBodyCapture bounds how many bytes of each request/response body are stored.
const maxBodyCapture = 256 << 10 // 256 KiB

// Header is a custom header to inject, scoped to one or more phases.
type Header struct {
	Name   string
	Value  string
	Phases []string
}

type phaseKey struct{}

// WithPhase tags a context (and thus requests derived from it) with a phase so
// the transport can inject the right headers and label the exchange.
func WithPhase(ctx context.Context, phase string) context.Context {
	return context.WithValue(ctx, phaseKey{}, phase)
}

// PhaseFromContext returns the phase tag, or "other" if unset.
func PhaseFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(phaseKey{}).(string); ok && v != "" {
		return v
	}
	return "other"
}

// Transport wraps a base RoundTripper with header injection and recording.
type Transport struct {
	base    http.RoundTripper
	headers []Header
	rec     *inspect.Recorder
}

// NewClient builds an *http.Client whose transport injects the given headers
// and records exchanges into rec.
func NewClient(headers []Header, rec *inspect.Recorder) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &Transport{
			base:    http.DefaultTransport,
			headers: headers,
			rec:     rec,
		},
	}
}

// RoundTrip injects headers, performs the request, and records the exchange.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	phase := PhaseFromContext(req.Context())

	// Work on a clone so we honor the RoundTripper contract (no mutation of the
	// caller's request).
	r := req.Clone(req.Context())

	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	for _, h := range t.headers {
		if phaseMatches(h.Phases, phase) {
			r.Header.Set(h.Name, h.Value)
		}
	}

	ex := inspect.Exchange{
		Phase:      phase,
		Method:     r.Method,
		URL:        r.URL.String(),
		ReqHeaders: r.Header.Clone(),
		ReqBody:    capBody(reqBody),
		Time:       time.Now(),
	}

	start := time.Now()
	resp, err := t.base.RoundTrip(r)
	ex.DurationMS = time.Since(start).Milliseconds()

	if err != nil {
		ex.Error = err.Error()
		t.rec.Add(ex)
		return nil, err
	}

	var respBody []byte
	if resp.Body != nil {
		respBody, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
	}

	ex.Status = resp.StatusCode
	ex.RespHeaders = resp.Header.Clone()
	ex.RespBody = capBody(respBody)
	t.rec.Add(ex)

	return resp, nil
}

func phaseMatches(phases []string, phase string) bool {
	for _, p := range phases {
		if p == phase {
			return true
		}
	}
	return false
}

func capBody(b []byte) string {
	if len(b) > maxBodyCapture {
		return string(b[:maxBodyCapture]) + "\n…(truncated)"
	}
	return string(b)
}
