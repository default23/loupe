package httpx

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/default23/loupe/internal/inspect"
)

func TestInjectsHeadersByPhaseAndRecords(t *testing.T) {
	var gotCustom []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCustom = append(gotCustom, r.Header.Get("X-Custom"))
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "hello-body")
	}))
	defer srv.Close()

	rec := inspect.NewRecorder()
	client := NewClient([]Header{
		{Name: "X-Custom", Value: "secret-value", Phases: []string{"token"}},
	}, rec)

	// Phase "token": header should be injected.
	doGet(t, client, WithPhase(context.Background(), "token"), srv.URL)
	// Phase "other": header should NOT be injected.
	doGet(t, client, context.Background(), srv.URL)

	if len(gotCustom) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(gotCustom))
	}
	if gotCustom[0] != "secret-value" {
		t.Errorf("token phase: expected header injected, got %q", gotCustom[0])
	}
	if gotCustom[1] != "" {
		t.Errorf("other phase: expected no header, got %q", gotCustom[1])
	}

	exs := rec.Exchanges()
	if len(exs) != 2 {
		t.Fatalf("expected 2 recorded exchanges, got %d", len(exs))
	}
	if exs[0].Seq != 0 || exs[1].Seq != 1 {
		t.Errorf("unexpected seq numbers: %d, %d", exs[0].Seq, exs[1].Seq)
	}
	if exs[0].Phase != "token" || exs[1].Phase != "other" {
		t.Errorf("unexpected phases: %q, %q", exs[0].Phase, exs[1].Phase)
	}
	if exs[0].Status != http.StatusTeapot {
		t.Errorf("expected recorded status 418, got %d", exs[0].Status)
	}
	if !strings.Contains(exs[0].RespBody, "hello-body") {
		t.Errorf("response body not captured: %q", exs[0].RespBody)
	}
	if exs[0].ReqHeaders.Get("X-Custom") != "secret-value" {
		t.Errorf("injected header not captured in exchange")
	}
}

func doGet(t *testing.T, c *http.Client, ctx context.Context, url string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
