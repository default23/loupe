// Package dbcheck holds an end-to-end regression test for the SQLite backend,
// exercising every repository against a real file-backed database. It lives in
// its own leaf package because it imports store together with the repositories
// (store itself cannot import them without a cycle). Needs no external service.
package dbcheck

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/default23/loupe/internal/crypto"
	"github.com/default23/loupe/internal/history"
	"github.com/default23/loupe/internal/inflight"
	"github.com/default23/loupe/internal/inspect"
	"github.com/default23/loupe/internal/profile"
	"github.com/default23/loupe/internal/store"
)

func TestSQLiteEndToEnd(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "loupe.db") + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"

	if err := store.Migrate(ctx, store.DialectSQLite, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st, err := store.Open(ctx, store.DialectSQLite, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	cipher, err := crypto.NewCipher("test-passphrase")
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	// --- profiles: Create / Get (incl. encrypted secret header) / Update / List / Delete
	profiles := profile.NewRepo(st.DB, cipher)
	p := &profile.Profile{
		Name:     "acme",
		Protocol: profile.OIDC,
		OIDC:     &profile.OIDCConfig{Issuer: "https://idp.example", ClientID: "abc"},
		CustomHeaders: []profile.CustomHeader{
			{Name: "X-Api-Key", Value: "supersecret", Secret: true, AppliesTo: []string{profile.PhaseToken}},
		},
	}
	if err := profiles.Create(ctx, p); err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.ID == 0 || p.CreatedAt.IsZero() {
		t.Fatalf("create did not populate ID/CreatedAt: id=%d createdAt=%v", p.ID, p.CreatedAt)
	}

	got, err := profiles.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "acme" || got.OIDC.ClientID != "abc" {
		t.Fatalf("get mismatch: %+v", got)
	}
	if len(got.CustomHeaders) != 1 || got.CustomHeaders[0].Value != "supersecret" {
		t.Fatalf("secret header did not round-trip: %+v", got.CustomHeaders)
	}

	got.Name = "acme-renamed"
	if err := profiles.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	list, err := profiles.List(ctx)
	if err != nil || len(list) != 1 || list[0].Name != "acme-renamed" {
		t.Fatalf("list mismatch: %v err=%v", list, err)
	}

	// --- inflight: Save / Take (single-use) / expiry / DeleteExpired
	inf := inflight.NewRepo(st.DB)
	rec := &inflight.Record{
		State: "state-1", ProfileID: p.ID, Protocol: "oidc",
		CodeVerifier: "cv", Nonce: "nn",
		Params:    map[string]any{"k": "v"},
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := inf.Save(ctx, rec); err != nil {
		t.Fatalf("inflight save: %v", err)
	}
	taken, err := inf.Take(ctx, "state-1")
	if err != nil || taken.CodeVerifier != "cv" || taken.Params["k"] != "v" {
		t.Fatalf("inflight take mismatch: %+v err=%v", taken, err)
	}
	if _, err := inf.Take(ctx, "state-1"); err != inflight.ErrNotFound {
		t.Fatalf("expected single-use ErrNotFound, got %v", err)
	}
	// expired record must not be returned, then be swept.
	_ = inf.Save(ctx, &inflight.Record{State: "old", ProfileID: p.ID, Protocol: "oidc", ExpiresAt: time.Now().Add(-time.Hour)})
	if _, err := inf.Take(ctx, "old"); err != inflight.ErrNotFound {
		t.Fatalf("expected expired ErrNotFound, got %v", err)
	}
	_ = inf.Save(ctx, &inflight.Record{State: "old2", ProfileID: p.ID, Protocol: "oidc", ExpiresAt: time.Now().Add(-time.Hour)})
	if err := inf.DeleteExpired(ctx); err != nil {
		t.Fatalf("delete expired: %v", err)
	}

	// --- history: Start / SaveDetails / SaveExchanges / Finish / List / Get
	hist := history.NewRepo(st.DB)
	a := &history.Attempt{ProfileID: &p.ID, ProfileName: "acme", Protocol: "oidc", ExternalBaseURL: "http://localhost:8080"}
	if err := hist.Start(ctx, a); err != nil {
		t.Fatalf("start: %v", err)
	}
	if a.ID == 0 || a.StartedAt.IsZero() {
		t.Fatalf("start did not populate ID/StartedAt")
	}
	if err := hist.SaveDetails(ctx, a.ID, history.Details{
		ParamsUsed:  map[string]any{"scope": "openid"},
		Validations: []inspect.Validation{{Name: "iss", OK: true}},
	}); err != nil {
		t.Fatalf("save details: %v", err)
	}
	// upsert path
	if err := hist.SaveDetails(ctx, a.ID, history.Details{ParamsUsed: map[string]any{"scope": "openid email"}}); err != nil {
		t.Fatalf("save details (upsert): %v", err)
	}
	exs := []inspect.Exchange{
		{Seq: 1, Phase: "token", Method: "POST", URL: "https://idp/token", Status: 200,
			ReqHeaders: http.Header{"X-Api-Key": {"supersecret"}}, RespBody: "{}", DurationMS: 12, Time: time.Now().UTC()},
	}
	if err := hist.SaveExchanges(ctx, a.ID, exs); err != nil {
		t.Fatalf("save exchanges: %v", err)
	}
	if err := hist.Finish(ctx, a.ID, history.StatusSuccess, "", history.Summary{}); err != nil {
		t.Fatalf("finish: %v", err)
	}

	attempts, err := hist.List(ctx, history.Filter{ProfileID: &p.ID, Protocol: "oidc", Status: history.StatusSuccess, Limit: 10})
	if err != nil || len(attempts) != 1 {
		t.Fatalf("history list mismatch: %v err=%v", attempts, err)
	}
	full, err := hist.Get(ctx, a.ID)
	if err != nil {
		t.Fatalf("history get: %v", err)
	}
	if full.Status != history.StatusSuccess || full.FinishedAt == nil {
		t.Fatalf("finished state not persisted: %+v", full.Attempt)
	}
	if len(full.Exchanges) != 1 || full.Exchanges[0].URL != "https://idp/token" {
		t.Fatalf("exchange not persisted: %+v", full.Exchanges)
	}
	if full.Details.ParamsUsed["scope"] != "openid email" {
		t.Fatalf("details upsert not persisted: %+v", full.Details)
	}

	// --- profile delete last
	if err := profiles.Delete(ctx, p.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := profiles.Get(ctx, p.ID); err != profile.ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}
