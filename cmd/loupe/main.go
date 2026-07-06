// Command loupe runs the SSO relying-party tester HTTP server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/default23/loupe/internal/config"
	"github.com/default23/loupe/internal/crypto"
	"github.com/default23/loupe/internal/history"
	"github.com/default23/loupe/internal/inflight"
	"github.com/default23/loupe/internal/profile"
	"github.com/default23/loupe/internal/store"
	"github.com/default23/loupe/internal/web"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	ctx := context.Background()

	dialect, dsn, err := storeTarget(cfg)
	if err != nil {
		return err
	}

	logger.Info("applying migrations", "driver", cfg.DBDriver)
	if err := store.Migrate(ctx, dialect, dsn); err != nil {
		return err
	}

	st, err := store.Open(ctx, dialect, dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	cipher, err := crypto.NewCipher(cfg.MasterKeyB64)
	if err != nil {
		return err
	}
	if cipher == nil {
		logger.Warn("no master key set; secrets cannot be stored (set MASTER_KEY)")
	}

	profiles := profile.NewRepo(st.DB, cipher)
	inflightRepo := inflight.NewRepo(st.DB)
	historyRepo := history.NewRepo(st.DB)

	srv, err := web.NewServer(cfg, st, profiles, inflightRepo, historyRepo, cipher, logger)
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	shutdownCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr, "base_url", cfg.ExternalBaseURL)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
			stop()
		}
	}()

	<-shutdownCtx.Done()
	logger.Info("shutting down")

	toCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpSrv.Shutdown(toCtx)
}

// storeTarget maps the configured driver to a store dialect and DSN. For SQLite
// it ensures the parent directory exists and enables foreign keys / a busy
// timeout via connection pragmas.
func storeTarget(cfg *config.Config) (store.Dialect, string, error) {
	switch cfg.DBDriver {
	case config.DriverPostgres:
		return store.DialectPostgres, cfg.DatabaseURL, nil
	case config.DriverSQLite:
		if dir := filepath.Dir(cfg.SQLitePath); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return "", "", fmt.Errorf("create sqlite dir: %w", err)
			}
		}
		dsn := "file:" + cfg.SQLitePath + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
		return store.DialectSQLite, dsn, nil
	default:
		return "", "", fmt.Errorf("unsupported DB_DRIVER %q", cfg.DBDriver)
	}
}
