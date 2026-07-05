// Command loupe runs the SSO relying-party tester HTTP server.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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

	logger.Info("applying migrations")
	if err := store.Migrate(ctx, cfg.DatabaseURL); err != nil {
		return err
	}

	st, err := store.Open(ctx, cfg.DatabaseURL)
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

	profiles := profile.NewRepo(st.Pool, cipher)
	inflightRepo := inflight.NewRepo(st.Pool)
	historyRepo := history.NewRepo(st.Pool)

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
