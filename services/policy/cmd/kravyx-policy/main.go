// kravyx-policy: Policy Service (increment 1b — validate and simulate).
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/akingpl1993-blip/kravyx-DLP/internal/engine"
	"github.com/akingpl1993-blip/kravyx-DLP/internal/platform/auth"
	"github.com/akingpl1993-blip/kravyx-DLP/internal/platform/config"
	"github.com/akingpl1993-blip/kravyx-DLP/internal/platform/httpx"
	"github.com/akingpl1993-blip/kravyx-DLP/services/policy/api"
)

var version = "dev" // set with -ldflags "-X main.version=..."

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).With("service", "kravyx-policy")
	if err := run(log); err != nil {
		log.Error("fatal", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	info, err := engine.Info()
	if err != nil {
		return err
	}

	authn := auth.DevAuthenticator{Token: cfg.DevToken, Principal: auth.NewPrincipal(cfg.DevSubject, cfg.DevTenantID, cfg.DevPermissions)}
	log.Warn("dev authenticator active: not for production", "tenant_id", cfg.DevTenantID, "permissions", cfg.DevPermissions)

	metrics := httpx.NewMetrics()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, 200, map[string]any{"service": "kravyx-policy", "version": version, "engine": json.RawMessage(info)})
	})
	mux.Handle("GET /metrics", metrics)
	(&api.API{Auth: authn, Log: log, Clock: time.Now}).Register(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteProblem(w, r, http.StatusNotFound, "not_found", "")
	})

	useTLS := cfg.TLSCertFile != ""
	handler := httpx.Chain(mux, httpx.WithRequestID, httpx.SecurityHeaders(useTLS), httpx.AccessLog(log, metrics), httpx.Recover(log), httpx.BodyLimit(cfg.MaxBodyBytes))
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.HTTPAddr, "profile", cfg.Profile, "tls", useTLS, "version", version)
		if useTLS {
			errc <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
	return nil
}
