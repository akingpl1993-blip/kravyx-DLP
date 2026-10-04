package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func stack(log *slog.Logger, m *Metrics, h http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", h)
	return Chain(mux, WithRequestID, SecurityHeaders(true), AccessLog(log, m), Recover(log), BodyLimit(16))
}

func TestHeadersAndRequestID(t *testing.T) {
	h := stack(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-Id", "<script>alert(1)</script>")
	h.ServeHTTP(rec, req)
	for _, k := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security", "Cache-Control"} {
		if rec.Header().Get(k) == "" {
			t.Errorf("missing %s", k)
		}
	}
	if id := rec.Header().Get("X-Request-Id"); strings.Contains(id, "<") || len(id) != 32 {
		t.Fatalf("hostile request id echoed: %q", id)
	}
}

func TestPanicBecomesProblemWithoutDetails(t *testing.T) {
	var logs bytes.Buffer
	h := stack(slog.New(slog.NewJSONHandler(&logs, nil)), nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("db password=hunter2 exploded")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 500 || rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("got %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatal("panic detail leaked to client")
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.Code != "internal" || p.Instance == "" {
		t.Fatalf("bad problem: %s", rec.Body.String())
	}
}

func TestBodyLimitAndNoQueryInLogs(t *testing.T) {
	var logs bytes.Buffer
	m := NewMetrics()
	h := stack(slog.New(slog.NewJSONHandler(&logs, nil)), m, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.ReadAll(r.Body)
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			WriteProblem(w, r, http.StatusRequestEntityTooLarge, "too_large", "")
		}
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/?token=SECRETQUERY", strings.NewReader(strings.Repeat("x", 100))))
	if rec.Code != 413 {
		t.Fatalf("got %d", rec.Code)
	}
	if strings.Contains(logs.String(), "SECRETQUERY") || strings.Contains(logs.String(), "xxxx") {
		t.Fatalf("query or body logged: %s", logs.String())
	}
	mrec := httptest.NewRecorder()
	m.ServeHTTP(mrec, nil)
	if !strings.Contains(mrec.Body.String(), `kravyx_http_requests_total{route="/",status="413"} 1`) {
		t.Fatalf("metrics: %s", mrec.Body.String())
	}
}
