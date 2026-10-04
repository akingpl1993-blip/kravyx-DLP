package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/akingpl1993-blip/kravyx-DLP/internal/platform/auth"
	"github.com/akingpl1993-blip/kravyx-DLP/internal/platform/httpx"
	"github.com/akingpl1993-blip/kravyx-DLP/internal/platform/secret"
)

const (
	tenant = "00000000-0000-4000-8000-000000000001"
	token  = "test-token-0123456789abcdef0123456789abcdef"
)

type harness struct {
	h    http.Handler
	logs *bytes.Buffer
}

func newHarness(t *testing.T, perms ...string) harness {
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	a := &API{
		Auth:  auth.DevAuthenticator{Token: secret.New(token), Principal: auth.NewPrincipal("analyst", tenant, perms)},
		Log:   log,
		Clock: func() time.Time { return time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC) },
	}
	mux := http.NewServeMux()
	a.Register(mux)
	return harness{httpx.Chain(mux, httpx.WithRequestID, httpx.SecurityHeaders(false), httpx.AccessLog(log, nil), httpx.Recover(log), httpx.BodyLimit(8<<20)), &logs}
}

func (h harness) do(t *testing.T, path string, body any, tok string) *httptest.ResponseRecorder {
	t.Helper()
	var b []byte
	switch v := body.(type) {
	case string:
		b = []byte(v)
	default:
		b, _ = json.Marshal(v)
	}
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func bundle(t *testing.T) json.RawMessage {
	b, err := os.ReadFile("../../../tests/fixtures/bundle-example.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func code(t *testing.T, rec *httptest.ResponseRecorder) string {
	var p httpx.Problem
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	return p.Code
}

func TestSimulateBlocksCardsAndNeverLeaksContent(t *testing.T) {
	h := newHarness(t, "policy.read")
	csv, _ := os.ReadFile("../../../tests/corpus/positive/card-export-12.csv")
	text := string(csv)
	rec := h.do(t, "/api/v1/policies/simulate", map[string]any{
		"bundle":  bundle(t),
		"context": map[string]any{"user": map[string]any{"id": "u"}, "channel": "web_upload", "destination": map[string]any{"external": true}},
		"content": map[string]any{"text": text},
	}, token)
	if rec.Code != 200 {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Verdict struct {
			Action      string `json:"action"`
			Explanation string `json:"explanation"`
		} `json:"verdict"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Verdict.Action != "block" || out.Verdict.Explanation == "" {
		t.Fatalf("verdict: %s", rec.Body.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n")[1:] {
		card := strings.Split(line, ",")[2]
		if strings.Contains(rec.Body.String(), card) || strings.Contains(h.logs.String(), card) {
			t.Fatalf("raw card %s leaked to response or logs", card)
		}
	}
	if strings.Contains(h.logs.String(), token) {
		t.Fatal("token leaked to logs")
	}
	if !strings.Contains(h.logs.String(), `"action":"policy.simulate"`) {
		t.Fatal("simulation not audited")
	}
}

func TestSimulateBase64AndContextOnly(t *testing.T) {
	h := newHarness(t, "policy.read")
	rec := h.do(t, "/api/v1/policies/simulate", map[string]any{
		"bundle":  bundle(t),
		"context": map[string]any{"user": map[string]any{"id": "u"}, "channel": "genai_prompt", "classification": "Restricted", "destination": map[string]any{"category": "generative_ai"}},
	}, token)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"action":"block"`) {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	rec = h.do(t, "/api/v1/policies/simulate", map[string]any{"bundle": bundle(t), "content": map[string]any{"base64": "!!!"}}, token)
	if rec.Code != 400 || code(t, rec) != "invalid_content" {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestAuthAndPermissions(t *testing.T) {
	h := newHarness(t, "policy.read")
	body := map[string]any{"bundle": bundle(t)}
	if rec := h.do(t, "/api/v1/policies/simulate", body, ""); rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := h.do(t, "/api/v1/policies/simulate", body, token+"x"); rec.Code != 401 {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec := h.do(t, "/api/v1/policies:validate", body, token); rec.Code != 403 || code(t, rec) != "forbidden" {
		t.Fatalf("missing policy.write: %d", rec.Code)
	}
}

func TestTenantMismatchIsForbidden(t *testing.T) {
	h := newHarness(t, "policy.read", "policy.write")
	other := strings.Replace(string(bundle(t)), tenant, "00000000-0000-4000-8000-0000000000bb", 1)
	for _, path := range []string{"/api/v1/policies/simulate", "/api/v1/policies:validate"} {
		rec := h.do(t, path, map[string]any{"bundle": json.RawMessage(other)}, token)
		if rec.Code != 403 || code(t, rec) != "tenant_mismatch" {
			t.Fatalf("%s: got %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestValidateReportsCompilerErrors(t *testing.T) {
	h := newHarness(t, "policy.write")
	if rec := h.do(t, "/api/v1/policies:validate", map[string]any{"bundle": bundle(t)}, token); rec.Code != 200 {
		t.Fatalf("valid bundle: %d %s", rec.Code, rec.Body.String())
	}
	bad := strings.Replace(string(bundle(t)), `"field": "classification", "op": "gte"`, `"field": "clasification", "op": "gte"`, 1)
	rec := h.do(t, "/api/v1/policies:validate", map[string]any{"bundle": json.RawMessage(bad)}, token)
	if rec.Code != 422 || code(t, rec) != "invalid_bundle" || !strings.Contains(rec.Body.String(), "unknown field") {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}

func TestStrictInput(t *testing.T) {
	h := newHarness(t, "policy.read")
	if rec := h.do(t, "/api/v1/policies/simulate", `{"bundle":{},"extra":1}`, token); rec.Code != 400 || code(t, rec) != "invalid_json" {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	if rec := h.do(t, "/api/v1/policies/simulate", `{"bundle":{}} {"x":1}`, token); rec.Code != 400 {
		t.Fatalf("trailing data: %d", rec.Code)
	}
	huge := strings.Repeat("a", MaxContentBytes+1)
	rec := h.do(t, "/api/v1/policies/simulate", map[string]any{"bundle": bundle(t), "content": map[string]any{"text": huge}}, token)
	if rec.Code != 413 {
		t.Fatalf("oversized content: %d", rec.Code)
	}
	req := httptest.NewRequest("POST", "/api/v1/policies/simulate", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	h.h.ServeHTTP(rr, req)
	if rr.Code != 415 {
		t.Fatalf("wrong content type: %d", rr.Code)
	}
}
