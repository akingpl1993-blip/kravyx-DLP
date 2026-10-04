// Package api is the Policy Service HTTP API (increment 1b: validate + simulate).
// Policy CRUD, versions and publishing are persisted in increment 1c.
package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/akingpl1993-blip/kravyx-DLP/internal/engine"
	"github.com/akingpl1993-blip/kravyx-DLP/internal/platform/auth"
	"github.com/akingpl1993-blip/kravyx-DLP/internal/platform/httpx"
)

// MaxContentBytes bounds decoded sample content in a simulation.
const MaxContentBytes = 5 << 20

type API struct {
	Auth  auth.Authenticator
	Log   *slog.Logger
	Clock func() time.Time
}

func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/policies:validate", auth.Require(a.Auth, "policy.write", a.validate))
	mux.HandleFunc("POST /api/v1/policies/simulate", auth.Require(a.Auth, "policy.read", a.simulate))
}

// decode reads a JSON body strictly: unknown fields and trailing data are errors.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		httpx.WriteProblem(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "use application/json")
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			httpx.WriteProblem(w, r, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
		} else {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "bad_request", "could not read body")
		}
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "invalid_json", "body must be a single JSON object matching the request schema")
		return false
	}
	return true
}

// tenantOf extracts bundle.tenant_id without trusting anything else in it.
func tenantOf(bundle json.RawMessage) string {
	var h struct {
		TenantID string `json:"tenant_id"`
	}
	_ = json.Unmarshal(bundle, &h)
	return strings.ToLower(h.TenantID)
}

func engineProblem(w http.ResponseWriter, r *http.Request, err error) {
	var e *engine.Error
	if errors.As(err, &e) {
		switch e.Code {
		case "invalid_bundle", "invalid_input":
			httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, e.Code, e.Message)
			return
		case "too_large":
			httpx.WriteProblem(w, r, http.StatusRequestEntityTooLarge, e.Code, e.Message)
			return
		}
	}
	httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal", "")
}

type validateReq struct {
	Bundle json.RawMessage `json:"bundle"`
}

func (a *API) validate(w http.ResponseWriter, r *http.Request) {
	var req validateReq
	if !decode(w, r, &req) {
		return
	}
	p := auth.FromContext(r.Context())
	if len(req.Bundle) == 0 || tenantOf(req.Bundle) != p.TenantID {
		httpx.WriteProblem(w, r, http.StatusForbidden, "tenant_mismatch", "bundle.tenant_id must be the caller's tenant")
		return
	}
	res, err := engine.Validate(req.Bundle)
	if err != nil {
		engineProblem(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, json.RawMessage(`{"valid":true,"result":`+string(res)+`}`))
}

type simulateReq struct {
	Bundle  json.RawMessage `json:"bundle"`
	Context json.RawMessage `json:"context"`
	Content *struct {
		Text   *string `json:"text"`
		Base64 *string `json:"base64"`
	} `json:"content"`
	At *time.Time `json:"at"`
}

func (a *API) simulate(w http.ResponseWriter, r *http.Request) {
	var req simulateReq
	if !decode(w, r, &req) {
		return
	}
	p := auth.FromContext(r.Context())
	if len(req.Bundle) == 0 || tenantOf(req.Bundle) != p.TenantID {
		httpx.WriteProblem(w, r, http.StatusForbidden, "tenant_mismatch", "bundle.tenant_id must be the caller's tenant")
		return
	}
	if len(req.Context) == 0 {
		req.Context = json.RawMessage(`{}`)
	}
	var content []byte
	if req.Content != nil {
		switch {
		case req.Content.Text != nil && req.Content.Base64 != nil:
			httpx.WriteProblem(w, r, http.StatusBadRequest, "invalid_content", "give content.text or content.base64, not both")
			return
		case req.Content.Text != nil:
			content = []byte(*req.Content.Text)
		case req.Content.Base64 != nil:
			b, err := base64.StdEncoding.DecodeString(*req.Content.Base64)
			if err != nil {
				httpx.WriteProblem(w, r, http.StatusBadRequest, "invalid_content", "content.base64 is not valid base64")
				return
			}
			content = b
		}
	}
	if len(content) > MaxContentBytes {
		httpx.WriteProblem(w, r, http.StatusRequestEntityTooLarge, "too_large", "content exceeds 5 MiB")
		return
	}
	at := a.Clock()
	if req.At != nil {
		at = *req.At
	}
	res, err := engine.Simulate(req.Bundle, req.Context, content, at)
	// Content is never persisted or logged; drop our reference immediately.
	clear(content)
	if err != nil {
		engineProblem(w, r, err)
		return
	}
	// Audit trail for simulations: metadata only. Persisted by the audit writer in 1c.
	a.Log.Info("audit", "action", "policy.simulate", "tenant_id", p.TenantID, "actor", p.Subject,
		"request_id", httpx.RequestID(r.Context()), "content_bytes", len(content), "result", "success")
	httpx.WriteJSON(w, http.StatusOK, res)
}
