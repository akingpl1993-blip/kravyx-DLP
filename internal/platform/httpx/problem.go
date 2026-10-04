package httpx

import (
	"encoding/json"
	"net/http"
)

// Problem is an RFC 9457 problem+json body. `Code` is stable and machine-readable;
// `Detail` is for humans and never contains request content or stack traces.
type Problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Code     string `json:"code"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

func WriteProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	p := Problem{
		Type:     "urn:kravyx:problem:" + code,
		Title:    http.StatusText(status),
		Status:   status,
		Code:     code,
		Detail:   detail,
		Instance: RequestID(r.Context()),
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

// WriteJSON writes a JSON success response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
