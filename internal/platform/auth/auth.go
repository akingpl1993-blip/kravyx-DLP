// Package auth authenticates callers and enforces permissions. Increment 1b ships
// only the dev authenticator (config refuses it outside the dev profile); the
// Identity service's OIDC token verifier implements the same interface in 1c.
package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/akingpl1993-blip/kravyx-DLP/internal/platform/httpx"
	"github.com/akingpl1993-blip/kravyx-DLP/internal/platform/secret"
)

type Principal struct {
	Subject     string
	TenantID    string
	permissions map[string]bool
}

func (p *Principal) Has(perm string) bool { return p != nil && p.permissions[perm] }

func NewPrincipal(subject, tenant string, perms []string) *Principal {
	m := make(map[string]bool, len(perms))
	for _, p := range perms {
		m[p] = true
	}
	return &Principal{Subject: subject, TenantID: tenant, permissions: m}
}

var ErrUnauthenticated = errors.New("unauthenticated")

type Authenticator interface {
	Authenticate(r *http.Request) (*Principal, error)
}

type ctxKey struct{}

func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// WithPrincipal is for tests and internal callers.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// DevAuthenticator accepts one static bearer token and maps it to a fixed principal.
type DevAuthenticator struct {
	Token     secret.String
	Principal *Principal
}

func (d DevAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	h := r.Header.Get("Authorization")
	tok, found := strings.CutPrefix(h, "Bearer ")
	if !found || d.Token.IsZero() || !d.Token.Equal(tok) {
		return nil, ErrUnauthenticated
	}
	return d.Principal, nil
}

// Require authenticates the request and checks one permission.
func Require(a Authenticator, perm string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := a.Authenticate(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="kravyx"`)
			httpx.WriteProblem(w, r, http.StatusUnauthorized, "unauthenticated", "")
			return
		}
		if !p.Has(perm) {
			httpx.WriteProblem(w, r, http.StatusForbidden, "forbidden", "missing permission "+perm)
			return
		}
		next(w, r.WithContext(WithPrincipal(r.Context(), p)))
	}
}
