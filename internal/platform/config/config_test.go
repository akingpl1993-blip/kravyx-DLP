package config

import (
	"errors"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func devEnv() map[string]string {
	return map[string]string{
		"KRAVYX_PROFILE":         "dev",
		"KRAVYX_DEV_TOKEN":       strings.Repeat("a1", 16),
		"KRAVYX_DEV_TENANT_ID":   "00000000-0000-4000-8000-000000000001",
		"KRAVYX_DEV_PERMISSIONS": "policy.read, policy.write",
	}
}

func TestDevProfileLoads(t *testing.T) {
	c, err := Load(env(devEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPAddr != "127.0.0.1:8081" || len(c.DevPermissions) != 2 || c.DevSubject != "dev-user" {
		t.Fatalf("unexpected config: %+v", c)
	}
}

func TestFailClosed(t *testing.T) {
	cases := []struct {
		name  string
		patch map[string]string
		want  string
	}{
		{"missing profile", map[string]string{"KRAVYX_PROFILE": ""}, "required"},
		{"unknown profile", map[string]string{"KRAVYX_PROFILE": "prod"}, "unknown"},
		{"short dev token", map[string]string{"KRAVYX_DEV_TOKEN": "short"}, "32 characters"},
		{"bad tenant", map[string]string{"KRAVYX_DEV_TENANT_ID": "acme"}, "UUID"},
		{"dev on public addr", map[string]string{"KRAVYX_HTTP_ADDR": "0.0.0.0:8081"}, "loopback"},
		{"body limit too big", map[string]string{"KRAVYX_MAX_BODY_BYTES": "999999999999"}, "between"},
		{"saas with dev token", map[string]string{"KRAVYX_PROFILE": "saas"}, "not allowed"},
		{"saas without TLS", map[string]string{"KRAVYX_PROFILE": "saas", "KRAVYX_DEV_TOKEN": "", "KRAVYX_DEV_TENANT_ID": "", "KRAVYX_DEV_PERMISSIONS": ""}, "TLS is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := devEnv()
			for k, v := range tc.patch {
				m[k] = v
			}
			_, err := Load(env(m))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestProductionProfilesRefuseUntilIdentityExists(t *testing.T) {
	_, err := Load(env(map[string]string{"KRAVYX_PROFILE": "onprem", "KRAVYX_TLS_CERT_FILE": "c", "KRAVYX_TLS_KEY_FILE": "k"}))
	if !errors.Is(err, ErrNoProductionAuth) {
		t.Fatalf("got %v", err)
	}
}
