// Package config loads service configuration from KRAVYX_* environment variables
// and refuses to start in any unsafe combination (fail closed).
package config

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/akingpl1993-blip/kravyx-DLP/internal/platform/secret"
)

type Profile string

const (
	Dev         Profile = "dev"
	SaaS        Profile = "saas"
	PrivateSaaS Profile = "private-saas"
	OnPrem      Profile = "onprem"
)

type Config struct {
	Profile      Profile
	HTTPAddr     string
	TLSCertFile  string
	TLSKeyFile   string
	MaxBodyBytes int64

	// Dev-only authenticator (replaced by the Identity service in increment 1c).
	DevToken       secret.String
	DevTenantID    string
	DevSubject     string
	DevPermissions []string
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ErrNoProductionAuth is returned outside the dev profile until the Identity
// service exists: the Policy API must never run unauthenticated.
var ErrNoProductionAuth = errors.New("no production authenticator is available yet (Identity service arrives in increment 1c); only KRAVYX_PROFILE=dev can start")

// Load reads configuration through getenv (os.Getenv in production, a map in tests).
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		Profile:      Profile(getenv("KRAVYX_PROFILE")),
		HTTPAddr:     getenv("KRAVYX_HTTP_ADDR"),
		TLSCertFile:  getenv("KRAVYX_TLS_CERT_FILE"),
		TLSKeyFile:   getenv("KRAVYX_TLS_KEY_FILE"),
		MaxBodyBytes: 8 << 20,
	}
	switch c.Profile {
	case Dev, SaaS, PrivateSaaS, OnPrem:
	case "":
		return c, errors.New("KRAVYX_PROFILE is required (dev, saas, private-saas, onprem)")
	default:
		return c, fmt.Errorf("unknown KRAVYX_PROFILE %q", c.Profile)
	}
	if v := getenv("KRAVYX_MAX_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1024 || n > 64<<20 {
			return c, errors.New("KRAVYX_MAX_BODY_BYTES must be between 1024 and 67108864")
		}
		c.MaxBodyBytes = n
	}
	if c.HTTPAddr == "" {
		c.HTTPAddr = "127.0.0.1:8081"
	}
	host, _, err := net.SplitHostPort(c.HTTPAddr)
	if err != nil {
		return c, fmt.Errorf("KRAVYX_HTTP_ADDR: %w", err)
	}

	devVars := []string{"KRAVYX_DEV_TOKEN", "KRAVYX_DEV_TENANT_ID", "KRAVYX_DEV_PERMISSIONS", "KRAVYX_DEV_SUBJECT"}
	if c.Profile != Dev {
		for _, k := range devVars {
			if getenv(k) != "" {
				return c, fmt.Errorf("%s is not allowed in profile %q", k, c.Profile)
			}
		}
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return c, fmt.Errorf("TLS is required in profile %q (KRAVYX_TLS_CERT_FILE, KRAVYX_TLS_KEY_FILE)", c.Profile)
		}
		return c, ErrNoProductionAuth
	}

	// Dev profile guardrails.
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return c, fmt.Errorf("dev profile must bind a loopback address, got %q", host)
	}
	tok := getenv("KRAVYX_DEV_TOKEN")
	if len(tok) < 32 {
		return c, errors.New("KRAVYX_DEV_TOKEN must be at least 32 characters (generate one: openssl rand -hex 32)")
	}
	c.DevToken = secret.New(tok)
	c.DevTenantID = strings.ToLower(getenv("KRAVYX_DEV_TENANT_ID"))
	if !uuidRe.MatchString(c.DevTenantID) {
		return c, errors.New("KRAVYX_DEV_TENANT_ID must be a UUID")
	}
	c.DevSubject = getenv("KRAVYX_DEV_SUBJECT")
	if c.DevSubject == "" {
		c.DevSubject = "dev-user"
	}
	for _, p := range strings.Split(getenv("KRAVYX_DEV_PERMISSIONS"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			c.DevPermissions = append(c.DevPermissions, p)
		}
	}
	return c, nil
}
