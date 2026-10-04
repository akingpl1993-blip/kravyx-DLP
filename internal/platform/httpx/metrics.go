package httpx

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Metrics is a minimal Prometheus-text exporter (stdlib only). It is replaced by
// OpenTelemetry once the dependency set is approved; the metric names stay.
type Metrics struct {
	mu      sync.Mutex
	counts  map[string]uint64 // route|status
	buckets map[string][]uint64
	sums    map[string]float64
}

var bounds = []float64{0.005, 0.025, 0.1, 0.25, 1, 2.5, 10}

func NewMetrics() *Metrics {
	return &Metrics{counts: map[string]uint64{}, buckets: map[string][]uint64{}, sums: map[string]float64{}}
}

func (m *Metrics) Observe(route string, status int, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[fmt.Sprintf("%s|%d", route, status)]++
	b, ok := m.buckets[route]
	if !ok {
		b = make([]uint64, len(bounds)+1)
		m.buckets[route] = b
	}
	s := d.Seconds()
	for i, ub := range bounds {
		if s <= ub {
			b[i]++
		}
	}
	b[len(bounds)]++
	m.sums[route] += s
}

func esc(s string) string { return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) }

func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var sb strings.Builder
	sb.WriteString("# TYPE kravyx_http_requests_total counter\n")
	keys := make([]string, 0, len(m.counts))
	for k := range m.counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		route, status, _ := strings.Cut(k, "|")
		fmt.Fprintf(&sb, "kravyx_http_requests_total{route=\"%s\",status=\"%s\"} %d\n", esc(route), status, m.counts[k])
	}
	sb.WriteString("# TYPE kravyx_http_request_duration_seconds histogram\n")
	routes := make([]string, 0, len(m.buckets))
	for r := range m.buckets {
		routes = append(routes, r)
	}
	sort.Strings(routes)
	for _, r := range routes {
		b := m.buckets[r]
		for i, ub := range bounds {
			fmt.Fprintf(&sb, "kravyx_http_request_duration_seconds_bucket{route=\"%s\",le=\"%g\"} %d\n", esc(r), ub, b[i])
		}
		fmt.Fprintf(&sb, "kravyx_http_request_duration_seconds_bucket{route=\"%s\",le=\"+Inf\"} %d\n", esc(r), b[len(bounds)])
		fmt.Fprintf(&sb, "kravyx_http_request_duration_seconds_sum{route=\"%s\"} %g\n", esc(r), m.sums[r])
		fmt.Fprintf(&sb, "kravyx_http_request_duration_seconds_count{route=\"%s\"} %d\n", esc(r), b[len(bounds)])
	}
	_, _ = w.Write([]byte(sb.String()))
}
