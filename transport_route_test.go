package proxify

// Unit tests for request-based upstream routing (migration plan Step P6). These
// pin the two properties the previous roundrobin-in-DialContext design lacked:
// a single route is chosen per RoundTrip (stable across retries/dials), and the
// count-based rotation is concurrent-safe. HTTP and SOCKS route transports are
// exercised against local recording upstreams; everything binds 127.0.0.1 with
// ephemeral ports and no external network.

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"testing"

	"github.com/projectdiscovery/proxify/internal/testutil/proxytest"
	"github.com/projectdiscovery/proxify/pkg/certs"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/proxify/pkg/types"
)

// routedProxy builds a Proxy wired only for transport construction (no
// listeners) with the given upstream config, then returns its standard
// RoundTripper. rotateEvery maps to UpstreamProxyRequestsNumber.
func routedProxy(t *testing.T, http4, socks []string, rotateEvery int) http.RoundTripper {
	t.Helper()
	p := &Proxy{
		Dialer: newTestDialer(t, nil),
		options: &Options{
			UpstreamHTTPProxies:         http4,
			UpstreamSock5Proxies:        socks,
			UpstreamProxyRequestsNumber: rotateEvery,
		},
	}
	rt, err := p.getStandardRoundTripper()
	if err != nil {
		t.Fatalf("getStandardRoundTripper: %v", err)
	}
	if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
		t.Cleanup(c.CloseIdleConnections)
	}
	return rt
}

// TestRouteSelectorSequence: routes [A,B] at rotateEvery=2 hand out A,A,B,B,A.
func TestRouteSelectorSequence(t *testing.T) {
	s, err := newRouteSelector([]string{"A", "B"}, 2)
	if err != nil {
		t.Fatalf("newRouteSelector: %v", err)
	}
	want := []string{"A", "A", "B", "B", "A"}
	for i, w := range want {
		if got := s.Next(); got != w {
			t.Fatalf("selection %d = %q, want %q", i+1, got, w)
		}
	}
}

// TestRouteSelectorConcurrent: 100 concurrent selections over [A,B] at
// rotateEvery=2 split exactly 50/50, proving the count-based rotation is
// concurrent-safe (run under -race). Distribution is invariant to interleaving
// because each Next() is serialized under the selector mutex.
func TestRouteSelectorConcurrent(t *testing.T) {
	s, err := newRouteSelector([]string{"A", "B"}, 2)
	if err != nil {
		t.Fatalf("newRouteSelector: %v", err)
	}
	const n = 100
	var mu sync.Mutex
	counts := map[string]int{}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := s.Next()
			mu.Lock()
			counts[r]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if counts["A"] != 50 || counts["B"] != 50 {
		t.Fatalf("distribution A=%d B=%d, want 50/50", counts["A"], counts["B"])
	}
}

// TestRouteSelectorRejectsBadConfig: constructor rejects an empty route list and
// a non-positive rotateEvery.
func TestRouteSelectorRejectsBadConfig(t *testing.T) {
	if _, err := newRouteSelector(nil, 2); err == nil {
		t.Fatal("newRouteSelector accepted empty route list")
	}
	if _, err := newRouteSelector([]string{"A"}, 0); err == nil {
		t.Fatal("newRouteSelector accepted rotateEvery=0")
	}
}

// TestRoutedHTTPProxiesDistribution: two local HTTP upstreams at rotateEvery=2
// see exactly two requests each over four sequential calls (requests 1-2 to A,
// 3-4 to B).
func TestRoutedHTTPProxiesDistribution(t *testing.T) {
	a := proxytest.NewHTTPUpstream(t)
	b := proxytest.NewHTTPUpstream(t)
	origin := proxytest.NewPlainOrigin(t, okHandler())
	rt := routedProxy(t, []string{a.URL, b.URL}, nil, 2)

	for i := 0; i < 4; i++ {
		drainGet(t, rt, origin.URL)
	}

	if got := len(a.Hosts()); got != 2 {
		t.Fatalf("upstream A saw %d requests, want 2 (%v)", got, a.Hosts())
	}
	if got := len(b.Hosts()); got != 2 {
		t.Fatalf("upstream B saw %d requests, want 2 (%v)", got, b.Hosts())
	}
}

// TestRoutedSOCKSProxiesDistribution: same distribution through two local SOCKS5
// upstreams.
func TestRoutedSOCKSProxiesDistribution(t *testing.T) {
	a := proxytest.NewSOCKS5Upstream(t)
	b := proxytest.NewSOCKS5Upstream(t)
	origin := proxytest.NewPlainOrigin(t, okHandler())
	rt := routedProxy(t, nil, []string{a.Addr, b.Addr}, 2)

	for i := 0; i < 4; i++ {
		drainGet(t, rt, origin.URL)
	}

	if got := len(a.Addrs()); got != 2 {
		t.Fatalf("SOCKS upstream A saw %d dials, want 2 (%v)", got, a.Addrs())
	}
	if got := len(b.Addrs()); got != 2 {
		t.Fatalf("SOCKS upstream B saw %d dials, want 2 (%v)", got, b.Addrs())
	}
}

// TestRoutedRequestStaysOnRouteWhenCanceled: at rotateEvery=1 the sequence is
// A,B,A,B. Canceling request 2 (which selects B) errors on B's route without
// falling back to A: A ends with two successful dials and B with one, proving
// the canceled request consumed B's turn rather than retrying elsewhere.
func TestRoutedRequestStaysOnRouteWhenCanceled(t *testing.T) {
	a := proxytest.NewSOCKS5Upstream(t)
	b := proxytest.NewSOCKS5Upstream(t)
	origin := proxytest.NewPlainOrigin(t, okHandler())
	rt := routedProxy(t, nil, []string{a.Addr, b.Addr}, 1)

	drainGet(t, rt, origin.URL) // 1 -> A

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(canceled, http.MethodGet, origin.URL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	if resp, err := rt.RoundTrip(req); err == nil { // 2 -> B, canceled
		_ = resp.Body.Close()
		t.Fatal("canceled RoundTrip succeeded, want error")
	}

	drainGet(t, rt, origin.URL) // 3 -> A
	drainGet(t, rt, origin.URL) // 4 -> B

	if got := len(a.Addrs()); got != 2 {
		t.Fatalf("route A saw %d dials, want 2 (no fallback expected) (%v)", got, a.Addrs())
	}
	if got := len(b.Addrs()); got != 1 {
		t.Fatalf("route B saw %d dials, want 1 (canceled req made no dial) (%v)", got, b.Addrs())
	}
}

// TestNewProxyRejectsBadUpstreamRouting: an invalid upstream URL or zero
// rotation is caught at NewProxy time, not deferred to the first request.
func TestNewProxyRejectsBadUpstreamRouting(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Options)
	}{
		{"zero rotation", func(o *Options) {
			o.UpstreamHTTPProxies = []string{"http://127.0.0.1:8080"}
			o.UpstreamProxyRequestsNumber = 0
		}},
		{"invalid url", func(o *Options) {
			o.UpstreamHTTPProxies = []string{"http://[::1"}
			o.UpstreamProxyRequestsNumber = 1
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configDir := t.TempDir()
			if err := certs.LoadCerts(configDir); err != nil {
				t.Fatalf("LoadCerts: %v", err)
			}
			opts := &Options{
				Directory:       configDir,
				OutputDirectory: filepath.Join(t.TempDir(), "logs"),
				CertCacheSize:   256,
				Verbosity:       types.VerbositySilent,
				ListenAddrHTTP:  freeAddr(t),
				Elastic:         &elastic.Options{},
				Kafka:           &kafka.Options{},
			}
			tc.mutate(opts)
			if _, err := NewProxy(opts); err == nil {
				t.Fatal("NewProxy accepted bad upstream routing config, want error")
			}
		})
	}
}

// okHandler is a trivial 200 OK origin handler for routing tests.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
}

// drainGet issues a GET through rt and drains the body, failing on error.
func drainGet(t *testing.T, rt http.RoundTripper, rawURL string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip %s: %v", rawURL, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
