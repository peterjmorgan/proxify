package proxify

// Direct integration tests for the mitmproxy-go candidate adapter (migration
// plan Step P9). The adapter is instantiated and served under an httptest HTTP
// server while Proxy.Run still uses the Martian core; these tests exercise the
// candidate path in isolation. Everything runs on 127.0.0.1 with ephemeral
// ports; no external network.

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/proxify/internal/testutil/proxytest"
	"github.com/projectdiscovery/proxify/pkg/certs"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/proxify/pkg/types"
)

// newAdapterProxy builds a Proxy with a fresh on-disk CA and returns it. mutate
// may adjust Options before NewProxy. The Martian core is still built by
// NewProxy (P9), but these tests drive only the candidate adapter.
func newAdapterProxy(t *testing.T, mutate func(*Options)) *Proxy {
	t.Helper()

	dir := t.TempDir()
	if err := certs.LoadCerts(dir); err != nil {
		t.Fatalf("LoadCerts(%q): %v", dir, err)
	}
	opts := &Options{
		Directory:     dir,
		CertCacheSize: 256,
		Verbosity:     types.VerbositySilent,
		Elastic:       &elastic.Options{},
		Kafka:         &kafka.Options{},
	}
	if mutate != nil {
		mutate(opts)
	}
	p, err := NewProxy(opts)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	return p
}

// serveAdapter builds the candidate adapter over p's direct transport and
// serves it on an ephemeral loopback HTTP server, returning the proxy URL and a
// pool trusting Proxify's CA (the CA that signs the MITM leaves).
func serveAdapter(t *testing.T, p *Proxy) (proxyURL string, caPool *x509.CertPool) {
	t.Helper()

	rt := newStandardTransport(p.Dialer)
	adapter, err := newMitmproxyAdapter(p, rt)
	if err != nil {
		t.Fatalf("newMitmproxyAdapter: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(adapter.ServeHTTP))
	t.Cleanup(srv.Close)
	t.Cleanup(adapter.Cleanup)

	pool := x509.NewCertPool()
	raw, err := certs.GetRawCA()
	if err != nil {
		t.Fatalf("GetRawCA: %v", err)
	}
	if !pool.AppendCertsFromPEM(raw.Bytes()) {
		t.Fatal("failed to add proxify CA to pool")
	}
	return srv.URL, pool
}

// TestAdapterMissingCAReturnsError: newMitmproxyAdapter fails with a descriptive
// error when the CA cert/key files are absent, rather than deferring to an
// opaque fork handshake failure.
func TestAdapterMissingCAReturnsError(t *testing.T) {
	// Load a CA elsewhere so NewProxy's Martian core has a usable global CA,
	// then point the adapter at an empty directory with no CA files.
	if err := certs.LoadCerts(t.TempDir()); err != nil {
		t.Fatalf("LoadCerts: %v", err)
	}
	emptyDir := t.TempDir() // deliberately no CA files
	opts := &Options{
		Directory:     emptyDir,
		CertCacheSize: 256,
		Verbosity:     types.VerbositySilent,
		Elastic:       &elastic.Options{},
		Kafka:         &kafka.Options{},
	}
	p, err := NewProxy(opts)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	_, err = newMitmproxyAdapter(p, newStandardTransport(p.Dialer))
	if err == nil {
		t.Fatal("expected error when CA files are missing, got nil")
	}
	if !strings.Contains(err.Error(), "CA certificate not found") {
		t.Fatalf("error = %q, want it to mention the missing CA certificate", err)
	}
}

// TestAdapterH1ConnectLogsCallbacksOnce: a single H1 CONNECT drives the CONNECT
// request and its 200 through Proxify's callbacks exactly once (via the
// lifecycle hook), then the inner GET exactly once (via the HTTP interceptor).
func TestAdapterH1ConnectLogsCallbacksOnce(t *testing.T) {
	origin := proxytest.NewH1Origin(t, helloHandler())

	var mu sync.Mutex
	var reqMethods []string
	var respCount int
	p := newAdapterProxy(t, func(o *Options) {
		o.OnRequestCallback = func(req *http.Request, _ *FlowContext) error {
			mu.Lock()
			reqMethods = append(reqMethods, req.Method)
			mu.Unlock()
			return nil
		}
		o.OnResponseCallback = func(_ *http.Response, _ *FlowContext) error {
			mu.Lock()
			respCount++
			mu.Unlock()
			return nil
		}
	})
	proxyURL, caPool := serveAdapter(t, p)
	client := proxytest.ProxyClient(t, proxyURL, caPool, false)

	resp, err := client.Get(origin.URL.String() + "/hello")
	if err != nil {
		t.Fatalf("GET https via CONNECT: %v", err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	connects, gets := 0, 0
	for _, m := range reqMethods {
		switch m {
		case http.MethodConnect:
			connects++
		case http.MethodGet:
			gets++
		}
	}
	if connects != 1 {
		t.Fatalf("CONNECT request callbacks = %d, want 1 (methods=%v)", connects, reqMethods)
	}
	if gets != 1 {
		t.Fatalf("inner GET request callbacks = %d, want 1 (methods=%v)", gets, reqMethods)
	}
	if len(reqMethods) != 2 {
		t.Fatalf("total request callbacks = %d, want 2 (methods=%v)", len(reqMethods), reqMethods)
	}
	// One response for the CONNECT (200 established) and one for the inner GET.
	if respCount != 2 {
		t.Fatalf("response callbacks = %d, want 2", respCount)
	}
}

// TestAdapterH2ConcurrentFlows: two concurrent HTTP/2 streams multiplexed over
// one client connection get distinct flow ids but share the same connection id.
func TestAdapterH2ConcurrentFlows(t *testing.T) {
	const concurrency = 2

	arrivals := make(chan struct{}, concurrency)
	release := make(chan struct{})
	origin := proxytest.NewH2Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals <- struct{}{}
		<-release // hold the stream open until every concurrent request has arrived
		w.WriteHeader(http.StatusOK)
	}))

	type flowKey struct{ flowID, connID string }
	var mu sync.Mutex
	var innerFlows []flowKey
	p := newAdapterProxy(t, func(o *Options) {
		o.OnRequestCallback = func(req *http.Request, ctx *FlowContext) error {
			if req.Method == http.MethodConnect {
				return nil // CONNECT control channel, not an inner stream
			}
			mu.Lock()
			innerFlows = append(innerFlows, flowKey{ctx.ID(), ctx.ConnectionID()})
			mu.Unlock()
			return nil
		}
	})
	proxyURL, caPool := serveAdapter(t, p)

	// A keep-alive H2 client so concurrent requests to the same origin
	// multiplex over one CONNECT tunnel (one connection id).
	client := h2KeepAliveProxyClient(t, proxyURL, caPool)

	// Warm up one connection first so the concurrent pair reuses it rather than
	// racing to dial two separate tunnels. Run it in a goroutine because the
	// origin handler blocks until released.
	warmDone := make(chan error, 1)
	go func() {
		resp, err := client.Get(origin.URL.String() + "/hello")
		if err == nil {
			_ = resp.Body.Close()
		}
		warmDone <- err
	}()
	<-arrivals              // warm-up stream arrived
	release <- struct{}{}   // let it complete
	if err := <-warmDone; err != nil {
		t.Fatalf("warm-up GET: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, concurrency)
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(origin.URL.String() + "/hello")
			if err != nil {
				errs <- err
				return
			}
			_ = resp.Body.Close()
		}()
	}
	// Wait for both concurrent streams to be in flight, then release them
	// together so they are genuinely multiplexed.
	for range concurrency {
		<-arrivals
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent GET: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(innerFlows) < concurrency+1 {
		t.Fatalf("inner flows = %d, want at least %d", len(innerFlows), concurrency+1)
	}
	flowIDs := map[string]struct{}{}
	connIDs := map[string]struct{}{}
	for _, f := range innerFlows {
		if f.flowID == "" {
			t.Fatal("inner flow has empty flow id")
		}
		if f.connID == "" {
			t.Fatal("inner flow has empty connection id")
		}
		flowIDs[f.flowID] = struct{}{}
		connIDs[f.connID] = struct{}{}
	}
	if len(flowIDs) != len(innerFlows) {
		t.Fatalf("flow ids not all distinct: %d unique of %d flows", len(flowIDs), len(innerFlows))
	}
	if len(connIDs) != 1 {
		t.Fatalf("connection ids = %d unique, want 1 (all inner streams share one connection)", len(connIDs))
	}
}

// h2KeepAliveProxyClient builds an HTTP/2-capable client that routes through
// proxyURL, trusts caPool, and keeps connections alive so concurrent requests
// multiplex over a single tunnel.
func h2KeepAliveProxyClient(t *testing.T, proxyURL string, caPool *x509.CertPool) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy URL %q: %v", proxyURL, err)
	}
	transport := &http.Transport{
		Proxy:             http.ProxyURL(u),
		TLSClientConfig:   &tls.Config{RootCAs: caPool},
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

// TestAdapterPassthroughPredicateFullHostport: the passthrough predicate is fed
// the full host:port, so a port-pinned regex matches only when the port is
// present.
func TestAdapterPassthroughPredicateFullHostport(t *testing.T) {
	p := newAdapterProxy(t, func(o *Options) {
		o.PassThrough = []string{`.*\.opaque\.test:443`}
	})
	adapter, err := newMitmproxyAdapter(p, newStandardTransport(p.Dialer))
	if err != nil {
		t.Fatalf("newMitmproxyAdapter: %v", err)
	}

	if !adapter.shouldPassthrough("foo.opaque.test:443") {
		t.Fatal("full hostport foo.opaque.test:443 should match the port-pinned regex")
	}
	if adapter.shouldPassthrough("foo.opaque.test") {
		t.Fatal("host without :443 must not match a port-pinned regex")
	}
	if adapter.shouldPassthrough("example.com:443") {
		t.Fatal("unrelated hostport must not match")
	}
}

// TestCacheCapacityHonorsExactAndDefault: the adapter resolves the leaf-cache
// capacity to the requested value exactly, defaulting to 256 only when unset.
func TestCacheCapacityHonorsExactAndDefault(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, defaultCertCacheSize},
		{-7, defaultCertCacheSize},
		{1, 1},
		{256, 256},
		{257, 257},
	}
	for _, c := range cases {
		if got := cacheCapacity(c.in); got != c.want {
			t.Errorf("cacheCapacity(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestAdapterCacheCapacityForkContract characterizes the pinned fork (v1.2.0)
// cert-cache capacity contract as observed through newMitmproxyAdapter. The
// adapter passes the requested capacity through verbatim; the fork currently
// accepts only multiples of 256 (mitm.go's surviving multiple-of-256 guard).
//
// Plan Step F4 (fork track) is meant to replace that guard with exact-capacity
// support, at which point capacities 1 and 257 should construct successfully;
// this test will fail then and must be updated to expect success.
func TestAdapterCacheCapacityForkContract(t *testing.T) {
	newAt := func(size int) error {
		p := newAdapterProxy(t, func(o *Options) { o.CertCacheSize = size })
		_, err := newMitmproxyAdapter(p, newStandardTransport(p.Dialer))
		return err
	}

	if err := newAt(256); err != nil {
		t.Fatalf("capacity 256 should construct, got %v", err)
	}
	for _, size := range []int{1, 257} {
		err := newAt(size)
		if err == nil {
			t.Fatalf("capacity %d unexpectedly constructed; fork F4 guard-removal may have landed — update this test to expect success", size)
		}
		if !strings.Contains(err.Error(), "multiple of 256") {
			t.Fatalf("capacity %d error = %q, want the fork multiple-of-256 guard", size, err)
		}
	}
}
