package proxify

// Unit and integration tests for the hardened TLS-fingerprinting transport
// (migration plan Step P7). These pin the behaviors the previous
// getTLSClientRoundTripper lacked: fastdialer policy on every socket (direct and
// proxy), request-based route rotation (reusing the P6 selector), context/Host/
// trailer/Request-linkage preservation across the net/http<->fhttp boundary, and
// concurrency safety of one client per route. Everything binds 127.0.0.1 on
// ephemeral ports; no external network.

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/proxify/internal/testutil/proxytest"
)

// tlsClientRT builds a Proxy wired only for transport construction (no
// listeners) in TLS-fingerprint mode with the given upstream config, then
// returns its RoundTripper via the public selection path (getRoundTripper).
// rotateEvery maps to UpstreamProxyRequestsNumber.
func tlsClientRT(t *testing.T, dialer *fastdialer.Dialer, http4, socks []string, rotateEvery int) http.RoundTripper {
	t.Helper()
	p := &Proxy{
		Dialer: dialer,
		options: &Options{
			TLSFingerprint:              true,
			TLSProfile:                  "chrome_120",
			UpstreamHTTPProxies:         http4,
			UpstreamSock5Proxies:        socks,
			UpstreamProxyRequestsNumber: rotateEvery,
		},
	}
	rt, err := p.getRoundTripper()
	if err != nil {
		t.Fatalf("getRoundTripper: %v", err)
	}
	if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
		t.Cleanup(c.CloseIdleConnections)
	}
	return rt
}

// TestTLSClientDirectReachesOrigin: profile chrome_120 reaches a local TLS
// origin, negotiates a non-empty protocol, and preserves Response.Request.
func TestTLSClientDirectReachesOrigin(t *testing.T) {
	origin := proxytest.NewH2Origin(t, protoEchoHandler(nil))
	rt := tlsClientRT(t, newTestDialer(t, nil), nil, nil, 0)

	resp, req := roundTripGet(t, rt, origin.URL.String())

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if resp.Proto == "" || resp.ProtoMajor == 0 {
		t.Fatalf("negotiated protocol empty: proto=%q major=%d", resp.Proto, resp.ProtoMajor)
	}
	if resp.Request != req {
		t.Fatalf("Response.Request = %p, want original request %p", resp.Request, req)
	}
}

// TestTLSClientPreservesTrailers: a response trailer set by the origin after the
// body survives the fhttp->net/http conversion, and Response.Request is the
// effective request. Uses an HTTP/1.1 origin (chunked trailers are
// deterministic there).
func TestTLSClientPreservesTrailers(t *testing.T) {
	origin := proxytest.NewH1Origin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "X-End")
		_, _ = io.WriteString(w, "body")
		w.Header().Set("X-End", "done")
	}))
	rt := tlsClientRT(t, newTestDialer(t, nil), nil, nil, 0)

	resp, req := roundTripGet(t, rt, origin.URL.String())

	if got := resp.Trailer.Get("X-End"); got != "done" {
		t.Fatalf("response trailer X-End = %q, want %q (trailer=%v)", got, "done", resp.Trailer)
	}
	if resp.Request != req {
		t.Fatalf("Response.Request = %p, want original request %p", resp.Request, req)
	}
}

// TestTLSClientContextCancellation: a canceled request errors while a sibling
// concurrent request on the same RoundTripper succeeds.
func TestTLSClientContextCancellation(t *testing.T) {
	origin := proxytest.NewH1Origin(t, okHandler())
	rt := tlsClientRT(t, newTestDialer(t, nil), nil, nil, 0)

	var wg sync.WaitGroup
	wg.Add(2)

	var canceledErr error
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL.String(), nil)
		if err != nil {
			canceledErr = err
			return
		}
		resp, err := rt.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
			canceledErr = nil
			return
		}
		canceledErr = err
	}()

	var siblingStatus int
	go func() {
		defer wg.Done()
		resp, _ := roundTripGet(t, rt, origin.URL.String())
		siblingStatus = resp.StatusCode
	}()

	wg.Wait()

	if canceledErr == nil {
		t.Fatal("canceled RoundTrip succeeded, want error")
	}
	if siblingStatus != http.StatusOK {
		t.Fatalf("sibling request status %d, want 200", siblingStatus)
	}
}

// TestTLSClientHTTPRouteRotation: two local HTTP upstreams at rotateEvery=2 see
// exactly two CONNECTs each over four sequential fingerprinted requests (A,A,B,B).
func TestTLSClientHTTPRouteRotation(t *testing.T) {
	a := proxytest.NewHTTPUpstream(t)
	b := proxytest.NewHTTPUpstream(t)
	origin := proxytest.NewH1Origin(t, okHandler())
	rt := tlsClientRT(t, newTestDialer(t, nil), []string{a.URL, b.URL}, nil, 2)

	for i := 0; i < 4; i++ {
		drainGet(t, rt, origin.URL.String())
	}

	if got := len(a.Hosts()); got != 2 {
		t.Fatalf("HTTP upstream A saw %d CONNECTs, want 2 (%v)", got, a.Hosts())
	}
	if got := len(b.Hosts()); got != 2 {
		t.Fatalf("HTTP upstream B saw %d CONNECTs, want 2 (%v)", got, b.Hosts())
	}
}

// TestTLSClientSOCKSRouteRotation: same A,A,B,B rotation through two local SOCKS5
// upstreams in fingerprint mode.
func TestTLSClientSOCKSRouteRotation(t *testing.T) {
	a := proxytest.NewSOCKS5Upstream(t)
	b := proxytest.NewSOCKS5Upstream(t)
	origin := proxytest.NewH1Origin(t, okHandler())
	rt := tlsClientRT(t, newTestDialer(t, nil), nil, []string{a.Addr, b.Addr}, 2)

	for i := 0; i < 4; i++ {
		drainGet(t, rt, origin.URL.String())
	}

	if got := len(a.Addrs()); got != 2 {
		t.Fatalf("SOCKS upstream A saw %d dials, want 2 (%v)", got, a.Addrs())
	}
	if got := len(b.Addrs()); got != 2 {
		t.Fatalf("SOCKS upstream B saw %d dials, want 2 (%v)", got, b.Addrs())
	}
}

// TestTLSClientFastdialerDenyDirect: a fastdialer denying loopback blocks the
// direct socket, so RoundTrip fails before the origin handler runs.
func TestTLSClientFastdialerDenyDirect(t *testing.T) {
	var hits int32
	origin := proxytest.NewH2Origin(t, protoEchoHandler(&hits))
	dialer := newTestDialer(t, func(o *fastdialer.Options) {
		o.Deny = []string{"127.0.0.0/8"}
	})
	rt := tlsClientRT(t, dialer, nil, nil, 0)

	req, err := http.NewRequest(http.MethodGet, origin.URL.String(), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if resp, err := rt.RoundTrip(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("direct dial to denied loopback succeeded, want error")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("origin handler ran %d times despite deny, want 0", got)
	}
}

// TestTLSClientFastdialerDenyProxy: a fastdialer denying loopback blocks the
// upstream proxy socket, so no CONNECT ever reaches the proxy.
func TestTLSClientFastdialerDenyProxy(t *testing.T) {
	upstream := proxytest.NewHTTPUpstream(t)
	dialer := newTestDialer(t, func(o *fastdialer.Options) {
		o.Deny = []string{"127.0.0.0/8"}
	})
	rt := tlsClientRT(t, dialer, []string{upstream.URL}, nil, 1)

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:1/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if resp, err := rt.RoundTrip(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("dial through denied proxy socket succeeded, want error")
	}
	if got := len(upstream.Hosts()); got != 0 {
		t.Fatalf("proxy saw %d requests despite deny, want 0 (%v)", got, upstream.Hosts())
	}
}

// TestTLSClientConcurrentRequests: 50 concurrent requests on one direct client
// all succeed, proving one client per route is safe for concurrent Do (run under
// -race).
func TestTLSClientConcurrentRequests(t *testing.T) {
	origin := proxytest.NewH2Origin(t, okHandler())
	rt := tlsClientRT(t, newTestDialer(t, nil), nil, nil, 0)

	const n = 50
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodGet, origin.URL.String(), nil)
			if err != nil {
				errs <- err
				return
			}
			resp, err := rt.RoundTrip(req)
			if err != nil {
				errs <- err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent RoundTrip failed: %v", err)
	}
}

// TestConvertToFHTTPRequestCarriesContextAndCopies: the net/http->fhttp
// conversion carries the request context and copies headers, trailers, and
// transfer-encoding into fresh slices so mutating the source never affects the
// converted request.
func TestConvertToFHTTPRequestCarriesContextAndCopies(t *testing.T) {
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "value")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test/path", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Host = "override.test"
	req.Header.Set("X-A", "1")
	req.Trailer = http.Header{"X-T": []string{"t"}}
	req.TransferEncoding = []string{"chunked"}

	fReq, err := convertToFHTTPRequest(req)
	if err != nil {
		t.Fatalf("convertToFHTTPRequest: %v", err)
	}
	if got := fReq.Context().Value(ctxKey{}); got != "value" {
		t.Fatalf("context not carried: got %v", got)
	}
	if fReq.Host != "override.test" {
		t.Fatalf("Host = %q, want override.test", fReq.Host)
	}

	// Mutate the source in place; the converted request must be unaffected.
	req.Header["X-A"][0] = "mutated"
	req.Trailer["X-T"][0] = "mutated"
	req.TransferEncoding[0] = "identity"

	if got := fReq.Header.Get("X-A"); got != "1" {
		t.Fatalf("header aliased: X-A = %q, want 1", got)
	}
	if got := fReq.Trailer.Get("X-T"); got != "t" {
		t.Fatalf("trailer aliased: X-T = %q, want t", got)
	}
	if fReq.TransferEncoding[0] != "chunked" {
		t.Fatalf("transfer-encoding aliased: %v", fReq.TransferEncoding)
	}
}
