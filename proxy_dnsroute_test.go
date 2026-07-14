package proxify

// DNS-policy, upstream-route-rotation, and TLS-mode E2E tests for migration plan
// Step P13. Transport-level unit tests already pin these behaviors in isolation
// (transport_test.go P5, transport_route_test.go P6, transport_tlsclient_test.go
// P7); these drive the candidate serving core (Proxy.Run over a real loopback
// listener) instead, proving no migration path bypasses fastdialer policy or the
// request-based route selector when a real client speaks to Proxify.
//
// Everything binds 127.0.0.1 with ephemeral ports and synchronizes on bounded
// polls/counters — no external network and no public DNS. The DNS test uses the
// reserved `.test` TLD, which cannot resolve publicly, so a successful dial
// proves the mapping went through Proxify's tinydns resolver rather than the OS.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/proxify/internal/testutil/proxytest"
)

// freeUDPAddr reserves an ephemeral 127.0.0.1 UDP port and returns it in the
// ":port" form Options.ListenDNSAddr expects (NewProxy builds the tinydns base
// resolver as "127.0.0.1"+ListenDNSAddr). It mirrors freeAddr's reserve-and-close
// pattern for TCP.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve ephemeral UDP port: %v", err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()
	return fmt.Sprintf(":%d", port)
}

// waitForDNSMapping polls Proxify's tinydns resolver (started asynchronously by
// Proxy.Run) until it answers host with wantIP, so the counted request below is
// sent only once the mapping is live. Querying the resolver directly makes DNS
// readiness deterministic instead of racing tinydns startup.
func waitForDNSMapping(t *testing.T, dnsAddr, host, wantIP string) {
	t.Helper()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", "127.0.0.1"+dnsAddr)
		},
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		addrs, err := resolver.LookupHost(ctx, host)
		cancel()
		if err == nil {
			for _, a := range addrs {
				if a == wantIP {
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tinydns never resolved %s -> %s within timeout", host, wantIP)
}

// TestDNSMappingReachesLocalOriginEndToEnd proves a DNS mapping resolves through
// Proxify's tinydns without public DNS: mapped.test -> 127.0.0.1 lets a client
// request to http://mapped.test:<origin-port>/ reach a local origin exactly once.
// The .test TLD is reserved (never publicly resolvable), so the single origin hit
// can only have come through the mapping.
func TestDNSMappingReachesLocalOriginEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var hosts []string
	origin := proxytest.NewPlainOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		mu.Unlock()
		_, _ = io.WriteString(w, "mapped-ok")
	}))

	u, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatalf("parse origin URL %q: %v", origin.URL, err)
	}
	originPort := u.Port()

	dnsAddr := freeUDPAddr(t)
	proxyURL, _, _ := startProxy(t, func(o *Options) {
		o.ListenDNSAddr = dnsAddr
		o.DNSMapping = "mapped.test:127.0.0.1"
	})

	waitForDNSMapping(t, dnsAddr, "mapped.test", "127.0.0.1")

	client := proxytest.ProxyClient(t, proxyURL, nil, false)
	resp, err := client.Get("http://mapped.test:" + originPort + "/")
	if err != nil {
		t.Fatalf("GET http://mapped.test:%s via proxy: %v", originPort, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "mapped-ok" {
		t.Fatalf("got %d %q, want 200 mapped-ok", resp.StatusCode, body)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(hosts) != 1 {
		t.Fatalf("mapped.test origin hit counter = %d, want 1 (%v)", len(hosts), hosts)
	}
	if !strings.HasPrefix(hosts[0], "mapped.test:") {
		t.Fatalf("origin saw Host %q, want it to carry mapped.test", hosts[0])
	}
}

// TestDenyAllowPolicyEndToEnd proves fastdialer allow/deny policy is enforced on
// the candidate serving core's upstream dial: a deny of the loopback CIDR rejects
// before the origin (hit counter 0), while a matching allow permits it (hit
// counter 1). Uses clear HTTP so the dial target is the origin IP directly.
func TestDenyAllowPolicyEndToEnd(t *testing.T) {
	t.Run("deny_rejects_before_origin", func(t *testing.T) {
		var hits int32
		origin := proxytest.NewPlainOrigin(t, protoEchoHandler(&hits))
		proxyURL, _, _ := startProxy(t, func(o *Options) {
			o.Deny = []string{"127.0.0.0/8"}
		})
		client := proxytest.ProxyClient(t, proxyURL, nil, false)

		// The client may see a gateway error status or a transport error; either
		// is fine. The contract is that the origin is never reached.
		if resp, err := client.Get(origin.URL + "/denied"); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		if got := atomic.LoadInt32(&hits); got != 0 {
			t.Fatalf("denied origin hit counter = %d, want 0", got)
		}
	})

	t.Run("allow_permits", func(t *testing.T) {
		var hits int32
		origin := proxytest.NewPlainOrigin(t, protoEchoHandler(&hits))
		proxyURL, _, _ := startProxy(t, func(o *Options) {
			o.Allow = []string{"127.0.0.0/8"}
		})
		client := proxytest.ProxyClient(t, proxyURL, nil, false)

		resp, err := client.Get(origin.URL + "/allowed")
		if err != nil {
			t.Fatalf("GET allowed origin via proxy: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if got := atomic.LoadInt32(&hits); got != 1 {
			t.Fatalf("allowed origin hit counter = %d, want 1", got)
		}
	})
}

// TestUpstreamRouteRotationEndToEnd proves request-based route rotation holds
// through the candidate serving core for both upstream proxy kinds: four
// sequential requests at rotateEvery=2 over two upstreams produce the exact
// A,A,B,B sequence. Because the requests are sequential, the cumulative per-route
// counts after each request ([1,0],[2,0],[2,1],[2,2]) establish the exact order
// (equivalent to asserting a per-request proxy-ID sequence of [A,A,B,B]).
func TestUpstreamRouteRotationEndToEnd(t *testing.T) {
	// Expected cumulative dial counts on (A, B) after request i (0-indexed).
	wantA := [4]int{1, 2, 2, 2}
	wantB := [4]int{0, 0, 1, 2}

	t.Run("http_proxies", func(t *testing.T) {
		a := proxytest.NewHTTPUpstream(t)
		b := proxytest.NewHTTPUpstream(t)
		origin := proxytest.NewPlainOrigin(t, okHandler())
		proxyURL, _, _ := startProxy(t, func(o *Options) {
			o.UpstreamHTTPProxies = []string{a.URL, b.URL}
			o.UpstreamProxyRequestsNumber = 2
		})
		client := proxytest.ProxyClient(t, proxyURL, nil, false)

		for i := 0; i < 4; i++ {
			resp, err := client.Get(origin.URL + "/")
			if err != nil {
				t.Fatalf("request %d via proxy: %v", i+1, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if got := len(a.Hosts()); got != wantA[i] {
				t.Fatalf("after request %d: HTTP upstream A saw %d, want %d (A=%v B=%v)", i+1, got, wantA[i], a.Hosts(), b.Hosts())
			}
			if got := len(b.Hosts()); got != wantB[i] {
				t.Fatalf("after request %d: HTTP upstream B saw %d, want %d (A=%v B=%v)", i+1, got, wantB[i], a.Hosts(), b.Hosts())
			}
		}
	})

	t.Run("socks5_proxies", func(t *testing.T) {
		a := proxytest.NewSOCKS5Upstream(t)
		b := proxytest.NewSOCKS5Upstream(t)
		origin := proxytest.NewPlainOrigin(t, okHandler())
		proxyURL, _, _ := startProxy(t, func(o *Options) {
			o.UpstreamSock5Proxies = []string{a.Addr, b.Addr}
			o.UpstreamProxyRequestsNumber = 2
		})
		client := proxytest.ProxyClient(t, proxyURL, nil, false)

		for i := 0; i < 4; i++ {
			resp, err := client.Get(origin.URL + "/")
			if err != nil {
				t.Fatalf("request %d via proxy: %v", i+1, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if got := len(a.Addrs()); got != wantA[i] {
				t.Fatalf("after request %d: SOCKS upstream A saw %d, want %d (A=%v B=%v)", i+1, got, wantA[i], a.Addrs(), b.Addrs())
			}
			if got := len(b.Addrs()); got != wantB[i] {
				t.Fatalf("after request %d: SOCKS upstream B saw %d, want %d (A=%v B=%v)", i+1, got, wantB[i], a.Addrs(), b.Addrs())
			}
		}
	})
}

// TestTLSModesEndToEnd proves both upstream TLS modes reach an HTTPS origin
// through the candidate serving core: the standard transport and the named
// fingerprint profile chrome_120. Each asserts the origin saw a valid request
// (200 + a negotiated upstream protocol echoed back), that Response.Request stays
// linked to the client's request, and that the client negotiated a non-empty
// TLS/HTTP protocol with the MITM leaf.
func TestTLSModesEndToEnd(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Options)
	}{
		{"standard", func(*Options) {}},
		{"chrome_120", func(o *Options) {
			o.TLSFingerprint = true
			o.TLSProfile = "chrome_120"
		}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var hits int32
			origin := proxytest.NewH2Origin(t, protoEchoHandler(&hits))
			proxyURL, caPool, _ := startProxy(t, tc.mutate)
			client := proxytest.ProxyClient(t, proxyURL, caPool, false)

			resp, err := client.Get(origin.URL.String() + "/tls")
			if err != nil {
				t.Fatalf("GET https origin via proxy: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusOK || string(body) != "hello" {
				t.Fatalf("got %d %q, want 200 hello", resp.StatusCode, body)
			}
			if got := atomic.LoadInt32(&hits); got != 1 {
				t.Fatalf("origin hit counter = %d, want 1", got)
			}
			// Origin saw a valid request: it echoed the protocol it negotiated.
			if got := resp.Header.Get("X-Origin-Proto"); got == "" {
				t.Fatal("origin did not echo a negotiated protocol (X-Origin-Proto empty)")
			}
			// Response.Request linkage survives the transport (relevant to the
			// fhttp<->net/http conversion in fingerprint mode).
			if resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.Path != "/tls" {
				t.Fatalf("Response.Request not linked to client request: %+v", resp.Request)
			}
			// Non-empty negotiated TLS + HTTP protocol on the client<->MITM leaf.
			if resp.TLS == nil {
				t.Fatal("no negotiated TLS state on response")
			}
			if resp.Proto == "" || resp.ProtoMajor == 0 {
				t.Fatalf("negotiated HTTP protocol empty: proto=%q major=%d", resp.Proto, resp.ProtoMajor)
			}
		})
	}
}

// TestFingerprintConcurrentRequestsEndToEnd fires 50 concurrent fingerprinted
// requests through the candidate serving core; all must succeed with no data race
// on the shared header/body conversion state (run under -race).
func TestFingerprintConcurrentRequestsEndToEnd(t *testing.T) {
	origin := proxytest.NewH2Origin(t, okHandler())
	proxyURL, caPool, _ := startProxy(t, func(o *Options) {
		o.TLSFingerprint = true
		o.TLSProfile = "chrome_120"
	})
	client := proxytest.ProxyClient(t, proxyURL, caPool, false)

	const n = 50
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(origin.URL.String() + "/c")
			if err != nil {
				errs <- err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("status %d, want 200", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent fingerprint request failed: %v", err)
	}
}
