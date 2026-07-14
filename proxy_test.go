package proxify

// Characterization tests for the CURRENT Martian-based proxy (migration plan
// Step P1). These pin observable behavior — status/body, presented
// certificates (MITM vs passthrough), negotiated protocol, and header
// mutations — so the mitmproxy-go core swap (P4+) can prove compatibility.
// Everything runs on 127.0.0.1 with ephemeral ports; no external network.

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
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

// freeAddr reserves an ephemeral 127.0.0.1 port and returns host:port.
// Proxy.Run listens itself, so tests pick the port first instead of reading
// the unexported listenAddr from Run's goroutine.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve ephemeral port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// startProxy loads a fresh CA into temp dirs, builds the current Proxy, and
// serves it on an ephemeral loopback port. It returns the proxy URL and a
// pool trusting this proxy's CA. mutate may adjust Options before NewProxy.
//
// Note: Proxy.Stop is currently a no-op, so serving goroutines run until the
// test binary exits; each test uses its own port and config dir.
func startProxy(t *testing.T, mutate func(*Options)) (proxyURL string, caPool *x509.CertPool, configDir string) {
	t.Helper()

	configDir = t.TempDir()

	// The logs dir gets its own temp root instead of t.TempDir(): the async
	// file logger can write a log entry after the test returns (Stop is a
	// no-op until P16), and a late write makes t.TempDir's RemoveAll fail the
	// test with "directory not empty". Removal here is best-effort with
	// retries; a leaked dir must not fail the test.
	outputRoot, err := os.MkdirTemp("", "proxify-test-logs-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		for i := 0; i < 40; i++ {
			if os.RemoveAll(outputRoot) == nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
	outputDir := filepath.Join(outputRoot, "logs")

	if err := certs.LoadCerts(configDir); err != nil {
		t.Fatalf("LoadCerts(%q): %v", configDir, err)
	}

	opts := &Options{
		Directory:       configDir,
		OutputDirectory: outputDir,
		CertCacheSize:   256,
		Verbosity:       types.VerbositySilent,
		ListenAddrHTTP:  freeAddr(t),
		// The logger dereferences these unconditionally; mirror the runner.
		Elastic: &elastic.Options{},
		Kafka:   &kafka.Options{},
	}
	if mutate != nil {
		mutate(opts)
	}

	proxy, err := NewProxy(opts)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	go func() { _ = proxy.Run() }()

	waitForListener(t, opts.ListenAddrHTTP)

	pool := x509.NewCertPool()
	raw, err := certs.GetRawCA()
	if err != nil {
		t.Fatalf("GetRawCA: %v", err)
	}
	if !pool.AppendCertsFromPEM(raw.Bytes()) {
		t.Fatal("failed to add proxify CA to pool")
	}
	return "http://" + opts.ListenAddrHTTP, pool, configDir
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("proxy never started listening on %s", addr)
}

func helloHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo selected request headers so tests can observe proxy-side
		// request mutations from the client side.
		w.Header().Set("X-Echo-Test", r.Header.Get("X-Test"))
		w.Header().Set("X-Echo-Accept-Encoding", r.Header.Get("Accept-Encoding"))
		fmt.Fprint(w, "hello")
	})
}

// TestCharacterizeH1PlainHTTP: plain HTTP/1.1 through the proxy returns the
// origin response, and the proxy strips "br" from Accept-Encoding.
func TestCharacterizeH1PlainHTTP(t *testing.T) {
	origin := proxytest.NewPlainOrigin(t, helloHandler())
	proxyURL, _, _ := startProxy(t, nil)
	client := proxytest.ProxyClient(t, proxyURL, nil, false)

	req, err := http.NewRequest(http.MethodGet, origin.URL+"/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip, br")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello" {
		t.Fatalf("got %d %q, want 200 %q", resp.StatusCode, body, "hello")
	}
	// Current behavior: removeBrEncoding prunes "br" before forwarding.
	if echoed := resp.Header.Get("X-Echo-Accept-Encoding"); strings.Contains(echoed, "br") {
		t.Fatalf("Accept-Encoding %q reached origin; current proxy prunes br", echoed)
	}
}

// TestCharacterizeHTTPSConnectMITM: HTTPS via CONNECT is MITM'd — the client
// sees a leaf certificate minted by the Proxify CA, and the body round-trips.
func TestCharacterizeHTTPSConnectMITM(t *testing.T) {
	origin := proxytest.NewH1Origin(t, helloHandler())
	proxyURL, caPool, _ := startProxy(t, nil)
	client := proxytest.ProxyClient(t, proxyURL, caPool, false)

	resp, err := client.Get(origin.URL.String() + "/hello")
	if err != nil {
		t.Fatalf("GET https via proxy CONNECT: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello" {
		t.Fatalf("got %d %q, want 200 %q", resp.StatusCode, body, "hello")
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("no TLS state on response")
	}
	issuer := resp.TLS.PeerCertificates[0].Issuer.Organization
	if len(issuer) == 0 || issuer[0] != "Proxify CA" {
		t.Fatalf("leaf issuer organization = %v, want [Proxify CA] (MITM)", issuer)
	}
}

// TestCharacterizeCallbacks: OnRequestCallback mutations reach the origin,
// OnResponseCallback mutations reach the client, and callbacks replace the
// default DSL/logging path without breaking proxying.
func TestCharacterizeCallbacks(t *testing.T) {
	origin := proxytest.NewPlainOrigin(t, helloHandler())
	proxyURL, _, _ := startProxy(t, func(o *Options) {
		o.OnRequestCallback = func(req *http.Request, _ *FlowContext) error {
			req.Header.Set("X-Test", "request")
			return nil
		}
		o.OnResponseCallback = func(resp *http.Response, _ *FlowContext) error {
			resp.Header.Set("X-Test", "response")
			return nil
		}
	})
	client := proxytest.ProxyClient(t, proxyURL, nil, false)

	resp, err := client.Get(origin.URL + "/hello")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("X-Echo-Test"); got != "request" {
		t.Fatalf("origin saw X-Test = %q, want %q (request callback)", got, "request")
	}
	if got := resp.Header.Get("X-Test"); got != "response" {
		t.Fatalf("client saw X-Test = %q, want %q (response callback)", got, "response")
	}
}

// TestCharacterizeFlowContextSharedAcrossCallbacks: the *FlowContext handed to
// the request callback is the SAME pointer handed to the response callback, so
// a value set on the request side is readable on the response side. This is the
// engine-neutral replacement for the old shared *martian.Context (plan P2).
func TestCharacterizeFlowContextSharedAcrossCallbacks(t *testing.T) {
	origin := proxytest.NewPlainOrigin(t, helloHandler())
	proxyURL, _, _ := startProxy(t, func(o *Options) {
		o.OnRequestCallback = func(req *http.Request, ctx *FlowContext) error {
			ctx.Set("callback-value", "seen")
			return nil
		}
		o.OnResponseCallback = func(resp *http.Response, ctx *FlowContext) error {
			if v, ok := ctx.Get("callback-value"); ok {
				resp.Header.Set("X-Flow-Shared", fmt.Sprint(v))
			}
			return nil
		}
	})
	client := proxytest.ProxyClient(t, proxyURL, nil, false)

	resp, err := client.Get(origin.URL + "/hello")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("X-Flow-Shared"); got != "seen" {
		t.Fatalf("response callback read shared value %q, want %q (same FlowContext pointer)", got, "seen")
	}
}

// TestCharacterizeFlowContextDistinctIDs: separate transactions receive
// distinct, non-empty flow IDs.
func TestCharacterizeFlowContextDistinctIDs(t *testing.T) {
	origin := proxytest.NewPlainOrigin(t, helloHandler())
	var mu sync.Mutex
	var ids []string
	proxyURL, _, _ := startProxy(t, func(o *Options) {
		o.OnRequestCallback = func(req *http.Request, ctx *FlowContext) error {
			mu.Lock()
			ids = append(ids, ctx.ID())
			mu.Unlock()
			return nil
		}
	})
	client := proxytest.ProxyClient(t, proxyURL, nil, false)

	for i := 0; i < 2; i++ {
		resp, err := client.Get(origin.URL + "/hello")
		if err != nil {
			t.Fatalf("GET #%d via proxy: %v", i, err)
		}
		_ = resp.Body.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	if len(ids) != 2 {
		t.Fatalf("captured %d flow ids, want 2", len(ids))
	}
	if ids[0] == "" || ids[1] == "" {
		t.Fatalf("flow ids must be non-empty, got %q and %q", ids[0], ids[1])
	}
	if ids[0] == ids[1] {
		t.Fatalf("flow ids not distinct across requests: both %q", ids[0])
	}
}

// TestCharacterizeCacert: GET http://proxify/cacert through the proxy is
// hijacked and served locally; the PEM body parses to exactly the CA
// currently on disk in the config directory.
func TestCharacterizeCacert(t *testing.T) {
	proxyURL, _, configDir := startProxy(t, nil)
	client := proxytest.ProxyClient(t, proxyURL, nil, false)

	resp, err := client.Get("http://proxify/cacert")
	if err != nil {
		t.Fatalf("GET /cacert via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Disposition"); !strings.Contains(got, "proxify.pem") {
		t.Fatalf("Content-Disposition = %q, want attachment proxify.pem", got)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /cacert body: %v", err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatal("/cacert body is not PEM")
	}
	served, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("/cacert DER does not parse: %v", err)
	}

	onDisk, err := os.ReadFile(filepath.Join(configDir, "cacert.pem"))
	if err != nil {
		t.Fatalf("read on-disk CA: %v", err)
	}
	diskBlock, _ := pem.Decode(onDisk)
	if diskBlock == nil {
		t.Fatal("on-disk cacert.pem is not PEM")
	}
	diskCert, err := x509.ParseCertificate(diskBlock.Bytes)
	if err != nil {
		t.Fatalf("on-disk CA does not parse: %v", err)
	}
	if !served.Equal(diskCert) {
		t.Fatal("/cacert served a different certificate than cacert.pem on disk")
	}
}

// TestCharacterizePassthrough: hosts matching PassThrough regexes are
// tunneled opaquely — the client sees the ORIGIN's certificate and can
// negotiate h2 end to end — while other hosts remain MITM'd.
func TestCharacterizePassthrough(t *testing.T) {
	passOrigin := proxytest.NewH2Origin(t, helloHandler())
	mitmOrigin := proxytest.NewH1Origin(t, helloHandler())
	proxyURL, caPool, _ := startProxy(t, func(o *Options) {
		// Match only the passthrough origin's exact host:port.
		o.PassThrough = []string{strings.ReplaceAll(passOrigin.Host, ".", `\.`) + "$"}
	})

	// Passthrough: trust the ORIGIN CA, offer h2. The tunnel must carry the
	// client's ALPN opaquely, so h2 succeeds and the leaf is the origin's.
	passClient := proxytest.ProxyClient(t, proxyURL, passOrigin.CA.Pool(), true)
	resp, err := passClient.Get(passOrigin.URL.String() + "/hello")
	if err != nil {
		t.Fatalf("GET passthrough origin via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello" {
		t.Fatalf("got %d %q, want 200 hello", resp.StatusCode, body)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("passthrough negotiated %s, want HTTP/2.0 (opaque ALPN)", resp.Proto)
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("no TLS state on passthrough response")
	}
	org := resp.TLS.PeerCertificates[0].Issuer.Organization
	if len(org) == 0 || org[0] != "Proxytest CA" {
		t.Fatalf("passthrough leaf issuer = %v, want origin's [Proxytest CA]", org)
	}

	// Control: a non-matching host on the same proxy is still MITM'd.
	mitmClient := proxytest.ProxyClient(t, proxyURL, caPool, false)
	resp2, err := mitmClient.Get(mitmOrigin.URL.String() + "/hello")
	if err != nil {
		t.Fatalf("GET mitm origin via proxy: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.TLS == nil || len(resp2.TLS.PeerCertificates) == 0 {
		t.Fatal("no TLS state on non-passthrough response")
	}
	org2 := resp2.TLS.PeerCertificates[0].Issuer.Organization
	if len(org2) == 0 || org2[0] != "Proxify CA" {
		t.Fatalf("non-passthrough leaf issuer = %v, want [Proxify CA]", org2)
	}
}

// TestCharacterizeStopIsNoOp documents that Proxy.Stop currently does
// nothing: listeners keep serving after Stop returns. Recorded as a SKIP so
// the no-op is NOT encoded as desired behavior.
func TestCharacterizeStopIsNoOp(t *testing.T) {
	t.Skip("TODO(migration P16): Proxy.Stop is a no-op today — listeners keep serving " +
		"after Stop and resources leak until process exit. Deliberately skipped instead " +
		"of asserted: graceful shutdown lands in plan step P16, which must replace this " +
		"skip with a real stop-then-refuse-connections assertion.")
}
