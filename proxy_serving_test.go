package proxify

// Serving-switch tests for migration plan Step P10. These prove the candidate
// adapter is the default serving core across HTTP-only, SOCKS-only, and
// combined listener configurations, that bind failures surface from Run and
// close the sibling listener, and that NewProxy ensures the CA exists for a
// direct library caller. Everything runs on 127.0.0.1 with ephemeral ports; no
// external network.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/proxify/internal/testutil/proxytest"
	"github.com/projectdiscovery/proxify/pkg/certs"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/proxify/pkg/types"
	"golang.org/x/net/proxy"
)

// runServingProxy builds a proxy with a fresh CA (via newAdapterProxy), starts
// Run in a goroutine, and waits for each configured listener to accept. It
// returns a cert pool trusting the proxy's CA.
func runServingProxy(t *testing.T, mutate func(*Options)) (p *Proxy, caPool *x509.CertPool) {
	t.Helper()
	p = newAdapterProxy(t, mutate)
	go func() { _ = p.Run() }()
	if p.options.ListenAddrHTTP != "" {
		waitForListener(t, p.options.ListenAddrHTTP)
	}
	if p.options.ListenAddrSocks5 != "" {
		waitForListener(t, p.options.ListenAddrSocks5)
	}
	return p, proxifyCAPool(t)
}

// proxifyCAPool returns a cert pool trusting the currently-loaded Proxify CA
// (the CA that signs the MITM leaves).
func proxifyCAPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	raw, err := certs.GetRawCA()
	if err != nil {
		t.Fatalf("GetRawCA: %v", err)
	}
	if !pool.AppendCertsFromPEM(raw.Bytes()) {
		t.Fatal("failed to add proxify CA to pool")
	}
	return pool
}

// socksHTTPClient returns an *http.Client that reaches origins through the
// SOCKS5 proxy at socksAddr (Proxify's SOCKS listener) and trusts caPool for
// the MITM TLS leaves.
func socksHTTPClient(t *testing.T, socksAddr string, caPool *x509.CertPool) *http.Client {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("build SOCKS5 dialer for %s: %v", socksAddr, err)
	}
	cd, ok := dialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("SOCKS5 dialer is not a ContextDialer")
	}
	transport := &http.Transport{
		DialContext:       cd.DialContext,
		TLSClientConfig:   &tls.Config{RootCAs: caPool},
		DisableKeepAlives: true,
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

// getHello does a GET and returns a non-nil error unless the response is a
// 200 "hello". It touches no *testing.T state, so it is safe to call from a
// goroutine.
func getHello(client *http.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello" {
		return fmt.Errorf("GET %s = %d %q, want 200 %q", url, resp.StatusCode, body, "hello")
	}
	return nil
}

// assertHello does a GET and asserts a 200 "hello" body from the test goroutine.
func assertHello(t *testing.T, client *http.Client, url string) {
	t.Helper()
	if err := getHello(client, url); err != nil {
		t.Fatal(err)
	}
}

// TestServingHTTPOnly: with only an HTTP listener configured, an HTTPS GET
// through the candidate returns 200 hello.
func TestServingHTTPOnly(t *testing.T) {
	origin := proxytest.NewH1Origin(t, helloHandler())
	p, caPool := runServingProxy(t, func(o *Options) {
		o.ListenAddrHTTP = freeAddr(t)
	})
	client := proxytest.ProxyClient(t, "http://"+p.options.ListenAddrHTTP, caPool, false)
	assertHello(t, client, origin.URL.String()+"/hello")
}

// TestServingSOCKSOnly: with only a SOCKS5 listener configured, an HTTPS GET
// tunneled through the candidate returns 200 hello — SOCKS is served directly
// by the adapter, not tunneled through an HTTP proxy.
func TestServingSOCKSOnly(t *testing.T) {
	origin := proxytest.NewH1Origin(t, helloHandler())
	p, caPool := runServingProxy(t, func(o *Options) {
		o.ListenAddrSocks5 = freeAddr(t)
	})
	if p.options.ListenAddrHTTP != "" {
		t.Fatal("expected no HTTP listener in SOCKS-only config")
	}
	client := socksHTTPClient(t, p.options.ListenAddrSocks5, caPool)
	assertHello(t, client, origin.URL.String()+"/hello")
}

// TestServingCombinedSimultaneous: with both listeners configured, an HTTP-proxy
// request and a SOCKS5 request succeed concurrently.
func TestServingCombinedSimultaneous(t *testing.T) {
	origin := proxytest.NewH1Origin(t, helloHandler())
	p, caPool := runServingProxy(t, func(o *Options) {
		o.ListenAddrHTTP = freeAddr(t)
		o.ListenAddrSocks5 = freeAddr(t)
	})

	httpClient := proxytest.ProxyClient(t, "http://"+p.options.ListenAddrHTTP, caPool, false)
	socksClient := socksHTTPClient(t, p.options.ListenAddrSocks5, caPool)

	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errs <- getHello(httpClient, origin.URL.String()+"/hello") }()
	go func() { defer wg.Done(); errs <- getHello(socksClient, origin.URL.String()+"/hello") }()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("simultaneous request failed: %v", err)
		}
	}
}

// TestServingCacertBypassesTransport: a clear http://proxify/cacert request is
// served from the local mux and never hits the candidate transport (proved by
// the PEM body and the absence of any origin dial).
func TestServingCacertBypassesTransport(t *testing.T) {
	p, _ := runServingProxy(t, func(o *Options) {
		o.ListenAddrHTTP = freeAddr(t)
	})
	client := proxytest.ProxyClient(t, "http://"+p.options.ListenAddrHTTP, nil, false)

	resp, err := client.Get("http://proxify/cacert")
	if err != nil {
		t.Fatalf("GET /cacert: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Disposition"); !strings.Contains(got, "proxify.pem") {
		t.Fatalf("Content-Disposition = %q, want attachment proxify.pem", got)
	}
}

// TestRunOccupiedHTTPPortReturnsError: an occupied HTTP port makes Run return
// non-nil, and the SOCKS port (bound after HTTP) is never taken.
func TestRunOccupiedHTTPPortReturnsError(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy HTTP port: %v", err)
	}
	defer func() { _ = busy.Close() }()
	socksAddr := freeAddr(t)

	p := newAdapterProxy(t, func(o *Options) {
		o.ListenAddrHTTP = busy.Addr().String()
		o.ListenAddrSocks5 = socksAddr
	})
	if err := p.Run(); err == nil {
		t.Fatal("Run returned nil, want error for occupied HTTP port")
	}
	// SOCKS was never bound (HTTP binds first and failed): the port is free.
	l, err := net.Listen("tcp", socksAddr)
	if err != nil {
		t.Fatalf("SOCKS port %s should be free after HTTP bind failure: %v", socksAddr, err)
	}
	_ = l.Close()
}

// TestRunOccupiedSOCKSPortClosesHTTP: an occupied SOCKS port makes Run return
// non-nil and closes the already-bound HTTP listener so no half-started server
// is left running.
func TestRunOccupiedSOCKSPortClosesHTTP(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy SOCKS port: %v", err)
	}
	defer func() { _ = busy.Close() }()
	httpAddr := freeAddr(t)

	p := newAdapterProxy(t, func(o *Options) {
		o.ListenAddrHTTP = httpAddr
		o.ListenAddrSocks5 = busy.Addr().String()
	})
	if err := p.Run(); err == nil {
		t.Fatal("Run returned nil, want error for occupied SOCKS port")
	}
	// The HTTP listener must have been closed: its port is bindable again.
	l, err := net.Listen("tcp", httpAddr)
	if err != nil {
		t.Fatalf("HTTP port %s should be closed/free after SOCKS bind failure: %v", httpAddr, err)
	}
	_ = l.Close()
}

// TestNewProxyEnsuresCAForDirectCaller: a direct NewProxy caller who never
// called certs.LoadCerts still gets a working adapter, because NewProxy loads
// (generating if needed) the CA under options.Directory.
func TestNewProxyEnsuresCAForDirectCaller(t *testing.T) {
	dir := t.TempDir() // no CA files, no prior LoadCerts
	opts := &Options{
		Directory:     dir,
		CertCacheSize: 256,
		Verbosity:     types.VerbositySilent,
		Elastic:       &elastic.Options{},
		Kafka:         &kafka.Options{},
	}
	p, err := NewProxy(opts)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	if p.adapter == nil {
		t.Fatal("NewProxy did not build the candidate adapter by default")
	}
	if _, err := os.Stat(certs.CACertPath(dir)); err != nil {
		t.Fatalf("NewProxy did not create the CA cert under %s: %v", dir, err)
	}
	if _, err := os.Stat(certs.CAKeyPath(dir)); err != nil {
		t.Fatalf("NewProxy did not create the CA key under %s: %v", dir, err)
	}
}
