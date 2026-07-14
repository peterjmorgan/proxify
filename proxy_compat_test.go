package proxify

// Policy-compatibility E2E tests for migration plan Step P11. These drive the
// candidate serving core (Proxy.Run over a real loopback listener) and lock
// down Proxify's *default* (non-callback) policy path — request/response DSL
// matching, request/response match-replace, the logger's on-disk export, and
// CONNECT visibility — plus the callback flow-identity contract and regex
// passthrough. They complement the characterization tests in proxy_test.go
// (callbacks, /cacert, MITM cert) rather than duplicating them.
//
// Everything binds 127.0.0.1:0 and synchronizes on bounded polls/channels; the
// async file logger writes after the client sees the response and Proxy.Stop is
// a no-op until P16, so on-disk assertions poll with a deadline instead of
// sleeping a fixed interval.

import (
	"crypto/x509"
	"io"
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

// startCompatProxy starts a full serving proxy (Proxy.Run) over an ephemeral
// HTTP listener with an on-disk log directory, so tests can assert Proxify's
// default policy path end to end: DSL match export, match/replace, and the
// logger's on-disk transaction files. It returns the proxy URL, a pool trusting
// the Proxify MITM CA, and the log output directory.
//
// It mirrors startProxy's CA/temp-dir plumbing but additionally exposes the log
// output directory (startProxy discards it); the log root is removed with
// retries because a late async write must not fail the test.
func startCompatProxy(t *testing.T, mutate func(*Options)) (proxyURL string, caPool *x509.CertPool, outputDir string) {
	t.Helper()

	configDir := t.TempDir()

	outputRoot, err := os.MkdirTemp("", "proxify-compat-logs-*")
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
	outputDir = filepath.Join(outputRoot, "logs")

	if err := certs.LoadCerts(configDir); err != nil {
		t.Fatalf("LoadCerts(%q): %v", configDir, err)
	}

	opts := &Options{
		Directory:       configDir,
		OutputDirectory: outputDir,
		CertCacheSize:   256,
		Verbosity:       types.VerbositySilent,
		ListenAddrHTTP:  freeAddr(t),
		Elastic:         &elastic.Options{},
		Kafka:           &kafka.Options{},
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

	return "http://" + opts.ListenAddrHTTP, proxifyCAPool(t), outputDir
}

// readLogFiles returns a best-effort snapshot of the logger's on-disk export:
// each regular file in outputDir mapped from base name to content. Errors are
// swallowed because the async writer may be mid-write; callers poll.
func readLogFiles(outputDir string) map[string]string {
	out := map[string]string{}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(outputDir, e.Name()))
		if err != nil {
			continue
		}
		out[e.Name()] = string(b)
	}
	return out
}

// waitForLogs polls the logger's on-disk export until pred is satisfied,
// returning the snapshot that satisfied it. On timeout it fails the test and
// reports what was present, so a missing/extra entry is diagnosable.
func waitForLogs(t *testing.T, outputDir string, pred func(files map[string]string) bool) map[string]string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last map[string]string
	for time.Now().Before(deadline) {
		last = readLogFiles(outputDir)
		if pred(last) {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
	names := make([]string, 0, len(last))
	for n := range last {
		names = append(names, n)
	}
	t.Fatalf("log export never satisfied predicate within timeout; files present: %v", names)
	return nil
}

// countContaining returns how many files' content contains sub.
func countContaining(files map[string]string, sub string) int {
	n := 0
	for _, c := range files {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

// TestCompatDSLMatchExport exercises the default (non-callback) path: a request
// DSL `contains(request, 'needle')` plus a response DSL `status_code == 201`
// mark the transaction as a match, and the logger exports the response to a
// ".match" file. Covered for both a plain-HTTP origin and an HTTPS origin
// reached through CONNECT.
func TestCompatDSLMatchExport(t *testing.T) {
	// Origin answers /needle with 201 (matching both DSLs) and anything else
	// with 200 (matching neither), so a stray request cannot forge a match file.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "needle") {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_, _ = io.WriteString(w, "hello")
	})

	mutate := func(o *Options) {
		o.RequestDSL = []string{"contains(request, 'needle')"}
		o.ResponseDSL = []string{"status_code == 201"}
	}

	t.Run("http", func(t *testing.T) {
		origin := proxytest.NewPlainOrigin(t, handler)
		proxyURL, _, outputDir := startCompatProxy(t, mutate)
		client := proxytest.ProxyClient(t, proxyURL, nil, false)

		resp, err := client.Get(origin.URL + "/needle")
		if err != nil {
			t.Fatalf("GET /needle via proxy: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status = %d, want 201", resp.StatusCode)
		}

		files := waitForLogs(t, outputDir, func(f map[string]string) bool {
			return anyNameHasSuffix(f, ".match.txt")
		})
		if !anyNameHasSuffix(files, ".match.txt") {
			t.Fatalf("no .match export file for a matching transaction; files: %v", names(files))
		}
	})

	t.Run("https", func(t *testing.T) {
		origin := proxytest.NewH1Origin(t, handler)
		proxyURL, caPool, outputDir := startCompatProxy(t, mutate)
		client := proxytest.ProxyClient(t, proxyURL, caPool, false)

		resp, err := client.Get(origin.URL.String() + "/needle")
		if err != nil {
			t.Fatalf("GET https /needle via CONNECT: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status = %d, want 201", resp.StatusCode)
		}

		files := waitForLogs(t, outputDir, func(f map[string]string) bool {
			return anyNameHasSuffix(f, ".match.txt")
		})
		// The CONNECT control channel (200, no 'needle') must not be a match.
		for name, content := range files {
			if strings.HasSuffix(name, ".match.txt") && strings.Contains(content, "CONNECT ") {
				t.Fatalf("CONNECT transaction wrongly exported as a match: %s", name)
			}
		}
	})
}

// TestCompatMatchReplace exercises the default path's request and response
// match-replace over an HTTPS (MITM) flow: the request header `X-Old: old` is
// rewritten to `X-Old: new` before the origin sees it, and the response body
// `old` is rewritten to `new` before the client sees it.
func TestCompatMatchReplace(t *testing.T) {
	// Origin echoes the received X-Old into a response header and returns the
	// body "old"; both the mutated request header and the mutated response body
	// are then observable from the client side.
	origin := proxytest.NewH1Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Recv-Old", r.Header.Get("X-Old"))
		_, _ = io.WriteString(w, "old")
	}))

	proxyURL, caPool, _ := startCompatProxy(t, func(o *Options) {
		o.RequestMatchReplaceDSL = []string{"replace(request, 'X-Old: old', 'X-Old: new')"}
		o.ResponseMatchReplaceDSL = []string{"replace(response, 'old', 'new')"}
	})
	client := proxytest.ProxyClient(t, proxyURL, caPool, false)

	req, err := http.NewRequest(http.MethodGet, origin.URL.String()+"/mr", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Old", "old")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("X-Recv-Old"); got != "new" {
		t.Fatalf("origin received X-Old = %q, want %q (request match-replace)", got, "new")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "new" {
		t.Fatalf("client body = %q, want %q (response match-replace)", body, "new")
	}
}

// TestCompatConnectVisibleInLoggerExport exercises the default path: a single
// HTTPS GET produces exactly one CONNECT log entry (method CONNECT, status 200)
// and a separate inner GET entry, proving the CONNECT control channel is
// observable in the export without being duplicated.
func TestCompatConnectVisibleInLoggerExport(t *testing.T) {
	origin := proxytest.NewH1Origin(t, helloHandler())
	proxyURL, caPool, outputDir := startCompatProxy(t, nil)
	client := proxytest.ProxyClient(t, proxyURL, caPool, false)

	resp, err := client.Get(origin.URL.String() + "/hello")
	if err != nil {
		t.Fatalf("GET https via CONNECT: %v", err)
	}
	_ = resp.Body.Close()

	files := waitForLogs(t, outputDir, func(f map[string]string) bool {
		return countContaining(f, "CONNECT ") == 1 && countContaining(f, "GET ") >= 1
	})
	if got := countContaining(files, "CONNECT "); got != 1 {
		t.Fatalf("CONNECT log entries = %d, want exactly 1 (files: %v)", got, names(files))
	}
	// The one CONNECT entry must carry its 200 established status.
	for _, content := range files {
		if strings.Contains(content, "CONNECT ") && !strings.Contains(content, "200") {
			t.Fatalf("CONNECT log entry missing 200 status:\n%s", content)
		}
	}
}

// TestCompatConnectAndInnerFlowIDs asserts the flow-identity contract: the
// CONNECT control channel and the inner request each get their own flow id
// while sharing the connection's id.
func TestCompatConnectAndInnerFlowIDs(t *testing.T) {
	origin := proxytest.NewH1Origin(t, helloHandler())

	type rec struct{ method, flowID, connID string }
	var mu sync.Mutex
	var recs []rec
	proxyURL, caPool, _ := startCompatProxy(t, func(o *Options) {
		o.OnRequestCallback = func(req *http.Request, ctx *FlowContext) error {
			mu.Lock()
			recs = append(recs, rec{req.Method, ctx.ID(), ctx.ConnectionID()})
			mu.Unlock()
			return nil
		}
	})
	client := proxytest.ProxyClient(t, proxyURL, caPool, false)

	resp, err := client.Get(origin.URL.String() + "/hello")
	if err != nil {
		t.Fatalf("GET https via CONNECT: %v", err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	var connect, inner *rec
	for i := range recs {
		switch recs[i].method {
		case http.MethodConnect:
			connect = &recs[i]
		case http.MethodGet:
			inner = &recs[i]
		}
	}
	if connect == nil || inner == nil {
		t.Fatalf("want one CONNECT and one inner GET callback, got %+v", recs)
	}
	if connect.flowID == "" || inner.flowID == "" {
		t.Fatalf("flow ids must be non-empty: connect=%q inner=%q", connect.flowID, inner.flowID)
	}
	if connect.flowID == inner.flowID {
		t.Fatalf("CONNECT and inner share flow id %q, want distinct", connect.flowID)
	}
	if connect.connID == "" || connect.connID != inner.connID {
		t.Fatalf("connection ids must match and be non-empty: connect=%q inner=%q", connect.connID, inner.connID)
	}
}

// TestCompatStaticRoot verifies the proxify static root is served locally: a
// clear GET http://proxify/ returns the banner page from the static directory
// without touching the candidate transport.
func TestCompatStaticRoot(t *testing.T) {
	proxyURL, _, _ := startCompatProxy(t, nil)
	client := proxytest.ProxyClient(t, proxyURL, nil, false)

	resp, err := client.Get("http://proxify/")
	if err != nil {
		t.Fatalf("GET http://proxify/ via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<title>Proxify</title>") {
		t.Fatalf("static root body missing banner title; got %d bytes", len(body))
	}
}

// TestCompatPassthroughNoInnerInterception verifies a regex passthrough carries
// bytes opaquely: the CONNECT is observed once but the inner HTTPS request is
// NOT intercepted, so no inner callback fires and the client negotiates h2 with
// the origin's own certificate end to end.
func TestCompatPassthroughNoInnerInterception(t *testing.T) {
	passOrigin := proxytest.NewH2Origin(t, helloHandler())

	var mu sync.Mutex
	var methods []string
	proxyURL, _, _ := startCompatProxy(t, func(o *Options) {
		o.PassThrough = []string{strings.ReplaceAll(passOrigin.Host, ".", `\.`) + "$"}
		o.OnRequestCallback = func(req *http.Request, _ *FlowContext) error {
			mu.Lock()
			methods = append(methods, req.Method)
			mu.Unlock()
			return nil
		}
	})

	// Trust the ORIGIN CA and offer h2: an opaque tunnel carries the client's
	// ALPN to the origin, so h2 succeeds and the leaf is the origin's own.
	client := proxytest.ProxyClient(t, proxyURL, passOrigin.CA.Pool(), true)
	resp, err := client.Get(passOrigin.URL.String() + "/hello")
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
	if org := resp.TLS.PeerCertificates[0].Issuer.Organization; len(org) == 0 || org[0] != "Proxytest CA" {
		t.Fatalf("passthrough leaf issuer = %v, want origin's [Proxytest CA]", org)
	}

	mu.Lock()
	defer mu.Unlock()
	connects, inner := 0, 0
	for _, m := range methods {
		if m == http.MethodConnect {
			connects++
		} else {
			inner++
		}
	}
	if connects != 1 {
		t.Fatalf("CONNECT callbacks = %d, want 1 (methods=%v)", connects, methods)
	}
	if inner != 0 {
		t.Fatalf("inner callbacks = %d, want 0 (passthrough is opaque; methods=%v)", inner, methods)
	}
}

// TestCompatPassthroughNoInnerLogEntry is the logger-export counterpart of the
// no-inner-interception contract: on the default path a passthrough tunnel logs
// its CONNECT but produces no inner request/response entry.
func TestCompatPassthroughNoInnerLogEntry(t *testing.T) {
	passOrigin := proxytest.NewH2Origin(t, helloHandler())
	proxyURL, _, outputDir := startCompatProxy(t, func(o *Options) {
		o.PassThrough = []string{strings.ReplaceAll(passOrigin.Host, ".", `\.`) + "$"}
	})

	client := proxytest.ProxyClient(t, proxyURL, passOrigin.CA.Pool(), true)
	resp, err := client.Get(passOrigin.URL.String() + "/hello")
	if err != nil {
		t.Fatalf("GET passthrough origin via proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "hello" {
		t.Fatalf("got %d %q, want 200 hello", resp.StatusCode, body)
	}

	// Wait until the CONNECT entry is exported, then assert no inner GET entry
	// exists — the opaque tunnel never enqueues an inner transaction.
	files := waitForLogs(t, outputDir, func(f map[string]string) bool {
		return countContaining(f, "CONNECT ") == 1
	})
	if got := countContaining(files, "GET /hello"); got != 0 {
		t.Fatalf("inner GET log entries = %d, want 0 (passthrough is opaque; files: %v)", got, names(files))
	}
}

// names returns the sorted-enough set of file names for diagnostics.
func names(files map[string]string) []string {
	out := make([]string, 0, len(files))
	for n := range files {
		out = append(out, n)
	}
	return out
}

// anyNameHasSuffix reports whether any log file name ends with suffix.
func anyNameHasSuffix(files map[string]string, suffix string) bool {
	for n := range files {
		if strings.HasSuffix(n, suffix) {
			return true
		}
	}
	return false
}
