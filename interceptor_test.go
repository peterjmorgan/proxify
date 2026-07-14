package proxify

// Unit tests for the protocol-neutral unified interceptor (migration plan
// Step P4). These exercise interceptHTTP directly with a synthetic transport
// (delegatedRoundTripper) so the request-callback -> transport ->
// response-callback ordering, the proxy-local short circuit, response repair,
// and match/replace linkage are pinned independently of any serving engine.
// No network is used.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/proxify/pkg/certs"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/proxify/pkg/types"
)

// newInterceptProxy builds a fully wired Proxy (logger + local mux + options)
// without starting any listener, so interceptHTTP can be driven directly. It
// loads a fresh CA so serveProxyLocal("/cacert") has something to serve.
func newInterceptProxy(t *testing.T, mutate func(*Options)) *Proxy {
	t.Helper()

	if err := certs.LoadCerts(t.TempDir()); err != nil {
		t.Fatalf("LoadCerts: %v", err)
	}
	opts := &Options{
		Directory:     t.TempDir(),
		CertCacheSize: 256,
		Verbosity:     types.VerbositySilent,
		// No OutputDirectory: the async file writer then writes nothing, so
		// there is no on-disk log racing this fast test's TempDir cleanup.
		// The logging path (snapshotting) still runs.
		// The logger dereferences these unconditionally; mirror the runner.
		Elastic: &elastic.Options{},
		Kafka:   &kafka.Options{},
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

// okResponse returns a minimal, fully-formed 200 response linked to req, built
// via a recorder so DumpResponse/ReadResponse round-trips (match-replace) work.
func okResponse(req *http.Request, body string) *http.Response {
	rec := httptest.NewRecorder()
	_, _ = io.WriteString(rec, body)
	resp := rec.Result()
	resp.Request = req
	return resp
}

// TestInterceptHTTPOrdering: request callback, transport, and response callback
// fire in exactly that order for a normal (non-proxy-local) flow.
func TestInterceptHTTPOrdering(t *testing.T) {
	var mu sync.Mutex
	var order []string
	mark := func(s string) {
		mu.Lock()
		order = append(order, s)
		mu.Unlock()
	}

	p := newInterceptProxy(t, func(o *Options) {
		o.OnRequestCallback = func(_ *http.Request, _ *FlowContext) error {
			mark("request-callback")
			return nil
		}
		o.OnResponseCallback = func(_ *http.Response, _ *FlowContext) error {
			mark("response-callback")
			return nil
		}
	})

	req := httptest.NewRequest(http.MethodGet, "http://origin.test/hello", nil)
	flow := newFlowContext("flow-1", "conn-1", false)
	next := func(r *http.Request) (*http.Response, error) {
		mark("transport")
		return okResponse(r, "hello"), nil
	}

	resp, err := p.interceptHTTP(context.Background(), flow, req, next)
	if err != nil {
		t.Fatalf("interceptHTTP: %v", err)
	}
	_ = resp.Body.Close()

	want := []string{"request-callback", "transport", "response-callback"}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("marker order = %v, want %v", order, want)
	}
}

// TestInterceptHTTPProxyLocalShortCircuit: a synthetic proxify host is served
// from the local mux, the transport is never invoked, and response.Request is
// the effective request.
func TestInterceptHTTPProxyLocalShortCircuit(t *testing.T) {
	p := newInterceptProxy(t, nil)

	req := httptest.NewRequest(http.MethodGet, "http://proxify/cacert", nil)
	req.Host = "proxify"
	flow := newFlowContext("flow-1", "conn-1", false)

	var transportCalled bool
	next := func(r *http.Request) (*http.Response, error) {
		transportCalled = true
		return okResponse(r, "should-not-happen"), nil
	}

	resp, err := p.interceptHTTP(context.Background(), flow, req, next)
	if err != nil {
		t.Fatalf("interceptHTTP: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if transportCalled {
		t.Fatal("transport was invoked for a proxy-local host; must be short-circuited")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Request != req {
		t.Fatal("response.Request is not the effective request")
	}
	if got := resp.Header.Get("Content-Disposition"); !strings.Contains(got, "proxify.pem") {
		t.Fatalf("Content-Disposition = %q, want attachment proxify.pem", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Fatalf("/cacert body is not a PEM certificate: %q", body)
	}
}

// TestInterceptHTTPRepairsNilRequestAndBody: a transport response with a nil
// Body and nil Request is repaired — the body becomes non-nil and Request is
// set to the effective request — before response policy runs.
func TestInterceptHTTPRepairsNilRequestAndBody(t *testing.T) {
	p := newInterceptProxy(t, nil)

	req := httptest.NewRequest(http.MethodGet, "http://origin.test/hello", nil)
	flow := newFlowContext("flow-1", "conn-1", false)
	next := func(_ *http.Request) (*http.Response, error) {
		// Deliberately return a bare response: nil Body, nil Request.
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
		}, nil
	}

	resp, err := p.interceptHTTP(context.Background(), flow, req, next)
	if err != nil {
		t.Fatalf("interceptHTTP: %v", err)
	}
	if resp.Body == nil {
		t.Fatal("response body was left nil; interceptor must repair it")
	}
	_ = resp.Body.Close()
	if resp.Request != req {
		t.Fatal("response.Request was not set to the effective request")
	}
}

// TestInterceptHTTPMatchReplace: request and response match-replace DSL mutate
// `old` to `new` on their respective streams, and the response stays linked to
// the effective request.
func TestInterceptHTTPMatchReplace(t *testing.T) {
	p := newInterceptProxy(t, func(o *Options) {
		o.RequestMatchReplaceDSL = []string{"replace(request,'oldreq','newreq')"}
		o.ResponseMatchReplaceDSL = []string{"replace(response,'oldresp','newresp')"}
	})

	req := httptest.NewRequest(http.MethodGet, "http://origin.test/submit", nil)
	req.Header.Set("User-Agent", "oldreq-agent")
	flow := newFlowContext("flow-1", "conn-1", false)

	var forwarded string
	next := func(r *http.Request) (*http.Response, error) {
		forwarded = r.Header.Get("User-Agent")
		return okResponse(r, "oldresp-body"), nil
	}

	resp, err := p.interceptHTTP(context.Background(), flow, req, next)
	if err != nil {
		t.Fatalf("interceptHTTP: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if !strings.Contains(forwarded, "newreq") || strings.Contains(forwarded, "oldreq") {
		t.Fatalf("forwarded request User-Agent = %q, want it to contain newreq and not oldreq", forwarded)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "newresp") || strings.Contains(string(body), "oldresp") {
		t.Fatalf("response body = %q, want it to contain newresp and not oldresp", body)
	}
	if resp.Request != req {
		t.Fatal("response.Request linkage lost across match-replace")
	}
}
