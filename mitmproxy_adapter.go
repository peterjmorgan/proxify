package proxify

// Candidate serving adapter for the mitmproxy-go fork (migration plan Step P9).
//
// mitmproxyAdapter wraps the fork's MitmProxyHandler and bridges it to
// Proxify's engine-neutral policy pipeline (interceptHTTP) and logging. It is
// built and exercised directly in P9 while Martian still owns Proxy.Run; P10
// switches serving over to it.
//
// Two request paths flow through the adapter:
//
//   - Intercepted requests/streams (HTTP/1.1 requests and HTTP/2 streams inside
//     a MITM'd tunnel, plus absolute-form clear proxy requests) arrive at the
//     fork's HTTP interceptor. httpInterceptor creates one fresh FlowContext per
//     request/stream — a UUID flow id, the fork's per-connection id, and the
//     TLS-derived secure flag — and delegates to interceptHTTP, whose `next`
//     performs the upstream round trip via the fork's delegated invoker.
//
//   - The CONNECT control channel itself never reaches the HTTP interceptor; it
//     is observed through the fork's connection lifecycle hook. onConnectionEvent
//     creates one CONNECT FlowContext per connection, passes the synthetic
//     CONNECT request and its selected response through Proxify's policy/logging
//     EXACTLY ONCE (request on receive, response on the tunnel status), records
//     the passthrough decision and any terminal error, and drops the flow when
//     the connection closes.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"

	mitmproxy "github.com/peterjmorgan/mitmproxy-go"
	"github.com/projectdiscovery/proxify/pkg/certs"
	"github.com/projectdiscovery/proxify/pkg/util"
)

// defaultCertCacheSize is the leaf-certificate cache capacity used when
// Options.CertCacheSize is unset. It mirrors the runner's -cert-cache-size
// default so a direct library caller and the CLI agree.
const defaultCertCacheSize = 256

// connectPassthroughKey / connectErrorKey are the CONNECT-flow value keys under
// which the lifecycle hook records the passthrough decision and any terminal
// error for the connection's control channel.
const (
	connectPassthroughKey = "connect-passthrough"
	connectErrorKey       = "connect-error"
)

// mitmproxyAdapter is Proxify's candidate serving core: the fork handler plus
// the Proxy it applies policy through and the per-connection CONNECT flow map.
type mitmproxyAdapter struct {
	handler   mitmproxy.MitmProxyHandler
	proxy     *Proxy
	transport http.RoundTripper

	// connectFlows holds the *FlowContext for each connection's CONNECT control
	// channel, keyed by the fork's connection id. It is populated on
	// ConnectReceived and deleted on ConnectionClosed.
	connectFlows sync.Map
}

// newMitmproxyAdapter builds the candidate handler for p, wiring the fork to
// Proxify's transport (rt), cert files, passthrough policy, and interceptor.
//
// The CA cert/key files must already exist under p.options.Directory; a direct
// library caller is responsible for loading them (P10's NewProxy calls
// certs.LoadCerts). We check up front and return a descriptive error rather
// than letting the fork fail opaquely at the first TLS handshake.
//
// HTTP/2 is intentionally left at the fork default (enabled): semantic H2 is the
// primary migration outcome, and the fork exposes only WithDisableHTTP2, so we
// pass no HTTP/2 option at all.
func newMitmproxyAdapter(p *Proxy, rt http.RoundTripper) (*mitmproxyAdapter, error) {
	certPath := certs.CACertPath(p.options.Directory)
	keyPath := certs.CAKeyPath(p.options.Directory)
	if _, err := os.Stat(certPath); err != nil {
		return nil, fmt.Errorf("mitmproxy adapter: CA certificate not found at %s: %w", certPath, err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return nil, fmt.Errorf("mitmproxy adapter: CA private key not found at %s: %w", keyPath, err)
	}

	a := &mitmproxyAdapter{proxy: p, transport: rt}

	handler, err := mitmproxy.NewMitmProxyHandler(
		mitmproxy.WithCACertPath(certPath),
		mitmproxy.WithCAKeyPath(keyPath),
		// Exact requested capacity, no rounding; background interval/expiry keep
		// the fork defaults.
		mitmproxy.WithCertCachePool(cacheCapacity(p.options.CertCacheSize), 0, 0),
		// Route every outbound dial through fastdialer (allow/deny/DNS policy).
		mitmproxy.WithContextDialer(&fastdialerForward{dialer: p.Dialer}),
		// Authoritative passthrough predicate over the full host:port.
		mitmproxy.WithPassthroughFunc(a.shouldPassthrough),
		// Terminate intercepted TLS locally; the injected transport dials origin.
		mitmproxy.WithLazyUpstreamMITM(),
		mitmproxy.WithRoundTripper(rt),
		mitmproxy.WithHTTPInterceptor(a.httpInterceptor),
		mitmproxy.WithConnectionLifecycleHook(a.onConnectionEvent),
	)
	if err != nil {
		return nil, fmt.Errorf("mitmproxy adapter: build handler: %w", err)
	}
	a.handler = handler
	return a, nil
}

// cacheCapacity resolves the configured leaf-cache capacity, honoring the
// requested size exactly and falling back to the default only when unset.
func cacheCapacity(size int) int {
	if size <= 0 {
		return defaultCertCacheSize
	}
	return size
}

// shouldPassthrough is the fork's authoritative passthrough predicate. It runs
// Proxify's PassThrough regexes against the full host:port so patterns that
// pin a port (e.g. `.*\.opaque\.test:443`) match as written.
func (a *mitmproxyAdapter) shouldPassthrough(hostport string) bool {
	return util.MatchAnyRegex(a.proxy.options.PassThrough, hostport)
}

// httpInterceptor is the fork's HTTP interceptor. It establishes one fresh
// FlowContext per intercepted request/stream (a UUID flow id, the shared
// per-connection id, and the TLS-derived secure flag) and runs Proxify's
// unified policy pipeline, performing the upstream round trip through the
// fork's delegated invoker.
func (a *mitmproxyAdapter) httpInterceptor(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
	connID, _ := mitmproxy.ConnectionIDFromContext(ctx)
	// Empty flow id lets newFlowContext mint a fresh UUID, so every
	// request/stream on a shared connection gets a distinct flow id.
	flow := newFlowContext("", connID, isSecureRequest(req))
	next := func(r *http.Request) (*http.Response, error) {
		return invoker.Invoke(r)
	}
	return a.proxy.interceptHTTP(ctx, flow, req, next)
}

// onConnectionEvent observes the fork's per-connection lifecycle. The CONNECT
// control channel never reaches httpInterceptor, so it is logged/callback'd
// here: a synthetic CONNECT request on receive and its selected response on the
// tunnel status, each exactly once. The fork does not carry a request object on
// CONNECT events (it sets ConnectionEvent.Request to nil for CONNECT), so the
// adapter fabricates one from the event host:port. Passthrough and
// terminal-error signals are recorded on the CONNECT flow; the flow is dropped
// on close.
func (a *mitmproxyAdapter) onConnectionEvent(_ context.Context, ev mitmproxy.ConnectionEvent) {
	switch ev.Kind {
	case mitmproxy.ConnectReceived:
		// CONNECT is the plaintext control channel, so secure is false; the
		// inner intercepted requests carry their own secure flow.
		flow := newFlowContext("", ev.ConnectionID, false)
		a.connectFlows.Store(ev.ConnectionID, flow)
		_ = a.proxy.modifyRequest(syntheticConnectRequest(ev.Hostport), flow)
	case mitmproxy.ConnectResponse:
		if flow, ok := a.loadConnectFlow(ev.ConnectionID); ok {
			resp := syntheticConnectResponse(ev.StatusCode, syntheticConnectRequest(ev.Hostport))
			_ = a.proxy.modifyResponse(resp, flow)
		}
	case mitmproxy.PassthroughDecided:
		if flow, ok := a.loadConnectFlow(ev.ConnectionID); ok {
			flow.Set(connectPassthroughKey, ev.Passthrough)
		}
	case mitmproxy.TerminalError:
		if flow, ok := a.loadConnectFlow(ev.ConnectionID); ok {
			flow.Set(connectErrorKey, ev.Err)
		}
	case mitmproxy.ConnectionClosed:
		a.connectFlows.Delete(ev.ConnectionID)
	}
}

// loadConnectFlow returns the CONNECT FlowContext stored for connID, if any.
func (a *mitmproxyAdapter) loadConnectFlow(connID string) (*FlowContext, bool) {
	v, ok := a.connectFlows.Load(connID)
	if !ok {
		return nil, false
	}
	flow, ok := v.(*FlowContext)
	return flow, ok
}

// ServeHTTP serves a clear proxy request (absolute-form or CONNECT) through the
// fork handler.
func (a *mitmproxyAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.handler.ServeHTTP(w, r)
}

// ServeSOCKS5 serves an accepted SOCKS5 connection through the fork handler,
// which takes ownership of conn and closes it.
func (a *mitmproxyAdapter) ServeSOCKS5(ctx context.Context, conn net.Conn) error {
	return a.handler.ServeSOCKS5(ctx, conn)
}

// Cleanup releases the fork handler's active connections and closes idle
// connections on the owned upstream transport.
func (a *mitmproxyAdapter) Cleanup() {
	a.handler.Cleanup()
	closeIdleRoundTripper(a.transport)
}

// isSecureRequest reports whether an intercepted request rode a TLS-terminated
// connection. It mirrors the fork's own secure-scheme test: a set req.TLS, or
// an https/wss URL scheme the fork assigns after terminating TLS.
func isSecureRequest(req *http.Request) bool {
	if req.TLS != nil {
		return true
	}
	if req.URL == nil {
		return false
	}
	switch req.URL.Scheme {
	case "https", "wss":
		return true
	default:
		return false
	}
}

// syntheticConnectRequest fabricates the CONNECT request Proxify's request
// policy logs for a tunnel. The fork does not surface a request object on
// CONNECT lifecycle events, so the adapter builds one from the target
// host:port with a non-nil header and no body.
func syntheticConnectRequest(hostport string) *http.Request {
	return &http.Request{
		Method:     http.MethodConnect,
		Host:       hostport,
		URL:        &url.URL{Host: hostport},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
}

// syntheticConnectResponse builds the *http.Response Proxify's response policy
// logs for a CONNECT tunnel: the status the fork selected (200 established, or
// 502 on upstream dial failure), a non-nil header and body, and the CONNECT
// request as its Request so response policy sees accurate linkage.
func syntheticConnectResponse(statusCode int, req *http.Request) *http.Response {
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	return &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}
}
