package proxify

// Transport construction for the proxy's upstream RoundTrippers (migration
// plan Step P5+). The direct (no upstream proxy) standard transport is built
// by newStandardTransport so it honors fastdialer policy and HTTP/2; upstream
// HTTP/SOCKS routing is request-based via routedRoundTripper (Step P6); the
// tls-client fingerprinting adapter is relocated here verbatim and reworked in
// Step P7.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/proxify/pkg/tlsprofile"
	errorutil "github.com/projectdiscovery/utils/errors"
	"golang.org/x/net/proxy"
)

// newStandardTransport builds the direct (no upstream proxy) standard
// http.Transport. It preserves proxify's historical pooling and TLS behavior
// (unbounded per-host idle connections, a TLS 1.0 floor, InsecureSkipVerify)
// but, unlike the previous direct branch, routes every dial through fastdialer
// via DialContext and enables HTTP/2.
//
// ForceAttemptHTTP2 is required here: the standard library disables H2 upgrades
// whenever a custom DialContext or TLSClientConfig is set, so without it the
// old direct branch silently spoke HTTP/1.1 only and bypassed fastdialer. Both
// fields are set together to keep direct H2 working while still enforcing
// fastdialer's allow/deny/DNS-mapping policy.
func newStandardTransport(dialer *fastdialer.Dialer) *http.Transport {
	return &http.Transport{
		MaxIdleConnsPerHost: -1,
		MaxIdleConns:        0,
		MaxConnsPerHost:     0,
		ForceAttemptHTTP2:   true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS10,
			InsecureSkipVerify: true,
		},
	}
}

// closeIdleRoundTripper closes idle connections on a RoundTripper when it
// implements the standard { CloseIdleConnections() } interface (as
// http.Transport does). This lets owners release pooled connections during
// teardown without knowing the concrete transport type; RoundTrippers that do
// not support it are a no-op.
func closeIdleRoundTripper(rt http.RoundTripper) {
	if c, ok := rt.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// getRoundTripper returns RoundTripper configured with options
func (p *Proxy) getRoundTripper() (http.RoundTripper, error) {
	// Use TLS fingerprinting if enabled
	if p.options.TLSFingerprint {
		return p.getTLSClientRoundTripper()
	}

	// Fall back to standard transport
	return p.getStandardRoundTripper()
}

// getStandardRoundTripper returns the upstream RoundTripper for non-fingerprint
// mode. Upstream HTTP proxies take precedence over SOCKS5; when either is
// configured a routedRoundTripper selects exactly one route per RoundTrip
// (Step P6). With no upstream proxy it falls back to the direct P5 transport.
func (p *Proxy) getStandardRoundTripper() (http.RoundTripper, error) {
	if len(p.options.UpstreamHTTPProxies) > 0 {
		return p.newRoutedRoundTripper(p.options.UpstreamHTTPProxies, newHTTPProxyTransport)
	}
	if len(p.options.UpstreamSock5Proxies) > 0 {
		return p.newRoutedRoundTripper(p.options.UpstreamSock5Proxies, newSOCKSProxyTransport)
	}
	return newStandardTransport(p.Dialer), nil
}

// routeSelector performs count-based round robin over a fixed list of upstream
// routes. Unlike the previous roundrobin-inside-DialContext design, Next() is
// called exactly once per RoundTrip, so a route stays stable across the retries
// and concurrent dials of a single request. It advances to the next route
// (modulo the route count) only after the current route has been handed out
// rotateEvery times. Safe for concurrent use.
type routeSelector struct {
	mu          sync.Mutex
	routes      []string
	rotateEvery int
	index       int
	used        int
}

// newRouteSelector validates and builds a routeSelector. An empty route list or
// a non-positive rotateEvery is rejected so misconfiguration fails at NewProxy
// time rather than silently at the first request.
func newRouteSelector(routes []string, rotateEvery int) (*routeSelector, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("route selector: empty route list")
	}
	if rotateEvery <= 0 {
		return nil, fmt.Errorf("route selector: rotateEvery must be > 0, got %d", rotateEvery)
	}
	return &routeSelector{
		routes:      append([]string(nil), routes...),
		rotateEvery: rotateEvery,
	}, nil
}

// Next returns the current route, advancing to the next route after rotateEvery
// selections.
func (s *routeSelector) Next() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used >= s.rotateEvery {
		s.index = (s.index + 1) % len(s.routes)
		s.used = 0
	}
	route := s.routes[s.index]
	s.used++
	return route
}

// routedRoundTripper selects one upstream route per RoundTrip (via routeSelector)
// then delegates to that route's fixed http.RoundTripper. Because each route owns
// its own transport, retries and concurrent dials within a single RoundTrip never
// change route.
type routedRoundTripper struct {
	selector   *routeSelector
	transports map[string]http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (rt *routedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	route := rt.selector.Next()
	return rt.transports[route].RoundTrip(req)
}

// CloseIdleConnections releases idle connections on every route transport.
func (rt *routedRoundTripper) CloseIdleConnections() {
	for _, t := range rt.transports {
		closeIdleRoundTripper(t)
	}
}

// newRoutedRoundTripper builds a routedRoundTripper: one fixed transport per
// distinct route (built by build) plus a routeSelector that picks one route per
// RoundTrip. Route order and rotateEvery drive the selection sequence.
func (p *Proxy) newRoutedRoundTripper(routes []string, build func(*fastdialer.Dialer, string) (*http.Transport, error)) (http.RoundTripper, error) {
	return p.newRoutedRoundTripperFunc(routes, func(route string) (http.RoundTripper, error) {
		return build(p.Dialer, route)
	})
}

// newRoutedRoundTripperFunc is the general form of newRoutedRoundTripper: it
// builds one RoundTripper per distinct route via build and selects one route per
// RoundTrip with a P6 routeSelector. The standard transport path (P6) and the
// tls-client fingerprinting path (P7) share it so route rotation is identical in
// both modes.
func (p *Proxy) newRoutedRoundTripperFunc(routes []string, build func(string) (http.RoundTripper, error)) (http.RoundTripper, error) {
	selector, err := newRouteSelector(routes, p.options.UpstreamProxyRequestsNumber)
	if err != nil {
		return nil, err
	}
	transports := make(map[string]http.RoundTripper, len(routes))
	for _, route := range routes {
		if _, ok := transports[route]; ok {
			continue
		}
		rt, err := build(route)
		if err != nil {
			return nil, err
		}
		transports[route] = rt
	}
	return &routedRoundTripper{selector: selector, transports: transports}, nil
}

// newHTTPProxyTransport builds a fixed-route http.Transport that forwards every
// request through proxyURL, dialing the proxy itself through fastdialer. It
// copies P5's direct-transport TLS/H2/pooling settings.
func newHTTPProxyTransport(dialer *fastdialer.Dialer, proxyURL string) (*http.Transport, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("invalid upstream HTTP proxy %q", proxyURL)
	}
	t := newStandardTransport(dialer)
	t.Proxy = http.ProxyURL(u)
	return t, nil
}

// newSOCKSProxyTransport builds a fixed-route http.Transport that tunnels every
// dial through the SOCKS5 proxy at proxyURL. The forward dial to the proxy goes
// through fastdialer, and the SOCKS dial is context-aware so request
// cancellation propagates. It copies P5's TLS/H2/pooling settings.
func newSOCKSProxyTransport(dialer *fastdialer.Dialer, proxyURL string) (*http.Transport, error) {
	socksDialer, err := proxy.SOCKS5("tcp", socksProxyAddress(proxyURL), nil, &fastdialerForward{dialer: dialer})
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("invalid upstream SOCKS5 proxy %q", proxyURL)
	}
	t := newStandardTransport(dialer)
	t.Proxy = nil
	if cd, ok := socksDialer.(proxy.ContextDialer); ok {
		t.DialContext = cd.DialContext
	} else {
		t.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
			return socksDialer.Dial(network, addr)
		}
	}
	return t, nil
}

// socksProxyAddress reduces an upstream SOCKS5 proxy value to the host:port the
// SOCKS dialer needs, tolerating both bare host:port and scheme-qualified
// (socks5://host:port) forms.
func socksProxyAddress(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// fastdialerForward adapts a fastdialer.Dialer to proxy.Dialer/ContextDialer so
// x/net/proxy uses it as the forward dialer when connecting to a SOCKS5 proxy —
// keeping fastdialer's allow/deny/DNS policy on the proxy socket.
type fastdialerForward struct {
	dialer *fastdialer.Dialer
}

// Dial implements proxy.Dialer.
func (f *fastdialerForward) Dial(network, addr string) (net.Conn, error) {
	return f.dialer.Dial(context.Background(), network, addr)
}

// DialContext implements proxy.ContextDialer.
func (f *fastdialerForward) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f.dialer.Dial(ctx, network, addr)
}

// getTLSClientRoundTripper returns a bogdanfinn/tls-client RoundTripper with TLS
// fingerprinting (Step P7). Upstream HTTP proxies take precedence over SOCKS5;
// when either is configured a routedRoundTripper (reusing the P6 routeSelector)
// selects exactly one route per RoundTrip, each route backed by its own
// tls-client HttpClient. With no upstream proxy a single direct client is used.
// Every client dials through fastdialer via WithProxyDialerFactory, so the
// fingerprinted path enforces the same allow/deny/DNS policy as the standard
// transport and honors upstream route rotation (unlike the previous
// first-proxy-only implementation).
func (p *Proxy) getTLSClientRoundTripper() (http.RoundTripper, error) {
	profile, err := tlsprofile.GetProfile(p.options.TLSProfile)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to get TLS profile")
	}
	build := func(route string) (http.RoundTripper, error) {
		return p.newTLSClientRoundTripper(profile, route)
	}
	if len(p.options.UpstreamHTTPProxies) > 0 {
		return p.newRoutedRoundTripperFunc(p.options.UpstreamHTTPProxies, build)
	}
	if len(p.options.UpstreamSock5Proxies) > 0 {
		routes := make([]string, len(p.options.UpstreamSock5Proxies))
		for i, raw := range p.options.UpstreamSock5Proxies {
			routes[i] = ensureSOCKSScheme(raw)
		}
		return p.newRoutedRoundTripperFunc(routes, build)
	}
	return build("")
}

// ensureSOCKSScheme normalizes an upstream SOCKS5 value to a socks5:// URL so
// both tls-client's WithProxyUrl (which requires a scheme) and the proxy dialer
// factory parse it, tolerating bare host:port and already-schemed forms.
func ensureSOCKSScheme(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" {
		return raw
	}
	return "socks5://" + raw
}

// newTLSClientRoundTripper builds one tls-client HttpClient for a single route
// (an empty route means direct) and wraps it as an http.RoundTripper.
//
// One client per route, selected once per RoundTrip, needs no client pool or
// global request mutex: tls-client's Do is safe for concurrent use. The only
// shared mutable state it touches per call is the header-order key, guarded by
// an internal lock that is released before the underlying (net/http-style)
// RoundTrip runs, so concurrent H2 streams on one client are never serialized.
func (p *Proxy) newTLSClientRoundTripper(profile profiles.ClientProfile, route string) (http.RoundTripper, error) {
	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profile),
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithInsecureSkipVerify(),
		// Route every socket through fastdialer: a direct client dials the
		// target, an http(s) route CONNECT-tunnels through the proxy, a socks5
		// route dials through a SOCKS5 forward dialer — each socket enforcing
		// fastdialer allow/deny/DNS policy. The factory is used even for direct
		// clients (empty proxy URL) so fastdialer always owns the dial.
		tls_client.WithProxyDialerFactory(fastdialerProxyDialerFactory(p.Dialer)),
		// Match proxify's connection pooling behavior.
		tls_client.WithTransportOptions(&tls_client.TransportOptions{
			MaxIdleConns:        0,  // Disable pooling
			MaxIdleConnsPerHost: -1, // Unlimited
			MaxConnsPerHost:     0,  // Unlimited
			DisableKeepAlives:   false,
		}),
	}
	if route != "" {
		// The factory reads this URL to build the CONNECT/SOCKS proxy dialer.
		opts = append(opts, tls_client.WithProxyUrl(route))
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to create TLS client")
	}
	return &tlsClientRoundTripper{client: client}, nil
}

// fastdialerProxyDialerFactory returns a tls_client.ProxyDialerFactory whose
// dialers are all backed by fastdialer, so the fingerprinted path enforces the
// same allow/deny/DNS policy as the standard transport. tls-client invokes the
// factory for every client (including direct ones, with an empty proxyURL):
//   - empty proxyURL: dial the target directly through fastdialer.
//   - http(s)://:     open an HTTP CONNECT tunnel, dialing the proxy socket via
//     fastdialer and sending Basic auth from the URL userinfo.
//   - socks5(h)://:   dial through a SOCKS5 dialer whose forward dial (the proxy
//     socket) uses fastdialer, with auth from the URL userinfo.
func fastdialerProxyDialerFactory(dialer *fastdialer.Dialer) tls_client.ProxyDialerFactory {
	return func(proxyURL string, timeout time.Duration, _ *net.TCPAddr, _ fhttp.Header, _ tls_client.Logger) (proxy.ContextDialer, error) {
		if proxyURL == "" {
			return &fastdialerForward{dialer: dialer}, nil
		}
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, errorutil.NewWithErr(err).Msgf("invalid upstream proxy %q", proxyURL)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("invalid upstream proxy %q: missing host", proxyURL)
		}
		switch u.Scheme {
		case "http", "https":
			return newConnectContextDialer(dialer, u, timeout), nil
		case "socks5", "socks5h":
			return newSOCKSContextDialer(dialer, u)
		default:
			return nil, fmt.Errorf("unsupported upstream proxy scheme %q in %q", u.Scheme, proxyURL)
		}
	}
}

// connectContextDialer reaches a target by opening an HTTP CONNECT tunnel
// through an upstream HTTP(S) proxy. The socket to the proxy is dialed through
// fastdialer; for an https proxy that socket is wrapped in TLS. The target
// host:port and Basic-auth credentials from the proxy URL are preserved. Each
// DialContext builds a fresh tunnel and keeps no shared mutable state, so it is
// safe for concurrent use.
type connectContextDialer struct {
	dialer    *fastdialer.Dialer
	proxyURL  *url.URL
	proxyAddr string
	proxyAuth string // "Basic ..." header value, or "" when unauthenticated
	useTLS    bool
	timeout   time.Duration
}

func newConnectContextDialer(dialer *fastdialer.Dialer, u *url.URL, timeout time.Duration) *connectContextDialer {
	d := &connectContextDialer{
		dialer:    dialer,
		proxyURL:  u,
		proxyAddr: proxyHostPort(u),
		useTLS:    u.Scheme == "https",
		timeout:   timeout,
	}
	if u.User != nil {
		password, _ := u.User.Password()
		d.proxyAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+password))
	}
	return d
}

// Dial implements proxy.Dialer.
func (d *connectContextDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// DialContext implements proxy.ContextDialer, establishing the CONNECT tunnel to
// addr (the target host:port) through the upstream proxy.
func (d *connectContextDialer) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	conn, err = d.dialer.Dial(ctx, network, d.proxyAddr)
	if err != nil {
		return nil, err
	}
	// Any failure after a successful proxy dial must close the proxy socket.
	defer func() {
		if err != nil && conn != nil {
			_ = conn.Close()
		}
	}()

	if d.useTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         d.proxyURL.Hostname(),
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		})
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tlsConn
	}

	// The proxy dial (via fastdialer) and the TLS handshake above already honor
	// ctx cancellation. Bound the blocking CONNECT exchange itself with the
	// client timeout so a silent proxy cannot hang the dial.
	if d.timeout > 0 {
		if err = conn.SetDeadline(time.Now().Add(d.timeout)); err != nil {
			return nil, err
		}
	}

	req := &fhttp.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: addr},
		Host:   addr,
		Header: make(fhttp.Header),
	}
	if d.proxyAuth != "" {
		req.Header.Set("Proxy-Authorization", d.proxyAuth)
	}
	if err = req.Write(conn); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := fhttp.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("connect via %s failed: %s", d.proxyAddr, resp.Status)
		return nil, err
	}

	// Clear the handshake deadline before handing the tunnel to the caller.
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	// Read through the bufio.Reader so any bytes it buffered past the 200 (the
	// start of the tunneled stream) are not lost; writes still go to conn.
	return &bufferedConn{Conn: conn, r: br}, nil
}

// bufferedConn preserves bytes a bufio.Reader read past the CONNECT response so
// the tunneled stream stays intact. Reads come from the reader; every other
// operation delegates to the embedded conn.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// newSOCKSContextDialer builds a proxy.ContextDialer that reaches the target
// through a SOCKS5 proxy whose forward dial (the socket to the proxy) goes
// through fastdialer. Credentials from the URL userinfo are preserved.
func newSOCKSContextDialer(dialer *fastdialer.Dialer, u *url.URL) (proxy.ContextDialer, error) {
	var auth *proxy.Auth
	if u.User != nil {
		password, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: password}
	}
	socksDialer, err := proxy.SOCKS5("tcp", u.Host, auth, &fastdialerForward{dialer: dialer})
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("invalid upstream SOCKS5 proxy %q", u.Redacted())
	}
	if cd, ok := socksDialer.(proxy.ContextDialer); ok {
		return cd, nil
	}
	return &dialerContextAdapter{dialer: socksDialer}, nil
}

// dialerContextAdapter adds a context-aware DialContext to a proxy.Dialer that
// lacks one, falling back to its context-free Dial.
type dialerContextAdapter struct {
	dialer proxy.Dialer
}

// Dial implements proxy.Dialer.
func (a *dialerContextAdapter) Dial(network, addr string) (net.Conn, error) {
	return a.dialer.Dial(network, addr)
}

// DialContext implements proxy.ContextDialer.
func (a *dialerContextAdapter) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	return a.dialer.Dial(network, addr)
}

// proxyHostPort returns the host:port of an HTTP(S) proxy URL, defaulting the
// port to 443 for https and 80 otherwise when absent.
func proxyHostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}

// tlsClientRoundTripper adapts tls_client.HttpClient to http.RoundTripper,
// converting between net/http and fhttp types while preserving the request
// context, Host, body, trailers, and the Response.Request linkage.
type tlsClientRoundTripper struct {
	client tls_client.HttpClient
}

// RoundTrip implements http.RoundTripper.
func (t *tlsClientRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	fReq, err := convertToFHTTPRequest(req)
	if err != nil {
		return nil, err
	}
	fResp, err := t.client.Do(fReq)
	if err != nil {
		return nil, err
	}
	return convertFromFHTTPResponse(fResp, req), nil
}

// CloseIdleConnections releases idle connections on the underlying tls-client.
func (t *tlsClientRoundTripper) CloseIdleConnections() {
	t.client.CloseIdleConnections()
}

// convertToFHTTPRequest converts a net/http.Request to an fhttp.Request. It
// carries the request context and copies headers and trailers into fresh maps
// (values copied, not aliased) so the two requests never share mutable state.
func convertToFHTTPRequest(req *http.Request) (*fhttp.Request, error) {
	fReq, err := fhttp.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to build fhttp request")
	}
	fReq.Header = cloneToFHTTPHeader(req.Header)
	fReq.Host = req.Host
	fReq.ContentLength = req.ContentLength
	fReq.TransferEncoding = append([]string(nil), req.TransferEncoding...)
	fReq.Close = req.Close
	if req.Trailer != nil {
		fReq.Trailer = cloneToFHTTPHeader(req.Trailer)
	}
	return fReq, nil
}

// convertFromFHTTPResponse converts an fhttp.Response to a net/http.Response,
// setting Request to the effective net/http request and copying headers into a
// fresh map. Trailers are populated only after the body is read, so they are
// synced from the fhttp response when the body reaches EOF or is closed rather
// than copied here (which would capture only the empty declared keys).
func convertFromFHTTPResponse(fResp *fhttp.Response, req *http.Request) *http.Response {
	resp := &http.Response{
		Status:           fResp.Status,
		StatusCode:       fResp.StatusCode,
		Proto:            fResp.Proto,
		ProtoMajor:       fResp.ProtoMajor,
		ProtoMinor:       fResp.ProtoMinor,
		ContentLength:    fResp.ContentLength,
		TransferEncoding: append([]string(nil), fResp.TransferEncoding...),
		Close:            fResp.Close,
		Uncompressed:     fResp.Uncompressed,
		Request:          req,
	}
	resp.Header = cloneFromFHTTPHeader(fResp.Header)

	// Pre-declare any trailer keys the response already advertised; their values
	// are filled by trailerSyncBody once the body is drained.
	resp.Trailer = cloneFromFHTTPHeader(fResp.Trailer)
	body := fResp.Body
	if body == nil {
		body = http.NoBody
	}
	resp.Body = &trailerSyncBody{body: body, fResp: fResp, dst: resp.Trailer}
	return resp
}

// cloneToFHTTPHeader copies a net/http.Header into a fresh fhttp.Header,
// duplicating value slices so the result shares no mutable state with the input.
func cloneToFHTTPHeader(h http.Header) fhttp.Header {
	out := make(fhttp.Header, len(h))
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// cloneFromFHTTPHeader copies an fhttp.Header into a fresh net/http.Header,
// duplicating value slices. The result is always non-nil.
func cloneFromFHTTPHeader(h fhttp.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// trailerSyncBody wraps the fhttp response body and copies the response's
// trailers into dst once the body reaches EOF or is closed. HTTP trailers are
// only known after the body is fully read, so this defers the copy instead of
// aliasing fResp.Trailer.
type trailerSyncBody struct {
	body  io.ReadCloser
	fResp *fhttp.Response
	dst   http.Header
	once  sync.Once
}

func (b *trailerSyncBody) syncTrailers() {
	b.once.Do(func() {
		for k, v := range b.fResp.Trailer {
			b.dst[k] = append([]string(nil), v...)
		}
	})
}

func (b *trailerSyncBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if errors.Is(err, io.EOF) {
		b.syncTrailers()
	}
	return n, err
}

func (b *trailerSyncBody) Close() error {
	err := b.body.Close()
	b.syncTrailers()
	return err
}
