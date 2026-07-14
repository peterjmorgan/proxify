package proxify

// Transport construction for the proxy's upstream RoundTrippers (migration
// plan Step P5+). The direct (no upstream proxy) standard transport is built
// by newStandardTransport so it honors fastdialer policy and HTTP/2; upstream
// HTTP/SOCKS routing is request-based via routedRoundTripper (Step P6); the
// tls-client fingerprinting adapter is relocated here verbatim and reworked in
// Step P7.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
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
	selector, err := newRouteSelector(routes, p.options.UpstreamProxyRequestsNumber)
	if err != nil {
		return nil, err
	}
	transports := make(map[string]http.RoundTripper, len(routes))
	for _, route := range routes {
		if _, ok := transports[route]; ok {
			continue
		}
		t, err := build(p.Dialer, route)
		if err != nil {
			return nil, err
		}
		transports[route] = t
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

// getTLSClientRoundTripper returns a bogdanfinn/tls-client RoundTripper with fingerprinting
func (p *Proxy) getTLSClientRoundTripper() (http.RoundTripper, error) {
	// Get the TLS profile
	profile, err := tlsprofile.GetProfile(p.options.TLSProfile)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to get TLS profile")
	}

	// Build tls-client options
	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profile),
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithInsecureSkipVerify(),

		// Match proxify's connection pooling behavior
		tls_client.WithTransportOptions(&tls_client.TransportOptions{
			MaxIdleConns:        0,  // Disable pooling
			MaxIdleConnsPerHost: -1, // Unlimited
			MaxConnsPerHost:     0,  // Unlimited
			DisableKeepAlives:   false,
		}),
	}

	// Handle upstream proxy configuration
	// NOTE: We use tls-client's built-in proxy support, which means we lose
	// round-robin load balancing for now. Single upstream proxy only.
	if len(p.options.UpstreamHTTPProxies) > 0 {
		// Use first HTTP proxy
		proxyURL := p.options.UpstreamHTTPProxies[0]
		opts = append(opts, tls_client.WithProxyUrl(proxyURL))

		if len(p.options.UpstreamHTTPProxies) > 1 {
			gologger.Warning().Msgf(
				"TLS fingerprinting mode: using only first upstream HTTP proxy (%s). "+
					"Round-robin load balancing is not supported with TLS fingerprinting.",
				proxyURL,
			)
		}
	} else if len(p.options.UpstreamSock5Proxies) > 0 {
		// Use first SOCKS5 proxy
		proxyURL := p.options.UpstreamSock5Proxies[0]
		opts = append(opts, tls_client.WithProxyUrl(proxyURL))

		if len(p.options.UpstreamSock5Proxies) > 1 {
			gologger.Warning().Msgf(
				"TLS fingerprinting mode: using only first upstream SOCKS5 proxy (%s). "+
					"Round-robin load balancing is not supported with TLS fingerprinting.",
				proxyURL,
			)
		}
	}

	// Create the tls-client
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to create TLS client")
	}

	// Wrap the client in a RoundTripper adapter
	return &tlsClientRoundTripper{client: client}, nil
}

// tlsClientRoundTripper adapts tls_client.HttpClient to http.RoundTripper interface
// It handles conversion between net/http and fhttp types
type tlsClientRoundTripper struct {
	client tls_client.HttpClient
}

// RoundTrip implements the http.RoundTripper interface
func (t *tlsClientRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Convert net/http.Request to fhttp.Request
	fReq := convertToFHTTPRequest(req)

	// Execute request with tls-client
	fResp, err := t.client.Do(fReq)
	if err != nil {
		return nil, err
	}

	// Convert fhttp.Response back to net/http.Response
	return convertFromFHTTPResponse(fResp), nil
}

// convertToFHTTPRequest converts a net/http.Request to fhttp.Request
func convertToFHTTPRequest(req *http.Request) *fhttp.Request {
	// Create fhttp request with same parameters
	fReq, _ := fhttp.NewRequest(req.Method, req.URL.String(), req.Body)

	// Copy headers
	fReq.Header = make(fhttp.Header)
	for k, v := range req.Header {
		fReq.Header[k] = v
	}

	// Copy other important fields
	fReq.Host = req.Host
	fReq.ContentLength = req.ContentLength
	fReq.TransferEncoding = req.TransferEncoding
	fReq.Close = req.Close
	fReq.Trailer = fhttp.Header(req.Trailer)

	return fReq
}

// convertFromFHTTPResponse converts an fhttp.Response to net/http.Response
func convertFromFHTTPResponse(fResp *fhttp.Response) *http.Response {
	resp := &http.Response{
		Status:           fResp.Status,
		StatusCode:       fResp.StatusCode,
		Proto:            fResp.Proto,
		ProtoMajor:       fResp.ProtoMajor,
		ProtoMinor:       fResp.ProtoMinor,
		Body:             fResp.Body,
		ContentLength:    fResp.ContentLength,
		TransferEncoding: fResp.TransferEncoding,
		Close:            fResp.Close,
		Uncompressed:     fResp.Uncompressed,
		Request:          nil, // We'll set this if needed
	}

	// Convert headers
	resp.Header = make(http.Header)
	for k, v := range fResp.Header {
		resp.Header[k] = v
	}

	// Convert trailer
	resp.Trailer = make(http.Header)
	for k, v := range fResp.Trailer {
		resp.Trailer[k] = v
	}

	return resp
}
