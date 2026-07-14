package proxify

// Transport construction for the proxy's upstream RoundTrippers (migration
// plan Step P5+). The direct (no upstream proxy) standard transport is built
// by newStandardTransport so it honors fastdialer policy and HTTP/2; the
// upstream HTTP/SOCKS branches and the tls-client fingerprinting adapter are
// relocated here verbatim and are reworked in later steps (P6/P7).

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"

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

// getStandardRoundTripper returns the original http.Transport implementation
func (p *Proxy) getStandardRoundTripper() (http.RoundTripper, error) {
	roundtrip := newStandardTransport(p.Dialer)

	if len(p.options.UpstreamHTTPProxies) > 0 {
		roundtrip = &http.Transport{Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(p.rbhttp.Next())
		}, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	} else if len(p.options.UpstreamSock5Proxies) > 0 {
		// for each socks5 proxy create a dialer
		socks5Dialers := make(map[string]proxy.Dialer)
		for _, socks5proxy := range p.options.UpstreamSock5Proxies {
			dialer, err := proxy.SOCKS5("tcp", socks5proxy, nil, proxy.Direct)
			if err != nil {
				return nil, err
			}
			socks5Dialers[socks5proxy] = dialer
		}
		roundtrip = &http.Transport{Dial: func(network, addr string) (net.Conn, error) {
			// lookup next dialer
			socks5Proxy := p.rbsocks5.Next()
			socks5Dialer := socks5Dialers[socks5Proxy]
			// use it to perform the request
			return socks5Dialer.Dial(network, addr)
		}, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return roundtrip, nil
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
