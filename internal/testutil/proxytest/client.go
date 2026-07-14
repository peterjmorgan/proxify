package proxytest

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// ProxyClient returns an *http.Client that routes everything through the
// proxy at proxyURL, trusts caPool for TLS, and — when forceH2 is set —
// offers h2 in ALPN so HTTP/2 can be negotiated end to end.
func ProxyClient(t *testing.T, proxyURL string, caPool *x509.CertPool, forceH2 bool) *http.Client {
	t.Helper()

	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("proxytest: parse proxy URL %q: %v", proxyURL, err)
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(u),
		TLSClientConfig: &tls.Config{
			RootCAs: caPool,
		},
		// A non-nil TLSClientConfig disables net/http's automatic HTTP/2;
		// opt back in explicitly when the caller wants h2.
		ForceAttemptHTTP2:   forceH2,
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: -1,
	}
	t.Cleanup(transport.CloseIdleConnections)

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
}
