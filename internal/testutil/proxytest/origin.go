package proxytest

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/net/http2"
)

// Origin is a local TLS test origin server backed by a throwaway CA.
type Origin struct {
	Server *httptest.Server
	CA     *CA
	URL    *url.URL
	// Host is the host:port the origin listens on (always 127.0.0.1).
	Host string
}

// NewPlainOrigin starts a local plain-HTTP (no TLS) origin server.
func NewPlainOrigin(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// NewH1Origin starts a local TLS origin that speaks HTTP/1.1 only
// (ALPN restricted to http/1.1). The server certificate is issued for
// 127.0.0.1 by a fresh throwaway CA available via Origin.CA.
func NewH1Origin(t *testing.T, handler http.Handler) *Origin {
	t.Helper()
	return newTLSOrigin(t, handler, false)
}

// NewH2Origin starts a local TLS origin with HTTP/2 enabled
// (ALPN offers h2 then http/1.1), certificate issued like NewH1Origin.
func NewH2Origin(t *testing.T, handler http.Handler) *Origin {
	t.Helper()
	return newTLSOrigin(t, handler, true)
}

func newTLSOrigin(t *testing.T, handler http.Handler, h2 bool) *Origin {
	t.Helper()

	ca := NewCA(t)
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.Issue(t, "127.0.0.1", "localhost")},
		NextProtos:   []string{"http/1.1"},
	}
	if h2 {
		srv.TLS.NextProtos = []string{http2.NextProtoTLS, "http/1.1"}
		srv.EnableHTTP2 = true
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("proxytest: parse origin URL %q: %v", srv.URL, err)
	}
	return &Origin{Server: srv, CA: ca, URL: u, Host: u.Host}
}
