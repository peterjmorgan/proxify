package proxytest

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"sync"
	"testing"

	"github.com/things-go/go-socks5"
)

// HTTPUpstream is a minimal local HTTP forward proxy (CONNECT tunnels and
// absolute-form plain requests) that records every host it is asked to reach.
type HTTPUpstream struct {
	Server *httptest.Server
	// Addr is the host:port the upstream proxy listens on.
	Addr string
	// URL is the http:// URL of the upstream proxy.
	URL string

	mu    sync.Mutex
	hosts []string
}

// Hosts returns a copy of the hosts requested through this upstream so far.
func (u *HTTPUpstream) Hosts() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.hosts...)
}

func (u *HTTPUpstream) record(host string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.hosts = append(u.hosts, host)
}

// NewHTTPUpstream starts a recording HTTP forward proxy on 127.0.0.1.
func NewHTTPUpstream(t *testing.T) *HTTPUpstream {
	t.Helper()

	upstream := &HTTPUpstream{}
	upstream.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.record(r.Host)
		if r.Method == http.MethodConnect {
			upstream.tunnel(w, r)
			return
		}
		// Absolute-form plain HTTP request: forward to the target.
		(&httputil.ReverseProxy{Director: func(*http.Request) {}}).ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Server.Close)

	upstream.URL = upstream.Server.URL
	upstream.Addr = upstream.Server.Listener.Addr().String()
	return upstream
}

// tunnel must not touch testing.T: hijacked conns are untracked by
// httptest.Server, so this can outlive the test that spawned it.
func (u *HTTPUpstream) tunnel(w http.ResponseWriter, r *http.Request) {
	target, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = target.Close() }()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	copyHalf := func(dst io.Writer, src io.Reader) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go copyHalf(target, client)
	go copyHalf(client, target)
	<-done
}

// SOCKS5Upstream is a local SOCKS5 proxy that records dialed addresses.
type SOCKS5Upstream struct {
	// Addr is the host:port the SOCKS5 proxy listens on.
	Addr string

	mu    sync.Mutex
	addrs []string
}

// Addrs returns a copy of the addresses dialed through this upstream so far.
func (u *SOCKS5Upstream) Addrs() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.addrs...)
}

// NewSOCKS5Upstream starts a recording SOCKS5 proxy on 127.0.0.1.
func NewSOCKS5Upstream(t *testing.T) *SOCKS5Upstream {
	t.Helper()

	upstream := &SOCKS5Upstream{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxytest: listen for SOCKS5 upstream: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	upstream.Addr = listener.Addr().String()

	server := socks5.NewServer(
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			upstream.mu.Lock()
			upstream.addrs = append(upstream.addrs, addr)
			upstream.mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}),
	)
	go func() { _ = server.Serve(listener) }()
	return upstream
}
