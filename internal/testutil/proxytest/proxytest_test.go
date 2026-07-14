package proxytest

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/proxy"
)

func helloHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello via %s", r.Proto)
	})
}

func TestH1OriginSpeaksHTTP1Only(t *testing.T) {
	origin := NewH1Origin(t, helloHandler())

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: origin.CA.Pool()},
			ForceAttemptHTTP2: true, // offer h2; origin must still pick http/1.1
		},
	}
	resp, err := client.Get(origin.URL.String())
	if err != nil {
		t.Fatalf("GET origin: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ProtoMajor != 1 {
		t.Fatalf("H1 origin negotiated %s, want HTTP/1.x", resp.Proto)
	}
}

func TestH2OriginNegotiatesH2(t *testing.T) {
	origin := NewH2Origin(t, helloHandler())

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: origin.CA.Pool()},
			ForceAttemptHTTP2: true,
		},
	}
	resp, err := client.Get(origin.URL.String())
	if err != nil {
		t.Fatalf("GET origin: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ProtoMajor != 2 {
		t.Fatalf("H2 origin negotiated %s, want HTTP/2.0", resp.Proto)
	}
}

func TestHTTPUpstreamTunnelsConnectAndRecords(t *testing.T) {
	origin := NewH1Origin(t, helloHandler())
	upstream := NewHTTPUpstream(t)

	client := ProxyClient(t, upstream.URL, origin.CA.Pool(), false)
	resp, err := client.Get(origin.URL.String())
	if err != nil {
		t.Fatalf("GET origin through upstream CONNECT: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	hosts := upstream.Hosts()
	if len(hosts) == 0 || hosts[0] != origin.Host {
		t.Fatalf("upstream recorded hosts %v, want first entry %q", hosts, origin.Host)
	}
}

func TestHTTPUpstreamForwardsPlainHTTP(t *testing.T) {
	// Plain HTTP origin: absolute-form request through the upstream proxy.
	origin := httptest.NewServer(helloHandler())
	t.Cleanup(origin.Close)
	upstream := NewHTTPUpstream(t)

	client := ProxyClient(t, upstream.URL, nil, false)
	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET plain origin through upstream: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello via HTTP/1.1" {
		t.Fatalf("status = %d body = %q, want 200 %q", resp.StatusCode, body, "hello via HTTP/1.1")
	}
	if hosts := upstream.Hosts(); len(hosts) == 0 {
		t.Fatal("upstream recorded no hosts for plain HTTP forward")
	}
}

func TestSOCKS5UpstreamTunnelsAndRecords(t *testing.T) {
	origin := NewH1Origin(t, helloHandler())
	upstream := NewSOCKS5Upstream(t)

	dialer, err := proxy.SOCKS5("tcp", upstream.Addr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("build SOCKS5 dialer: %v", err)
	}
	transport := &http.Transport{
		Dial:            dialer.Dial,
		TLSClientConfig: &tls.Config{RootCAs: origin.CA.Pool()},
	}
	t.Cleanup(transport.CloseIdleConnections)

	resp, err := (&http.Client{Transport: transport}).Get(origin.URL.String())
	if err != nil {
		t.Fatalf("GET origin through SOCKS5 upstream: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || len(body) == 0 {
		t.Fatalf("status = %d body = %q, want 200 with body", resp.StatusCode, body)
	}

	addrs := upstream.Addrs()
	if len(addrs) == 0 || addrs[0] != origin.Host {
		t.Fatalf("SOCKS5 upstream recorded %v, want first entry %q", addrs, origin.Host)
	}
}
