package proxify

// Unit tests for the direct standard transport (migration plan Step P5). These
// drive newStandardTransport directly against local TLS origins to pin the two
// behaviors the previous direct branch silently dropped: HTTP/2 negotiation
// (ForceAttemptHTTP2) and routing every dial through fastdialer so its
// allow/deny policy is enforced. Response.Request linkage and the
// closeIdleRoundTripper helper are covered too. Everything binds 127.0.0.1 with
// ephemeral ports; no external network.

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/proxify/internal/testutil/proxytest"
)

// newTestDialer builds a fastdialer for a test, applying mutate to a copy of
// DefaultOptions (e.g. to set Allow/Deny). The dialer is closed on cleanup.
func newTestDialer(t *testing.T, mutate func(*fastdialer.Options)) *fastdialer.Dialer {
	t.Helper()
	opts := fastdialer.DefaultOptions
	if mutate != nil {
		mutate(&opts)
	}
	d, err := fastdialer.NewDialer(opts)
	if err != nil {
		t.Fatalf("fastdialer.NewDialer: %v", err)
	}
	t.Cleanup(d.Close)
	return d
}

// protoEchoHandler reports the protocol the origin negotiated so the client can
// confirm the origin (not just the client) spoke HTTP/2, and counts how many
// requests actually reached the handler.
func protoEchoHandler(hits *int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		w.Header().Set("X-Origin-Proto", r.Proto)
		_, _ = io.WriteString(w, "hello")
	})
}

// roundTripGet issues a GET through rt and returns the response (body drained).
func roundTripGet(t *testing.T, rt http.RoundTripper, url string) (*http.Response, *http.Request) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip %s: %v", url, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp, req
}

// TestStandardTransportDirectH2: a direct standard transport reaches a local
// TLS HTTP/2 origin, negotiates h2 end to end (origin sees HTTP/2.0), and sets
// Response.Request to the original request.
func TestStandardTransportDirectH2(t *testing.T) {
	var hits int32
	origin := proxytest.NewH2Origin(t, protoEchoHandler(&hits))
	rt := newStandardTransport(newTestDialer(t, nil))
	defer rt.CloseIdleConnections()

	resp, req := roundTripGet(t, rt, origin.URL.String())

	if resp.ProtoMajor != 2 {
		t.Fatalf("client negotiated %s, want HTTP/2.0", resp.Proto)
	}
	if got := resp.Header.Get("X-Origin-Proto"); got != "HTTP/2.0" {
		t.Fatalf("origin saw %q, want HTTP/2.0", got)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("origin handler ran %d times, want 1", hits)
	}
	if resp.Request != req {
		t.Fatalf("Response.Request = %p, want original request %p", resp.Request, req)
	}
}

// TestStandardTransportDirectH1: the same transport also works against a local
// TLS HTTP/1.1-only origin (ForceAttemptHTTP2 offers h2 but must fall back).
func TestStandardTransportDirectH1(t *testing.T) {
	var hits int32
	origin := proxytest.NewH1Origin(t, protoEchoHandler(&hits))
	rt := newStandardTransport(newTestDialer(t, nil))
	defer rt.CloseIdleConnections()

	resp, _ := roundTripGet(t, rt, origin.URL.String())

	if resp.ProtoMajor != 1 {
		t.Fatalf("negotiated %s, want HTTP/1.x", resp.Proto)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("origin handler ran %d times, want 1", hits)
	}
}

// TestStandardTransportFastdialerDeny: a fastdialer denying the loopback CIDR
// makes RoundTrip fail before the origin handler runs, proving the direct
// transport dials through fastdialer rather than a bare net.Dialer.
func TestStandardTransportFastdialerDeny(t *testing.T) {
	var hits int32
	origin := proxytest.NewH2Origin(t, protoEchoHandler(&hits))
	dialer := newTestDialer(t, func(o *fastdialer.Options) {
		o.Deny = []string{"127.0.0.0/8"}
	})
	rt := newStandardTransport(dialer)
	defer rt.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, origin.URL.String(), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("RoundTrip to denied loopback CIDR succeeded, want dial error")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("origin handler ran %d times despite deny, want 0", got)
	}
}

// TestStandardTransportFastdialerAllow: an allow-list that includes the loopback
// CIDR still permits the direct dial, so the request reaches the origin.
func TestStandardTransportFastdialerAllow(t *testing.T) {
	var hits int32
	origin := proxytest.NewH2Origin(t, protoEchoHandler(&hits))
	dialer := newTestDialer(t, func(o *fastdialer.Options) {
		o.Allow = []string{"127.0.0.0/8"}
	})
	rt := newStandardTransport(dialer)
	defer rt.CloseIdleConnections()

	resp, _ := roundTripGet(t, rt, origin.URL.String())

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("origin handler ran %d times, want 1", hits)
	}
}

// TestCloseIdleRoundTripper: the helper invokes CloseIdleConnections on a
// transport that supports it and is a safe no-op otherwise.
func TestCloseIdleRoundTripper(t *testing.T) {
	// *http.Transport implements CloseIdleConnections; helper must not panic.
	closeIdleRoundTripper(newStandardTransport(newTestDialer(t, nil)))

	// A RoundTripper without CloseIdleConnections is a no-op, not a panic.
	closeIdleRoundTripper(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.Canceled
	}))
}

// roundTripperFunc adapts a func to http.RoundTripper for the no-op test.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
