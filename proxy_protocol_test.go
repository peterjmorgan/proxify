package proxify

// HTTP/1 and HTTP/2 protocol-matrix E2E tests for migration plan Step P12.
// Semantic HTTP/2 is the primary migration outcome, so these drive the
// candidate serving core (Proxy.Run over a real loopback listener) and prove
// four independent properties:
//
//   - downstream/upstream protocol independence — the client's protocol to the
//     proxy and the origin's negotiated protocol are asserted separately across
//     H1->H1, H1->H2 TLS, H2->H2, and H2->H1 TLS (TestProtocolMatrix);
//   - stream identity — two concurrent H2 streams on one downstream connection
//     each get a distinct FlowContext.ID while sharing one ConnectionID;
//   - streaming + trailers — a streaming origin's first chunk reaches the client
//     before the origin releases the second, and a trailer survives to EOF;
//   - cancellation isolation — canceling one H2 stream ends only that request
//     (RST_STREAM / context cancellation) while a sibling stream on the same
//     downstream connection still completes with 200.
//
// Everything binds 127.0.0.1:0 and synchronizes on bounded channels: every
// test-side wait has a 2-second timeout and cleanup so no goroutine can hang the
// suite (origin-side release fallbacks are deliberately longer so a serving-core
// regression fails a 2s wait rather than being masked). The concurrency shape
// mirrors the tls-client concurrency tests in transport_tlsclient_test.go.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/proxify/internal/testutil/proxytest"
)

// protoRec is one observation of an intercepted request as the proxy saw it:
// the downstream protocol (req.Proto) plus the flow and connection identity.
type protoRec struct {
	method string
	proto  string
	path   string
	flowID string
	connID string
}

// protoRecorder collects protoRecs from OnRequestCallback across concurrent
// streams. It is safe for concurrent use.
type protoRecorder struct {
	mu   sync.Mutex
	recs []protoRec
}

// callback returns an OnRequestFunc that records every request. It never
// mutates the request, so the round trip proceeds unmodified.
func (r *protoRecorder) callback() OnRequestFunc {
	return func(req *http.Request, ctx *FlowContext) error {
		r.mu.Lock()
		r.recs = append(r.recs, protoRec{
			method: req.Method,
			proto:  req.Proto,
			path:   req.URL.Path,
			flowID: ctx.ID(),
			connID: ctx.ConnectionID(),
		})
		r.mu.Unlock()
		return nil
	}
}

// inner returns the recorded non-CONNECT requests (the intercepted inner
// requests, excluding the CONNECT control channel).
func (r *protoRecorder) inner() []protoRec {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]protoRec, 0, len(r.recs))
	for _, rec := range r.recs {
		if rec.method != http.MethodConnect {
			out = append(out, rec)
		}
	}
	return out
}

// distinctConnIDs returns the number of distinct connection ids across the
// recorded inner requests.
func (r *protoRecorder) distinctConnIDs() int {
	seen := map[string]struct{}{}
	for _, rec := range r.inner() {
		seen[rec.connID] = struct{}{}
	}
	return len(seen)
}

// recvWithin waits for ch to fire or fails the test after 2 seconds. It must be
// called only from the test goroutine (it calls t.Fatalf).
func recvWithin(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out after 2s waiting for %s", what)
	}
}

// TestProtocolMatrix asserts downstream/upstream protocol independence: the
// protocol the client speaks to the proxy (observed as req.Proto in the request
// callback) and the protocol the origin negotiates (echoed in X-Origin-Proto)
// are asserted separately for every H1/H2 combination. h2c prior knowledge is
// covered as a documented-skip subtest because Proxy.Run serves a plain
// http.Server with no h2c handler.
func TestProtocolMatrix(t *testing.T) {
	cases := []struct {
		name           string
		clientH2       bool // client offers h2 to the proxy's MITM leaf
		originH2       bool // origin offers h2 in ALPN
		wantDownstream string
		wantUpstream   string
	}{
		{"H1_to_H1", false, false, "HTTP/1.1", "HTTP/1.1"},
		{"H1_to_H2_TLS", false, true, "HTTP/1.1", "HTTP/2.0"},
		{"H2_to_H2", true, true, "HTTP/2.0", "HTTP/2.0"},
		{"H2_to_H1_TLS", true, false, "HTTP/2.0", "HTTP/1.1"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var origin *proxytest.Origin
			if tc.originH2 {
				origin = proxytest.NewH2Origin(t, protoEchoHandler(nil))
			} else {
				origin = proxytest.NewH1Origin(t, protoEchoHandler(nil))
			}

			rec := &protoRecorder{}
			proxyURL, caPool, _ := startProxy(t, func(o *Options) {
				o.OnRequestCallback = rec.callback()
			})

			var client *http.Client
			if tc.clientH2 {
				client = h2KeepAliveProxyClient(t, proxyURL, caPool)
			} else {
				client = proxytest.ProxyClient(t, proxyURL, caPool, false)
			}

			resp, err := client.Get(origin.URL.String() + "/matrix")
			if err != nil {
				t.Fatalf("GET via proxy: %v", err)
			}
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			// Upstream: the protocol the origin actually negotiated.
			if got := resp.Header.Get("X-Origin-Proto"); got != tc.wantUpstream {
				t.Fatalf("upstream origin protocol = %q, want %q", got, tc.wantUpstream)
			}

			// Downstream: the protocol the proxy saw the inner request arrive on.
			inner := rec.inner()
			if len(inner) != 1 {
				t.Fatalf("inner request callbacks = %d, want 1 (%+v)", len(inner), inner)
			}
			if inner[0].proto != tc.wantDownstream {
				t.Fatalf("downstream req.Proto = %q, want %q", inner[0].proto, tc.wantDownstream)
			}
		})
	}

	t.Run("h2c_prior_knowledge", func(t *testing.T) {
		t.Skip("listener harness serves a plain http.Server without an h2c handler; " +
			"downstream h2c prior knowledge is not offered (see proxy.go Run)")
	})
}

// TestConcurrentH2StreamsShareConnection fires two concurrent GETs that both
// block at the origin until both have arrived, so the two streams are
// simultaneously in flight on one downstream H2 connection. Each stream must get
// a distinct FlowContext.ID while sharing a single ConnectionID.
func TestConcurrentH2StreamsShareConnection(t *testing.T) {
	var mu sync.Mutex
	var arrived int
	bothArrived := make(chan struct{})
	origin := proxytest.NewH2Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the two concurrent stream requests participate in the barrier;
		// the warm-up request returns immediately so it cannot stall the setup.
		if r.URL.Path == "/stream0" || r.URL.Path == "/stream1" {
			mu.Lock()
			arrived++
			if arrived == 2 {
				close(bothArrived)
			}
			mu.Unlock()
			select {
			case <-bothArrived:
			case <-time.After(2 * time.Second):
			}
		}
		_, _ = io.WriteString(w, "hello")
	}))

	rec := &protoRecorder{}
	proxyURL, caPool, _ := startProxy(t, func(o *Options) {
		o.OnRequestCallback = rec.callback()
	})
	client := h2KeepAliveProxyClient(t, proxyURL, caPool)

	// Warm up one request so the downstream H2 connection exists and is pooled;
	// the two concurrent requests then multiplex over it instead of racing to
	// open two connections.
	warm, err := client.Get(origin.URL.String() + "/warm")
	if err != nil {
		t.Fatalf("warm-up GET: %v", err)
	}
	_, _ = io.ReadAll(warm.Body)
	_ = warm.Body.Close()

	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := client.Get(fmt.Sprintf("%s/stream%d", origin.URL.String(), i))
			if err != nil {
				errs <- err
				return
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if string(body) != "hello" {
				errs <- fmt.Errorf("stream%d body = %q, want hello", i, body)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent stream failed: %v", err)
		}
	}

	// Both concurrent streams must be H2, distinct flows, one connection.
	var streams []protoRec
	for _, r := range rec.inner() {
		if r.path == "/stream0" || r.path == "/stream1" {
			streams = append(streams, r)
		}
	}
	if len(streams) != 2 {
		t.Fatalf("recorded %d concurrent streams, want 2 (%+v)", len(streams), streams)
	}
	if streams[0].proto != "HTTP/2.0" || streams[1].proto != "HTTP/2.0" {
		t.Fatalf("concurrent streams not both H2: %+v", streams)
	}
	if streams[0].flowID == "" || streams[0].flowID == streams[1].flowID {
		t.Fatalf("concurrent streams must have distinct non-empty flow ids: %q, %q", streams[0].flowID, streams[1].flowID)
	}
	if streams[0].connID == "" || streams[0].connID != streams[1].connID {
		t.Fatalf("concurrent streams must share one non-empty connection id: %q, %q", streams[0].connID, streams[1].connID)
	}
}

// TestH2StreamingAndTrailers verifies a streaming origin over H2->H2: the client
// observes the first chunk before the origin is released to send the second, and
// a response trailer set after the body survives to EOF.
//
// It runs the callback path (no-op OnRequest/OnResponse) to isolate the serving
// core's streaming from the logger's deliberate response-body snapshot: the
// default path buffers the first responseSnapshotPrefix (4 KiB) bytes for the
// on-disk export, so io.CopyN blocks until the origin sends that many bytes or
// EOF — which would defer "part1" past the release and defeat this test. That
// buffering lives in pkg/logger (Do Not Modify) and predates the migration, so
// it is not a regression; the callback path is how a library consumer streams.
//
// The origin's own release fallback (8s) is intentionally longer than the 2s
// wait for part1: if the serving core ever buffers the whole response, "part1"
// never reaches the client before release, and the 2s wait fails the test
// instead of the origin fallback silently masking the regression.
func TestH2StreamingAndTrailers(t *testing.T) {
	releasePart2 := make(chan struct{})
	origin := proxytest.NewH2Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-End")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "part1")
		flusher.Flush()
		select {
		case <-releasePart2:
		case <-time.After(8 * time.Second):
		}
		_, _ = io.WriteString(w, "part2")
		w.Header().Set("X-End", "done")
	}))

	proxyURL, caPool, _ := startProxy(t, func(o *Options) {
		o.OnRequestCallback = func(*http.Request, *FlowContext) error { return nil }
		o.OnResponseCallback = func(*http.Response, *FlowContext) error { return nil }
	})
	client := h2KeepAliveProxyClient(t, proxyURL, caPool)

	resp, err := client.Get(origin.URL.String() + "/stream")
	if err != nil {
		t.Fatalf("GET streaming origin: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ProtoMajor != 2 {
		t.Fatalf("downstream response protocol = %s, want HTTP/2.0", resp.Proto)
	}

	part1Seen := make(chan struct{})
	type result struct {
		body    string
		trailer string
		err     error
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, len("part1"))
		if _, err := io.ReadFull(resp.Body, buf); err != nil {
			done <- result{err: fmt.Errorf("read part1: %w", err)}
			return
		}
		close(part1Seen)
		rest, err := io.ReadAll(resp.Body)
		if err != nil {
			done <- result{err: fmt.Errorf("read rest: %w", err)}
			return
		}
		done <- result{body: "part1" + string(rest), trailer: resp.Trailer.Get("X-End")}
	}()

	// The client must see part1 BEFORE the origin is released to send part2 —
	// proving the response streams rather than buffering to completion.
	recvWithin(t, part1Seen, "client to observe part1 before release")
	close(releasePart2)

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("streaming read: %v", res.err)
		}
		if res.body != "part1part2" {
			t.Fatalf("streamed body = %q, want %q", res.body, "part1part2")
		}
		if res.trailer != "done" {
			t.Fatalf("response trailer X-End = %q, want %q", res.trailer, "done")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out after 2s waiting for streamed body + trailer")
	}
}

// TestH2StreamCancellationIsolation cancels one in-flight H2 stream while a
// sibling stream on the same downstream connection stays blocked. The canceled
// request must end with cancellation; the sibling must still return 200 without
// the proxy opening a second downstream connection.
func TestH2StreamCancellationIsolation(t *testing.T) {
	cancelStarted := make(chan struct{})
	okStarted := make(chan struct{})
	releaseOK := make(chan struct{})

	origin := proxytest.NewH2Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cancel":
			close(cancelStarted)
			// Block until the client's cancellation propagates (or a safety
			// timeout) so the origin never hangs the suite.
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		case "/ok":
			close(okStarted)
			select {
			case <-releaseOK:
			case <-time.After(2 * time.Second):
			}
			_, _ = io.WriteString(w, "hello")
		default:
			_, _ = io.WriteString(w, "warm")
		}
	}))

	rec := &protoRecorder{}
	proxyURL, caPool, _ := startProxy(t, func(o *Options) {
		o.OnRequestCallback = rec.callback()
	})
	client := h2KeepAliveProxyClient(t, proxyURL, caPool)

	// Warm up so the downstream H2 connection is pooled; both real streams then
	// multiplex over it.
	warm, err := client.Get(origin.URL.String() + "/warm")
	if err != nil {
		t.Fatalf("warm-up GET: %v", err)
	}
	_, _ = io.ReadAll(warm.Body)
	_ = warm.Body.Close()

	// Start the /ok stream (blocks at the origin) and wait until it is in flight.
	okDone := make(chan error, 1)
	go func() {
		resp, err := client.Get(origin.URL.String() + "/ok")
		if err != nil {
			okDone <- err
			return
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "hello" {
			okDone <- fmt.Errorf("/ok = %d %q, want 200 hello", resp.StatusCode, body)
			return
		}
		okDone <- nil
	}()
	recvWithin(t, okStarted, "/ok stream to reach the origin")

	// Start the /cancel stream on the same connection and wait until it is in
	// flight, then cancel only that request.
	ctx, cancel := context.WithCancel(context.Background())
	cancelDone := make(chan error, 1)
	go func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL.String()+"/cancel", nil)
		if err != nil {
			cancelDone <- err
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			cancelDone <- err
			return
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		cancelDone <- fmt.Errorf("/cancel returned %d, want a cancellation error", resp.StatusCode)
	}()
	recvWithin(t, cancelStarted, "/cancel stream to reach the origin")

	cancel()

	// The canceled stream ends with context cancellation (RST_STREAM downstream).
	select {
	case err := <-cancelDone:
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("/cancel error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out after 2s waiting for /cancel to end")
	}

	// The sibling stream still completes with 200 on the same connection.
	close(releaseOK)
	select {
	case err := <-okDone:
		if err != nil {
			t.Fatalf("/ok did not complete after sibling cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out after 2s waiting for /ok to complete")
	}

	// No new downstream connection was opened: /ok and /cancel shared one.
	if got := rec.distinctConnIDs(); got != 1 {
		t.Fatalf("distinct downstream connection ids = %d, want 1 (%+v)", got, rec.inner())
	}
}
