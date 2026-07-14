package logger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/proxify/pkg/types"
	pdhttpUtils "github.com/projectdiscovery/utils/http"
)

func newTestRequest(t *testing.T, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://example.local/hello", body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

func TestSnapshotRequestPreservesLiveBody(t *testing.T) {
	const payload = "live-request-body"
	req := newTestRequest(t, strings.NewReader(payload))

	clone := snapshotRequest(req)

	live, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading live body: %v", err)
	}
	if string(live) != payload {
		t.Fatalf("live body = %q, want %q", live, payload)
	}
	snap, err := io.ReadAll(clone.Body)
	if err != nil {
		t.Fatalf("reading snapshot body: %v", err)
	}
	if string(snap) != payload {
		t.Fatalf("snapshot body = %q, want %q", snap, payload)
	}
	if clone.GetBody != nil {
		t.Fatal("snapshot GetBody must be nil; must not share the rewind func")
	}
}

func TestSnapshotRequestConcurrentDumpAndForward(t *testing.T) {
	const payload = "concurrent-body"
	req := newTestRequest(t, strings.NewReader(payload))

	clone := snapshotRequest(req)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		// async writer side: dump mutates the clone's Body field
		defer wg.Done()
		if _, err := httputil.DumpRequest(clone, true); err != nil {
			t.Errorf("DumpRequest on snapshot: %v", err)
		}
	}()
	go func() {
		// transport side: forwards the live request
		defer wg.Done()
		if b, err := io.ReadAll(req.Body); err != nil || string(b) != payload {
			t.Errorf("live forward read = %q, %v; want %q, nil", b, err, payload)
		}
	}()
	wg.Wait()
}

func TestSnapshotRequestNilAndNoBody(t *testing.T) {
	reqNil := newTestRequest(t, nil)
	if clone := snapshotRequest(reqNil); clone == nil {
		t.Fatal("snapshot of nil-body request is nil")
	}
	reqNoBody := newTestRequest(t, nil)
	reqNoBody.Body = http.NoBody
	if clone := snapshotRequest(reqNoBody); clone.Body != http.NoBody {
		t.Fatal("http.NoBody must pass through unchanged")
	}
}

func TestSnapshotRequestPropagatesReadError(t *testing.T) {
	wantErr := errors.New("client aborted upload")
	req := newTestRequest(t, io.MultiReader(strings.NewReader("partial"), &errReader{err: wantErr}))

	clone := snapshotRequest(req)

	b, err := io.ReadAll(req.Body)
	if string(b) != "partial" {
		t.Fatalf("live prefix = %q, want %q", b, "partial")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("live body error = %v, want %v", err, wantErr)
	}
	sb, serr := io.ReadAll(clone.Body)
	if string(sb) != "partial" || !errors.Is(serr, wantErr) {
		t.Fatalf("snapshot body = %q, %v; want %q, %v", sb, serr, "partial", wantErr)
	}
}

func newTestResponse(body io.ReadCloser) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       body,
	}
}

// closeTracker records whether the original body was closed through the wrapper.
type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error { c.closed = true; return nil }

func TestSnapshotResponseSmallBody(t *testing.T) {
	const payload = "hello"
	resp := newTestResponse(io.NopCloser(strings.NewReader(payload)))

	clone := snapshotResponse(resp)

	if live, _ := io.ReadAll(resp.Body); string(live) != payload {
		t.Fatalf("live body = %q, want %q", live, payload)
	}
	if snap, _ := io.ReadAll(clone.Body); string(snap) != payload {
		t.Fatalf("snapshot body = %q, want %q", snap, payload)
	}
}

func TestSnapshotResponseLargeBodyStreamsFullToClient(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 10*1024)
	resp := newTestResponse(io.NopCloser(bytes.NewReader(payload)))

	clone := snapshotResponse(resp)

	live, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading live body: %v", err)
	}
	if !bytes.Equal(live, payload) {
		t.Fatalf("live body: got %d bytes, want %d intact", len(live), len(payload))
	}
	snap, _ := io.ReadAll(clone.Body)
	if len(snap) != responseSnapshotPrefix {
		t.Fatalf("snapshot prefix = %d bytes, want %d", len(snap), responseSnapshotPrefix)
	}
}

func TestSnapshotResponseDecouplesMutations(t *testing.T) {
	resp := newTestResponse(io.NopCloser(strings.NewReader("ok")))

	clone := snapshotResponse(resp)

	// callers mutate the live response after logging (proxy.go sets Close on
	// redirects); the queued snapshot must not observe it
	resp.Close = true
	resp.Header.Set("X-After", "mutated")
	if clone.Close {
		t.Fatal("snapshot aliases live Close flag")
	}
	if clone.Header.Get("X-After") != "" {
		t.Fatal("snapshot aliases live Header map")
	}
}

func TestSnapshotResponseClosesOriginalBody(t *testing.T) {
	tracker := &closeTracker{Reader: strings.NewReader("body")}
	resp := newTestResponse(tracker)

	snapshotResponse(resp)

	if err := resp.Body.Close(); err != nil {
		t.Fatalf("closing live body: %v", err)
	}
	if !tracker.closed {
		t.Fatal("closing the wrapped live body must close the original body")
	}
}

// TestSnapshotResponseChainParity locks the responseSnapshotPrefix = 4096+1
// design: run snapshots through the same 4096-capped ResponseChain AsyncWrite
// uses. An oversize body must trip the cap (partial 4096 bytes plus the
// x-nuclei-ignore-error marker header, matching the old live-body behavior);
// a body of exactly 4096 bytes must be logged whole with no marker.
func TestSnapshotResponseChainParity(t *testing.T) {
	cases := []struct {
		name       string
		bodySize   int
		wantLogged int
		wantMarker bool
	}{
		{name: "oversize trips cap", bodySize: 10 * 1024, wantLogged: 4096, wantMarker: true},
		{name: "exactly cap logs whole", bodySize: 4096, wantLogged: 4096, wantMarker: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte("y"), tc.bodySize)
			resp := newTestResponse(io.NopCloser(bytes.NewReader(payload)))

			clone := snapshotResponse(resp)

			chain := pdhttpUtils.NewResponseChain(clone, 4096)
			defer chain.Close()
			if err := chain.Fill(); err != nil {
				t.Fatalf("ResponseChain.Fill: %v", err)
			}
			if got := chain.Body().Len(); got != tc.wantLogged {
				t.Fatalf("logged body = %d bytes, want %d", got, tc.wantLogged)
			}
			marker := clone.Header.Get("x-nuclei-ignore-error") != ""
			if marker != tc.wantMarker {
				t.Fatalf("ignore-error marker present = %v, want %v", marker, tc.wantMarker)
			}
			// the marker Header.Set on the clone must never leak to the live response
			if resp.Header.Get("x-nuclei-ignore-error") != "" {
				t.Fatal("chain marker header leaked onto the live response")
			}
			if live, _ := io.ReadAll(resp.Body); len(live) != tc.bodySize {
				t.Fatalf("live body = %d bytes, want %d intact", len(live), tc.bodySize)
			}
		})
	}
}

func TestSnapshotResponsePropagatesMidBodyError(t *testing.T) {
	wantErr := errors.New("upstream reset")
	resp := newTestResponse(io.NopCloser(io.MultiReader(strings.NewReader("partial"), &errReader{err: wantErr})))

	clone := snapshotResponse(resp)

	b, err := io.ReadAll(resp.Body)
	if string(b) != "partial" || !errors.Is(err, wantErr) {
		t.Fatalf("live body = %q, %v; want %q, %v", b, err, "partial", wantErr)
	}
	// snapshot keeps what was captured before the failure
	if sb, _ := io.ReadAll(clone.Body); string(sb) != "partial" {
		t.Fatalf("snapshot body = %q, want %q", sb, "partial")
	}
}

func TestLoggerEndToEndRaceFree(t *testing.T) {
	// No output folder: the file store is a no-op with empty OutputFolder/File,
	// so even though Close now drains AsyncWrite (P15) nothing hits disk. The
	// race surface under test is AsyncWrite consuming snapshots while live
	// objects are used and mutated.
	l := NewLogger(&OptionsLogger{
		Verbosity: types.VerbosityDefault,
		Elastic:   &elastic.Options{},
		Kafka:     &kafka.Options{},
	})

	const payload = "e2e-body"
	req := newTestRequest(t, strings.NewReader(payload))
	if err := l.LogRequest(req, types.UserData{ID: "flow-1", Host: "example.local"}); err != nil {
		t.Fatalf("LogRequest: %v", err)
	}
	// the transport forwards the live request while AsyncWrite dumps the snapshot
	if b, err := io.ReadAll(req.Body); err != nil || string(b) != payload {
		t.Fatalf("live forward read = %q, %v; want %q, nil", b, err, payload)
	}

	resp := newTestResponse(io.NopCloser(strings.NewReader("resp-body")))
	resp.Request = req
	if err := l.LogResponse(resp, types.UserData{ID: "flow-1", Host: "example.local", HasResponse: true}); err != nil {
		t.Fatalf("LogResponse: %v", err)
	}
	// the proxy writes the live response to the client and mutates it afterwards,
	// concurrently with AsyncWrite processing the queued snapshots
	if b, _ := io.ReadAll(resp.Body); string(b) != "resp-body" {
		t.Fatalf("live response body = %q, want %q", b, "resp-body")
	}
	resp.Close = true
	resp.Header.Set("X-After-Log", "mutated")

	// let AsyncWrite dequeue everything so its snapshot reads genuinely overlap
	// the live mutations above under the race detector
	for len(l.asyncqueue) > 0 {
		time.Sleep(time.Millisecond)
	}
	l.Close()
}

// recordingStore is a fake Store that records, in arrival order, the flow ID of
// every transaction AsyncWrite hands it.
type recordingStore struct {
	mu  sync.Mutex
	ids []string
}

func (s *recordingStore) Save(data types.HTTPTransaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ids = append(s.ids, data.Userdata.ID)
	return nil
}

func (s *recordingStore) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.ids))
	copy(out, s.ids)
	return out
}

// countingWriter is a fake OutputFileWriter that counts how many times Close was
// called, so the "close once" invariant can be asserted.
type countingWriter struct {
	closes atomic.Int64
}

func (w *countingWriter) Write(*types.HTTPRequestResponseLog) error { return nil }
func (w *countingWriter) Close() error {
	w.closes.Add(1)
	return nil
}

// newDrainTestLogger builds a Logger wired to the given store with no disk or
// structured output, so tests exercise the drain path in isolation.
func newDrainTestLogger(t *testing.T, store Store) *Logger {
	t.Helper()
	l := NewLogger(&OptionsLogger{
		Verbosity: types.VerbosityDefault,
		Elastic:   &elastic.Options{},
		Kafka:     &kafka.Options{},
	})
	// Replace the default file store before enqueuing anything: the channel
	// send below establishes happens-before with AsyncWrite's read of Store.
	l.Store = []Store{store}
	return l
}

// TestCloseDrainsAllAcceptedInOrder enqueues 100 numbered transactions and
// asserts the fake Store received all of them, in order, by the time Close
// returns (P15: no accepted item is dropped and the drain is synchronous).
func TestCloseDrainsAllAcceptedInOrder(t *testing.T) {
	store := &recordingStore{}
	l := newDrainTestLogger(t, store)

	const n = 100
	want := make([]string, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%03d", i)
		want[i] = id
		req := newTestRequest(t, strings.NewReader("body"))
		if err := l.LogRequest(req, types.UserData{ID: id, Host: "example.local"}); err != nil {
			t.Fatalf("LogRequest %d: %v", i, err)
		}
	}

	l.Close()

	got := store.snapshot()
	if len(got) != n {
		t.Fatalf("store received %d transactions, want %d", len(got), n)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("out of order at %d: got %q, want %q", i, got[i], want[i])
		}
	}

	// Close after drain must still reject producers.
	if err := l.LogRequest(newTestRequest(t, nil), types.UserData{ID: "late"}); !errors.Is(err, ErrLoggerClosed) {
		t.Fatalf("LogRequest after Close = %v, want ErrLoggerClosed", err)
	}
}

// TestConcurrentProducersRacingClose runs 20 producers against a concurrent
// Close: every LogRequest must return nil or ErrLoggerClosed and never panic
// on a send to a closed channel (run under -race).
func TestConcurrentProducersRacingClose(t *testing.T) {
	l := newDrainTestLogger(t, &recordingStore{})

	const producers = 20
	var wg sync.WaitGroup
	wg.Add(producers)
	for p := 0; p < producers; p++ {
		go func(p int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				req := newTestRequest(t, strings.NewReader("body"))
				err := l.LogRequest(req, types.UserData{ID: fmt.Sprintf("%d-%d", p, i)})
				if err != nil && !errors.Is(err, ErrLoggerClosed) {
					t.Errorf("producer %d: unexpected error %v", p, err)
					return
				}
			}
		}(p)
	}

	// Close concurrently with the producers so some sends race the close.
	l.Close()
	wg.Wait()
}

// TestRepeatedCloseIsIdempotent calls Close 20 times concurrently and asserts
// every call returns and the structured writer is closed exactly once.
func TestRepeatedCloseIsIdempotent(t *testing.T) {
	writer := &countingWriter{}
	l := newDrainTestLogger(t, &recordingStore{})
	l.sWriter = writer

	const callers = 20
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			l.Close()
		}()
	}
	wg.Wait()

	if got := writer.closes.Load(); got != 1 {
		t.Fatalf("structured writer closed %d times, want 1", got)
	}
}
