package proxytest

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/josexy/websocket"
	"golang.org/x/net/http2"
)

// WSConfig configures a local WebSocket test origin. The zero value is a plain
// (ws://) echo origin with no header requirements.
type WSConfig struct {
	// TLS serves wss:// (leaf issued by a fresh throwaway CA for 127.0.0.1);
	// otherwise the origin serves plain ws://.
	TLS bool
	// RequireHeaderKey/Value, when RequireHeaderKey is non-empty, makes the
	// origin reject the upgrade with 400 unless the upgrade request carries the
	// exact header value. This proves a proxy-side request mutation reached the
	// origin (the client sends nothing under this key).
	RequireHeaderKey, RequireHeaderValue string
	// ResponseHeaderKey/Value, when ResponseHeaderKey is non-empty, is added to
	// the 101 handshake response the origin sends, so a test can prove an origin
	// response header survives to the client.
	ResponseHeaderKey, ResponseHeaderValue string
}

// WSOrigin is a local WebSocket echo origin for interception tests. On a
// successful upgrade it echoes a text "ping" as "pong" and then blocks reading
// until the relay tears down, so a test can observe teardown deterministically
// via Exits. Everything binds 127.0.0.1 on an ephemeral port.
type WSOrigin struct {
	Server *httptest.Server
	// CA is the throwaway authority that signed the origin leaf (nil for plain
	// ws://). Proxify dials upstream with InsecureSkipVerify, so tests do not
	// need it for the MITM path; it is exposed for symmetry with Origin.
	CA *CA
	// URL is the origin base (ws://127.0.0.1:port or wss://127.0.0.1:port).
	URL *url.URL
	// Host is the host:port the origin listens on (always 127.0.0.1).
	Host string
	// Hits counts upgrade requests that reached the origin handler. A handshake
	// rejected by the proxy before dialing the origin leaves this at zero.
	Hits *atomic.Int64
	// Exits counts origin handler goroutines that have returned (the read loop
	// ended and the connection was closed), i.e. a relayed WebSocket that has
	// fully torn down on the upstream side.
	Exits *atomic.Int64
}

// NewWebSocketOrigin starts a local WebSocket echo origin per cfg. It uses the
// candidate's gorilla-compatible websocket library (already resolved
// transitively) for the server upgrade; no second server framework is added.
func NewWebSocketOrigin(t *testing.T, cfg WSConfig) *WSOrigin {
	t.Helper()

	o := &WSOrigin{Hits: &atomic.Int64{}, Exits: &atomic.Int64{}}
	upgrader := &websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		o.Hits.Add(1)
		if cfg.RequireHeaderKey != "" && r.Header.Get(cfg.RequireHeaderKey) != cfg.RequireHeaderValue {
			http.Error(w, "missing required handshake header", http.StatusBadRequest)
			return
		}
		var respHeader http.Header
		if cfg.ResponseHeaderKey != "" {
			respHeader = http.Header{cfg.ResponseHeaderKey: {cfg.ResponseHeaderValue}}
		}
		conn, err := upgrader.Upgrade(w, r, respHeader)
		if err != nil {
			return
		}
		defer func() {
			_ = conn.Close()
			o.Exits.Add(1)
		}()
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.TextMessage && string(msg) == "ping" {
				if err := conn.WriteMessage(websocket.TextMessage, []byte("pong")); err != nil {
					return
				}
			}
		}
	})

	scheme := "ws"
	if cfg.TLS {
		scheme = "wss"
		o.CA = NewCA(t)
		srv := httptest.NewUnstartedServer(mux)
		srv.TLS = &tls.Config{
			Certificates: []tls.Certificate{o.CA.Issue(t, "127.0.0.1", "localhost")},
			// Offer h2 then http/1.1 like the H2 origin; the WebSocket upgrade
			// still negotiates http/1.1, exercising ALPN selection realistically.
			NextProtos: []string{http2.NextProtoTLS, "http/1.1"},
		}
		srv.StartTLS()
		o.Server = srv
	} else {
		o.Server = httptest.NewServer(mux)
	}
	t.Cleanup(o.Server.Close)

	u, err := url.Parse(o.Server.URL)
	if err != nil {
		t.Fatalf("proxytest: parse ws origin URL %q: %v", o.Server.URL, err)
	}
	u.Scheme = scheme
	o.URL = u
	o.Host = u.Host
	return o
}
