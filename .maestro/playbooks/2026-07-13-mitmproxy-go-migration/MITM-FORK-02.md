# mitmproxy-go Migration — Fork Phase 2: Lazy MITM / Lifecycle / WebSocket

**Repository:** the FORK `github.com/peterjmorgan/mitmproxy-go` (base `1c9f067`), run from a
fork checkout — NOT the Proxify working directory. Authoritative spec:
`planning/mitmproxy-go-migration/plan.md` Steps F5–F7. Do this only after `MITM-FORK-01.md`
(F1–F4) is green. New behavior stays opt-in; the eager default is untouched.

- [ ] **F5 — Implement opt-in lazy-upstream MITM (depends on F1–F4).** In opt-in lazy mode,
  terminate downstream TLS/H1/H2 without opening an origin connection.
  - Add `WithLazyUpstreamMITM() Option` and immutable runtime state. Refactor `Serve` so passthrough always dials and relays; eager mode keeps the current dial-first path; lazy intercepted mode creates local/`connCtx` with no remote conn.
  - Lazy TLS `GetConfigForClient` calls the F4 helper using SNI then CONNECT authority. Advertise h2 only if the client offered h2 AND HTTP2 is enabled; always include http/1.1 fallback; never advertise a protocol the client did not offer.
  - Lazy cleartext H1 and h2c prior-knowledge use the injected RoundTripper; with none, lazily construct the existing per-connection transport so the fork stays independently usable. For intercepted SOCKS5, write success WITHOUT a speculative origin dial (use a zero bind address when no upstream socket exists); passthrough SOCKS5 retains dial-before-success. All nil remote/transport close paths must be safe.
  - Add helper `downstreamTLSConfig(ctx, capturedClientHello) (*tls.Config, error)` using F4.
  - Do Not Modify: eager ClientHello mirroring behavior or WebSocket interception semantics.
  - Success: a counting dialer stays at zero through CONNECT + downstream TLS handshake, then the injected transport returns 200; ALPN negotiation matches offer/HTTP2 flag; H2↔H1 crossovers succeed; SOCKS intercepted handshake has zero dials until the first HTTP request and surfaces dial failure without panic; lazy + all eager tests pass under `-race`. Full detail: plan.md §Step F5.

- [ ] **F6 — Add stable connection identity and lifecycle events (depends on F5).** Expose
  immutable per-connection identity/events without serializing streams.
  - New `lifecycle.go`: `type ConnectionEventKind uint8` with constants `ConnectReceived, ConnectResponse, PassthroughDecided, TerminalError, ConnectionClosed`; `type ConnectionEvent struct { Kind ConnectionEventKind; ConnectionID, Hostport string; Request *http.Request; StatusCode int; Passthrough bool; Err error }`; `type ConnectionLifecycleHook func(context.Context, ConnectionEvent)`.
  - Add `WithConnectionLifecycleHook` and `ConnectionIDFromContext(context.Context) (string, bool)`. Assign IDs from a package-level `atomic.uint64` formatted decimal at connection bootstrap; put the ID in every derived H1/H2/WebSocket request context.
  - Emit CONNECT-received only for HTTP CONNECT, then selected status before bytes are written; emit passthrough for HTTP and SOCKS; terminal error at most once per terminal connection path; closed exactly once. Invoke hooks synchronously in the connection's goroutine with NO package-global hook mutex; document that hooks must return promptly. Existing `ErrorHandler` stays compatible.
  - Do Not Modify: metadata public API, HTTP interceptor signature, `ErrorHandler` contract.
  - Success: CONNECT event order is received→response(200)→passthrough(false)→closed; failed target emits response(502 where applicable), terminal error once, closed once; two concurrent H2 streams share the same non-empty connection ID; reconnects get different IDs; tests pass under `-race`. Full detail: plan.md §Step F6.

- [ ] **F7 — Intercept WebSocket handshakes through HTTPInterceptor (depends on F1, F3, F5,
  F6).** Wrap the upgrade request/response in the ordinary `HTTPInterceptor` while keeping
  frame relay.
  - In `relayConnForWS`, build a delegated-invoker closure that lazily dials upstream, performs `websocket.DialWithPreparedRequestAndNetConn`, and retains its websocket conn. Run `cfg.httpInt` around the request/invoker exactly once — request mutation affects the upstream handshake, response mutation affects the downstream handshake.
  - If the interceptor returns a non-101 response or short-circuits without invoking, write that response downstream, close any opened upstream conn, and do NOT relay. On error/nil response, close resources and propagate through lifecycle. Preserve bounded headers/body, Connection/Upgrade sanitization, frame limits, cancellation, and existing `WebsocketInterceptor` behavior. Use the F6 connection context/ID and F1 dialer in eager and lazy modes.
  - Do Not Modify: `WsFrame` API or frame payload interception behavior.
  - Success: interceptor request/response header mutations are observed by origin/client; a synthetic 403 never dials origin and starts no frame relay; a successful `ping`→`pong` still relays; cancellation releases buffers; existing WebSocket `-race` tests pass. Full detail: plan.md §Step F7.

- [ ] Run `gofmt -l .`, `go vet ./...`, `go test ./...`, `go test -race ./...` across the fork
  after F5–F7; all clean before `MITM-FORK-03.md` (publish).
