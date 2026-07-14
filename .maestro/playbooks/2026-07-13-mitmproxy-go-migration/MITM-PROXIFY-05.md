# mitmproxy-go Migration — Proxify Phase 5: Interceptor and Transports

**Repository:** Proxify (this working directory). Authoritative spec:
`planning/mitmproxy-go-migration/plan.md` Steps P4–P7 — read each step before its task; line
numbers there are a pre-work snapshot and drift after P2–P4 edit `proxy.go`, so locate code by
symbol name. Martian still owns `Run` in this phase. All new transports must be concurrent-safe
and preserve fastdialer policy. Every network test binds `127.0.0.1:0`.

- [x] **P4 — Extract the protocol-neutral unified interceptor (depends on P2).** New
  `interceptor.go` defines private `type delegatedRoundTripper func(*http.Request) (*http.Response, error)`
  and `func (p *Proxy) interceptHTTP(ctx context.Context, flow *FlowContext, req *http.Request, next delegatedRoundTripper) (*http.Response, error)`.
  - Exact order: proxy-local short-circuit → request policy/callback → `next` → ensure non-nil body and `resp.Request` = effective req → response policy/callback → return. Extract `modifyRequest(req,flow)` and `modifyResponse(resp,flow)` preserving DSL, match/replace, remove-br, logging, redirects, and callback short-circuit. Replace `hijackNServe` with `serveProxyLocal(req) *http.Response` using an `httptest` recorder for `proxify`, `proxify:80`, `proxify:443`, and the bound `listenAddr`. Stream bodies unless MatchReplace/logger config explicitly buffers — do NOT add unconditional `io.ReadAll`. Keep Martian `ModifyRequest`/`ModifyResponse` thin and operational until P17.
  - Do Not Modify: listener serving, upstream transport construction, logger format.
  - Success: ordered markers request-callback → transport → response-callback; synthetic proxify `/cacert` never invokes transport and `response.Request` is the effective req; nil Request/body is repaired; match-replace mutates `old`→`new` preserving linkage; current Martian E2E still passes. Full detail: plan.md §Step P4.
  - **Done (2026-07-13):** Added `interceptor.go` with `delegatedRoundTripper`, `interceptHTTP` (fixed 6-step order), extracted `modifyRequest`/`modifyResponse` (protocol-neutral; UserData now stored on `FlowContext` key `user-data`), `serveProxyLocal` (httptest recorder), and `isProxyLocal`. `ModifyRequest`/`ModifyResponse` in `proxy.go` are now thin Martian bridges delegating to the shared policy; `hijackNServe` is a thin hijack-and-write shim over `serveProxyLocal`. No unconditional `io.ReadAll` added — bodies stream; only existing MatchReplace/logger buffering runs. New `interceptor_test.go` covers all four success criteria (ordering, proxy-local short-circuit + `resp.Request` linkage, nil body/Request repair, match-replace old→new + linkage). `go test ./...`, `go test -race ./...`, `go vet ./...` all clean; existing Martian characterization E2E still passes.

- [ ] **P5 — Correct the direct standard transport (depends on P1).** Move transport code to
  `transport.go`. Add `newStandardTransport(dialer *fastdialer.Dialer) *http.Transport` with the
  current pooling/TLS-minimum/insecure behavior, a `DialContext` calling `dialer.Dial`, and
  `ForceAttemptHTTP2 = true` (the current direct branch omits both, silently bypassing
  fastdialer). `getStandardRoundTripper` uses it for direct mode; leave proxy branches unchanged
  until P6. Add private `closeIdleRoundTripper(http.RoundTripper)` using interface
  `{ CloseIdleConnections() }`.
  - Do Not Modify: upstream proxy branches or the tls-client adapter.
  - Success: a local mapped hostname reaches a local TLS H2 origin and the origin sees HTTP/2; a denied local CIDR errors before the origin handler runs; `response.Request` equals the original; direct H1/H2 and fastdialer allow/deny tests pass under `-race`. Full detail: plan.md §Step P5.

- [ ] **P6 — Request-based, concurrent HTTP/SOCKS upstream routing (depends on P5).** Define
  private `routeSelector` (mutex, routes, `rotateEvery`, index, used) whose constructor rejects
  an empty route list and `rotateEvery <= 0`; `Next() string` advances modulo route count after
  exactly `UpstreamProxyRequestsNumber` selections and keeps the route across retries/dials
  within one RoundTrip. Define `routedRoundTripper` holding one `http.RoundTripper` per route
  that selects once then delegates. Build HTTP route transports with a fixed `Proxy` URL and
  fastdialer `DialContext` to the proxy; build SOCKS5 route transports with context-aware SOCKS
  dialers whose forward dial uses fastdialer. HTTP list takes precedence over SOCKS; direct uses
  P5. Remove use of `projectdiscovery/roundrobin` from the new path (keep the module until P17).
  - Do Not Modify: TLS-profile transport or listeners.
  - Success: routes `[proxyA,proxyB]`, `rotateEvery=2` produce A,A,B,B,A under 100 concurrent calls when sorted by selector sequence; two local proxies observe exactly requests 1-2 and 3-4; a canceled request stays on the selected route; invalid URL / zero rotation fails `NewProxy`; passes under `-race` with no fallback. Full detail: plan.md §Step P6.

- [ ] **P7 — Harden TLS-profile transport and route selection (depends on P6).** Build one
  tls-client `HttpClient` per route (or one direct client) selected via the P6 `routeSelector`
  once per RoundTrip. Always use `tls_client.WithProxyDialerFactory` returning a
  `proxy.ContextDialer` backed by fastdialer (direct, or dialing the HTTP/SOCKS proxy via
  fastdialer while preserving target hostname/auth). Conversion copies request context, Host,
  body, ContentLength, TransferEncoding, trailers, and headers WITHOUT aliasing mutable maps;
  response conversion sets `Request` to the effective net/http request and copies trailers.
  Prove tls-client clients are safe for concurrent `Do`; if not, add a per-route client POOL
  (never a global request mutex, which would serialize H2 streams). Implement
  `CloseIdleConnections` where supported.
  - Do Not Modify: profile registry `pkg/tlsprofile` or CLI flags.
  - Success: profile `chrome_120` reaches a local TLS origin with non-empty negotiated protocol; context cancellation reaches the tls-client request while a sibling succeeds; trailers `X-End: done` and `response.Request` preserved; HTTP and SOCKS route lists rotate A,A,B,B at count 2; fastdialer denial blocks direct and proxy sockets; 50 concurrent requests pass under `-race`. Full detail: plan.md §Step P7.

- [ ] Run `go test ./...`, `go test -race ./...`, `go vet ./...`; all clean before Proxify
  Phase 6.
