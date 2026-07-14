# mitmproxy-go Migration — Proxify Phase 8: Compatibility Gates and Logger Drain

**Repository:** Proxify (this working directory). Authoritative spec:
`planning/mitmproxy-go-migration/plan.md` Steps P11–P15. The candidate now serves both
listeners. These are mostly test-only tasks (extend root E2E); make production changes only for
observed regressions. Every network test binds `127.0.0.1:0` with bounded contexts/channels —
no `time.Sleep` as the sole synchronization.

- [x] **P11 — Policy compatibility (depends on P10).** Extend root E2E to cover HTTP and HTTPS
  request DSL, response DSL, request/response match-replace, callback `Set`/`Get`, logger
  export, CONNECT request/response visibility, proxify static root and `/cacert`, and regex
  passthrough. CONNECT must have one flow id, the inner request a different flow id, both sharing
  the connection id; passthrough carries bytes opaquely and produces NO inner HTTP callback/log
  entry. Do Not Modify: logger on-disk schema, DSL library, transports, shutdown. Success: all
  listed cases pass under `-race`. Full detail: plan.md §Step P11.

  **Done (2026-07-13):** Added `proxy_compat_test.go` with 8 E2E tests over the candidate serving
  core (`Proxy.Run`): `TestCompatDSLMatchExport` (http+https subtests: request+response DSL drive
  a `.match` logger export), `TestCompatMatchReplace` (request `X-Old: old`→`new` header and
  response `old`→`new` body, client-visible over MITM), `TestCompatConnectVisibleInLoggerExport`
  (exactly one CONNECT export entry with 200 + separate inner GET), `TestCompatConnectAndInnerFlowIDs`
  (distinct flow ids, shared connection id), `TestCompatStaticRoot` (banner page), and two
  passthrough tests proving opaque h2 with the origin cert and **zero** inner callback/log entries.
  `/cacert` and callback `Set`/`Get` remain covered by existing `TestCharacterizeCacert` and
  `TestCharacterizeFlowContextSharedAcrossCallbacks`. On-disk assertions poll with a deadline
  (async logger + no-op Stop until P16).

  **Two observed regressions fixed (allowed by "production changes only for observed regressions";
  neither touches the Do-Not-Modify list):**
  1. `syntheticConnectRequest` (mitmproxy_adapter.go) had a nil `Body`, so every CONNECT panicked
     when a request DSL (`util.HTTPRequestToMap` reads `req.Body`) or request match-replace
     (`MatchReplaceRequest` closes `req.Body`) was configured while intercepting HTTPS. Fixed by
     using `http.NoBody`, mirroring `syntheticConnectResponse`.
  2. `MatchReplaceRequest` (proxy.go) rebuilt the request via `http.ReadRequest`, which drops the
     URL scheme/host for origin-form requests; the candidate transport routes off `req.URL`, so
     match-replace broke routing (EOF). Fixed by preserving the pre-rewrite scheme/host when the
     rewrite did not supply its own.

  Verified: `go test -race .` and `go vet ./...` clean.

- [x] **P12 — HTTP/1 and HTTP/2 protocol matrix (depends on P10).** Add table-driven
  `TestProtocolMatrix` for H1→H1, H1→H2 TLS, H2→H2, H2→H1 TLS, asserting downstream callback
  `req.Proto` and upstream origin protocol separately. Add two concurrent H2 streams (distinct
  `FlowContext.ID`, one `ConnectionID`). A streaming origin flushes `part1`, blocks, then
  `part2`; the client observes `part1` before release and trailer `X-End: done` after EOF.
  Cancel a `/cancel` stream while `/ok` stays blocked — the canceled request ends with
  cancellation/RST_STREAM and `/ok` returns 200 with no new downstream connection. Include h2c
  prior knowledge if the listener harness supports it. Use channels `part1Seen`, `releasePart2`,
  `cancelStarted`, `okStarted`, each wait with a 2-second timeout + cleanup. Do Not Modify:
  DSL/logger formats, WebSocket, CLI, HTTP/3 deps. Success: all pairs + isolation + streaming +
  trailers + cancellation pass under `-race`. Full detail: plan.md §Step P12.

  **Done (2026-07-13):** Added `proxy_protocol_test.go` with four E2E tests over the candidate
  serving core (`Proxy.Run`):
  - `TestProtocolMatrix` — table-driven H1→H1, H1→H2 TLS, H2→H2, H2→H1 TLS. Downstream protocol
    is read from the intercepted inner request's `req.Proto` (via `OnRequestCallback`), upstream
    from the origin's echoed `X-Origin-Proto`; the two are asserted independently. Verified
    downstream H2 through the MITM leaf negotiates (probe: inner proto `HTTP/2.0`). h2c prior
    knowledge is a documented-skip subtest: `Proxy.Run` serves a plain `http.Server` with no
    `h2c` handler, so downstream h2c prior knowledge is not offered by the listener harness.
  - `TestConcurrentH2StreamsShareConnection` — a warm-up pools one downstream H2 connection, then
    two concurrent GETs block at the origin until both arrive (simultaneously in flight). Asserts
    both are `HTTP/2.0`, have distinct non-empty `FlowContext.ID`, and share one `ConnectionID`.
  - `TestH2StreamingAndTrailers` — H2→H2 streaming origin; client reads `part1` and signals
    before the test releases `part2`, proving the serving core streams (not buffers); body is
    `part1part2` and trailer `X-End: done` survives to EOF.
  - `TestH2StreamCancellationIsolation` — `/ok` and `/cancel` multiplex on one warmed connection;
    canceling `/cancel`'s context ends it with `context.Canceled` while `/ok` still returns 200
    `hello`, and only one distinct downstream `ConnectionID` is observed (no new connection).

  **No production changes** (allowed only for observed regressions; none observed). One behavior
  was investigated and confirmed *not* a regression: on the default (logging) path the streaming
  test buffers, because `pkg/logger` snapshots the first `responseSnapshotPrefix` (4 KiB) of the
  response body — `io.CopyN` blocks until 4 KiB or EOF, deferring `part1` past release. That
  buffering lives in the logger (Do Not Modify) and predates the migration, so the streaming test
  runs the callback path (no-op `OnRequest`/`OnResponse`) to isolate serving-core streaming, which
  streams correctly (part1 at ~0.1s, before release). The origin release fallback (8s) is longer
  than the 2s `part1Seen` wait so a real buffering regression fails the wait rather than being
  masked.

  Verified: `go test -race .` and `go vet ./...` clean.

- [x] **P13 — DNS policy, route rotation, TLS modes end-to-end (depends on P10, P6, P7).**
  Through the candidate: DNS mapping `mapped.test → 127.0.0.1` reaches a local origin without
  public DNS; deny `127.0.0.0/8` rejects before the origin while a matching allow permits; four
  requests with `rotateEvery=2` to two HTTP proxies then two SOCKS5 proxies assert A,A,B,B
  independently; repeat for standard TLS and named profile `chrome_120` asserting valid origin
  request, `response.Request` linkage, and non-empty negotiated TLS/HTTP protocol; 50 concurrent
  fingerprint requests under `-race` with no shared conversion-map/body race. Expected values:
  proxy ID headers `[A,A,B,B]`; denied-origin hit counter 0; `mapped.test` hit counter 1. Do Not
  Modify: candidate fork APIs, CLI flags, TLS profile registry. Full detail: plan.md §Step P13.

  **Done (2026-07-13):** Added `proxy_dnsroute_test.go` with five E2E tests over the candidate
  serving core (`Proxy.Run`), all binding `127.0.0.1` with ephemeral ports and no public network:
  - `TestDNSMappingReachesLocalOriginEndToEnd` — `ListenDNSAddr` + `DNSMapping=mapped.test:127.0.0.1`
    starts Proxify's tinydns; a client GET to `http://mapped.test:<port>/` reaches a local origin
    exactly once (hit counter 1, Host carries `mapped.test`). The reserved `.test` TLD cannot resolve
    publicly, so the hit can only have come through the mapping. New helpers `freeUDPAddr` (ephemeral
    UDP port in `:port` form) and `waitForDNSMapping` (polls the resolver directly so the counted
    request is sent only once tinydns is live — deterministic, no startup race).
  - `TestDenyAllowPolicyEndToEnd` — deny `127.0.0.0/8` rejects before the origin (hit counter 0);
    the matching allow permits it (hit counter 1, 200). The allow subtest is the differential that
    proves the deny result isn't a false pass.
  - `TestUpstreamRouteRotationEndToEnd` — four sequential requests at `rotateEvery=2` over two HTTP
    upstreams, then two SOCKS5 upstreams; cumulative per-route counts after each request
    (`[1,0],[2,0],[2,1],[2,2]`) establish the exact `A,A,B,B` order independently per listener
    (equivalent to the spec's per-request proxy-ID sequence; SOCKS tunnels are opaque so a response
    header can't carry the ID — cumulative counts assert order without touching the fork fixtures).
  - `TestTLSModesEndToEnd` — standard transport and named profile `chrome_120` to an HTTPS (H2)
    origin: each asserts origin-saw-valid-request (200 + echoed `X-Origin-Proto`), `Response.Request`
    linkage (survives the fhttp↔net/http conversion in fingerprint mode), and non-empty negotiated
    TLS + HTTP protocol on the client↔MITM leaf.
  - `TestFingerprintConcurrentRequestsEndToEnd` — 50 concurrent `chrome_120` requests through the
    serving core, all 200, no shared conversion-map/body race under `-race`.

  **No production changes** (allowed only for observed regressions; none observed). DNS mapping,
  allow/deny, route rotation, and both TLS modes all flow correctly through `Proxy.Run` as built.

  Verified: `go test -race .` (full root package, 8.1s) and `go vet ./...` clean.

- [ ] **P14 — SOCKS listener and WebSocket behavior (depends on P10 and fork F7).** Through the
  HTTP proxy and the SOCKS5 listener, test HTTP and HTTPS interception callbacks, request
  mutation, response mutation, and shared policy output. A local WS origin requires request
  header `X-Handshake: changed`, sends response header `X-Origin: yes`, and echoes `ping`→`pong`;
  a response callback adds `X-Response: changed` (client sees both headers); a callback synthetic
  403 rejects the upgrade with origin hit count 0; Stop/connection cancellation closes the WS
  relay with no leaked goroutines (full Stop is P16). Add `NewWebSocketOrigin` to
  `internal/testutil/proxytest` if absent; reuse the candidate's websocket/gorilla-compatible
  client (do not add a second server framework). Do Not Modify: frame payload API, upstream
  transport selection, logger formats. Full detail: plan.md §Step P14.

  **BLOCKED (2026-07-14) — left unchecked: two required scenarios fail on a fork defect I cannot
  fix from the Proxify repo.** Added the fixture and tests; 2 of 4 scenarios pass, 2 are skipped
  pending a fork fix.

  Landed:
  - `internal/testutil/proxytest/websocket.go` — new `NewWebSocketOrigin(t, WSConfig)` echo origin
    (ws:// or wss://) built on the candidate's gorilla-compatible `github.com/josexy/websocket`
    (no second server framework). It can require an upgrade-request header, add a 101 response
    header, echo `ping`→`pong`, and exposes `Hits`/`Exits` atomics for hit-count and teardown
    assertions.
  - `proxy_websocket_test.go` — 4 E2E tests over the serving core (`Proxy.Run`) with both an HTTP
    proxy and the native SOCKS5 listener:
    - **PASS `TestListenerSharedPolicy`** — HTTP proxy and SOCKS5 run the *same* policy: for both a
      plain-HTTP origin and a MITM'd HTTPS origin, a request-header mutation reaches the origin and
      a response-header mutation reaches the client, and the request/response callbacks each fire.
    - **PASS `TestWebSocketCallbackRejectionNeverReachesOrigin`** — a request callback that rejects a
      WS upgrade short-circuits before any origin dial (origin hit count 0) on both listeners. This
      is Proxify's callback-level form of the spec's "synthetic 403 rejects upgrade, origin hit
      count zero": the public callback API rejects by returning an error, stopping the pipeline
      before the upstream WebSocket dial.
    - **SKIP `TestWebSocketInterception`** (X-Handshake→origin, X-Origin+X-Response→client, ping→pong)
      and **SKIP `TestWebSocketRelayTeardownOnClientClose`** (client-close tears down the relay, no
      goroutine leak) — both need a *successful* MITM'd WS relay, which panics in the fork.

  Fork defect (root cause): in `github.com/peterjmorgan/mitmproxy-go` v1.2.0,
  `handleTunnelRequest` sets `var dstConn net.Conn = connCtx.remote` (mitm.go:1270). Under
  `WithLazyUpstreamMITM` (which the adapter uses) `connCtx.remote` is an un-dialed
  `*remoteClientConn`, so `dstConn` is a non-nil interface wrapping a typed-nil pointer.
  `relayConnForWS`'s invoker then reads `if upstream == nil` (mitm.go:1856) as false and writes the
  upstream handshake to the nil conn → nil-pointer panic, instead of lazily dialing. The fork's own
  tests miss this: they cover eager+WS+success and lazy+WS+reject (reject never invokes the upstream
  dial). This contradicts fork step **F7**'s "successful `ping`→`pong` relays in eager and lazy
  modes" success criterion, so the fix belongs to the fork track (patch `relayConnForWS` to treat an
  un-dialed remote as needing a lazy dial, then re-pin the fork), not Proxify. `t.Skip` on the two
  tests names the exact fix so they flip to active once the fork is re-pinned.

  No Proxify production changes: the only sound fix is in the fork; dropping `WithLazyUpstreamMITM`
  to sidestep the panic would revert the P9/P10 TLS-termination model and is not acceptable.

  Verified: `go test -race .` (full root package, ~9.8s) and `go vet ./...` clean with the two
  fork-blocked tests skipped. Left `- [ ]` because the successful-relay and teardown scenarios
  (spec's scenarios 15–16) do not yet pass.

- [ ] **P15 — Make logger shutdown drain safely (depends on P11).** In `pkg/logger/logger.go`
  add a producer/close mutex, `closeOnce`, and a worker `WaitGroup`. `LogRequest`/`LogResponse`
  either enqueue while open or return a new package error `ErrLoggerClosed`. `Close` marks closed
  while excluding producers, closes `asyncqueue` exactly once, waits for `AsyncWrite` to drain,
  then closes `sWriter` exactly once; hold the producer mutex only through the send/closed
  decision, never while draining. Preserve queue size, `Store` behavior, log formats, ordering,
  and the public `Close()` signature; do not silently drop accepted items. Do Not Modify:
  serialization schema, `MaxSize` truncation, Elastic/Kafka implementations. Success: 100 numbered
  transactions all reach a fake `Store` in order before `Close` returns; 20 concurrent producers
  racing `Close` return nil or `ErrLoggerClosed` and never panic; 20 repeated `Close` calls all
  return; `go test -race ./pkg/logger/...` passes. Full detail: plan.md §Step P15.

- [ ] Run `go test ./...`, `go test -race ./...`, `go vet ./...`; all clean before Proxify
  Phase 9.
