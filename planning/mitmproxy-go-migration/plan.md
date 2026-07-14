# Proxify mitmproxy-go Migration Plan

## Overview

This plan replaces Proxify's archived Martian-based interception core with a pinned,
controlled fork of `github.com/josexy/mitmproxy-go`, while preserving Proxify's
request/response semantics and adding semantic HTTP/2 interception. Work spans two
repositories:

- **Fork repository:** `github.com/peterjmorgan/mitmproxy-go`, based exactly on audited
  upstream commit `1c9f0671f96d897fd57b0966a64cd7721718cf0a`.
- **Proxify repository:** this repository, on branch `migrate-mitmproxy-go`.

The fork remains backward-compatible by default. Its new behavior is opt-in: a
context dialer, passthrough predicate, shared RoundTripper, lazy-upstream MITM mode,
connection lifecycle events, stable connection identity, and HTTP-intercepted
WebSocket handshakes. Proxify then supplies a protocol-neutral interceptor based only
on `context.Context`, `*http.Request`, and `*http.Response`.

### Key Decisions

1. `WithLazyUpstreamMITM`, `WithContextDialer`, `WithPassthroughFunc`,
   `WithRoundTripper`, and `WithConnectionLifecycleHook` are opt-in fork options;
   existing eager behavior remains the fork default.
2. The fork assigns an opaque, process-unique connection ID and exposes
   `ConnectionIDFromContext(context.Context) (string, bool)`. Proxify consumes it only
   in its candidate adapter. Policy code remains independent of fork types.
3. A single injected `http.RoundTripper` is shared by H1 and H2. Its contract requires
   concurrent use safety. The fork never closes an injected transport; its owner does.
4. The lifecycle API uses immutable events and a non-blocking-per-connection callback;
   there is no global event lock. Event kinds are CONNECT received, CONNECT response,
   passthrough decision, terminal error, and connection closed.
5. In lazy mode, passthrough still dials before relaying, but intercepted HTTP/TLS does
   not create a speculative origin connection. SOCKS5 sends success after protocol
   validation for intercepted traffic; an actual upstream failure becomes an HTTP 502
   or TLS-tunnel termination. Passthrough SOCKS5 retains dial-before-success behavior.
6. Proxify's upstream precedence remains HTTP proxy list, then SOCKS5 proxy list, then
   direct. Rotation is concurrency-safe and advances once per request, not per retry or
   TCP connection.
7. `tls-client` gets a `ProxyDialerFactory` backed by Proxify's `fastdialer`; one client
   is built per upstream route and selected per request. This preserves named profiles,
   DNS/network policy, and proxy rotation without mutating a shared client.
8. Existing Martian serving remains operational while FlowContext, certificates,
   transport, and interceptor code are extracted. The candidate adapter is integration
   tested directly before the default serving path changes. Martian is removed only
   after the compatibility matrix passes.
9. The fork handoff is immutable: Proxify must depend on a published commit SHA (and
   resulting Go pseudo-version), never a branch and never a final `replace` directive.
10. HTTP/3, QUIC, UDP interception, TUN, CONNECT-UDP, and MASQUE remain out of scope.

## Blueprint

### Components

**Fork repository**

- Dial abstraction in `option.go`, `proxy_dialer.go`, and `mitm.go`.
- Passthrough predicate in `option.go`, `runtime_config.go`, and
  `shouldPassthroughRequest` in `mitm.go`.
- Shared semantic transport in `interceptor.go`, `runtime_config.go`, and
  `roundTripWithContext` in `mitm.go`.
- Lazy certificate/ALPN and connection bootstrap in `mitm.go` and
  `keycert_pool.go`.
- Connection identity/events in `mitm.go` and a new `lifecycle.go`.
- WebSocket handshake interception in `relayConnForWS` in `mitm.go`.

**Proxify repository**

- `FlowContext` in a new `flow_context.go`.
- Protocol-neutral policy pipeline extracted from `ModifyRequest` and
  `ModifyResponse` in `proxy.go` into a new `interceptor.go`.
- Certificate file access and stdlib CA generation in `pkg/certs/mitm.go`.
- Concurrent route selection and transports in a new `transport.go`.
- Candidate boundary adapter in a new `mitmproxy_adapter.go`.
- HTTP and SOCKS listener ownership and idempotent shutdown in `proxy.go`.
- Local H1/H2/WebSocket/upstream-proxy fixtures in `internal/testutil/proxytest` and
  end-to-end tests in the root package.

### Dependency Graph

```text
Fork F1 context dialer ───────────────┐
Fork F2 passthrough predicate ────────┤
Fork F3 injected RoundTripper ────────┼─> F5 lazy MITM ─> F6 lifecycle/identity
Fork F4 certificate issuance refactor┘                     │
Fork F3 + F5 ──────────────────────────────────────────────> F7 WebSocket handshake
F1..F7 ─> F8 fork verification/published immutable SHA ──────────────┐
                                                                    │
Proxify P1 baseline fixtures                                        │
P2 FlowContext ─> P4 unified interceptor                            │
P3 certificate API ─────────────────────────────────────────────────┤
P5 standard transport ─> P6 proxy routes ─> P7 TLS-profile routes   │
F8 + P3 + P4 + P7 ─> P8 toolchain and immutable dependency pin ─> P9 adapter
P9 ─> P10 listener switch ─> P11..P14 compatibility suites ─> P15 logger drain
P11..P15 ─> P16 shutdown ─> P17 Martian removal ─> P18 release verification
```

F1-F4 and P1-P3 can proceed in parallel. P5-P7 can proceed after P1 without waiting
for the fork. P8 is the strict repository handoff: record the fork commit, push it,
resolve it through the Go module proxy/direct VCS, and commit the resulting pseudo-
version before importing fork APIs in Proxify.

### Integration Approach

The fork's `HTTPInterceptor` calls Proxify's adapter. The adapter gets the stable
connection ID, creates a new `FlowContext` for each ordinary request/H2 stream, and
calls `Proxy.interceptHTTP`. That method handles proxy-local routes, request policy,
the injected upstream transport, response linkage, and response policy. CONNECT
events use one separate FlowContext per CONNECT, stored only for the event lifetime
and removed on connection close. WebSocket upgrade requests use the same HTTP
interceptor before the fork starts frame relay.

## State-Space Analysis

### Leaf Certificate Cache

- **NEW:** no host/SNI key exists; generate a leaf from CONNECT authority/SNI, insert,
  and return it.
- **CHANGED:** CA/key or requested identity changes only across a new handler; cache is
  handler-owned, so no in-place mutation is supported.
- **UNCHANGED:** normalized SNI/authority hits the cache and returns the existing cert.
- **REMOVED:** LRU capacity eviction or expiry removes the entry; the next request is
  handled as NEW.
- **ERROR:** key generation, invalid authority, or signing failure returns a handshake
  error and does not cache a partial certificate.
- **TIMEOUT:** downstream handshake context/deadline aborts the handshake; a completed
  certificate may remain valid in cache, but no half-built entry is published.
- **RECONNECT:** a new downstream connection reuses a valid cached leaf, but gets a new
  connection ID and lifecycle.

### Connection / Flow Lifecycle

- **NEW:** connection bootstrap assigns one connection ID; CONNECT assigns one event
  flow; every H1 request or H2 stream gets a distinct flow ID.
- **CHANGED:** lifecycle progresses received -> response selected -> passthrough/intercept
  -> closed, with an optional terminal error before closed.
- **UNCHANGED:** all streams on a connection observe the same connection ID; events are
  immutable after emission.
- **REMOVED:** closed event removes Proxify's CONNECT flow entry and active-connection
  tracking.
- **ERROR:** terminal error fires at most once per connection error path and is followed
  by closed; ordinary per-stream RoundTrip errors do not serialize or close siblings.
- **TIMEOUT:** handshake/dial/request cancellation reports the appropriate error and
  closes only the affected stream unless the connection itself is unusable.
- **RECONNECT:** a fresh TCP/SOCKS connection receives a fresh connection ID and no
  values from the prior FlowContext.

### Proxy Route Selection

- **NEW:** selector starts at route zero with request count zero.
- **CHANGED:** after exactly `UpstreamProxyRequestsNumber` selections, advance modulo
  route count.
- **UNCHANGED:** retries/dials within one RoundTrip keep the selected route.
- **REMOVED:** runtime route removal is unsupported; options are immutable after
  `NewProxy`.
- **ERROR:** invalid route fails construction; a route failure is returned and does not
  silently fall back to a different proxy.
- **TIMEOUT:** context timeout applies to the selected route and does not advance it a
  second time.
- **RECONNECT:** transport connection reuse does not affect request-based rotation.

### Shutdown

- **NEW:** `NewProxy` owns resources; `Run` transitions listeners to serving.
- **CHANGED:** first `Stop` transitions running resources to closing then closed.
- **UNCHANGED:** repeated public `Stop()` waits for the same completion and performs no
  work; private `stop()` returns the stored result to tests/internal callers.
- **REMOVED:** listeners, active candidate connections, idle transport connections,
  TinyDNS, and logger queue are closed in prescribed order.
- **ERROR:** all close errors are joined; one failure does not skip later cleanup.
- **TIMEOUT:** HTTP graceful shutdown uses a bounded context, then candidate cleanup
  force-closes remaining connections.
- **RECONNECT:** `Proxy` is not restartable after Stop; callers construct a new Proxy.

## Implementation Steps

> **Line numbers are a pre-work snapshot, not a contract.** Fork line references are
> relative to base commit `1c9f067`; Proxify line references are relative to the current
> `migrate-mitmproxy-go` HEAD before any step runs. Earlier Proxify steps (P2, P3, P4)
> rewrite `proxy.go` heavily, so every later step's `proxy.go:NNN` citation will have
> drifted. Always locate code by the named symbol first (functions/types are listed in
> each step) and treat the line range only as a starting hint. Re-read the cited file
> before editing.

### Step F1: Generalize outbound dialing in the fork

**Repository:** fork. **Dependencies:** audited base commit. **Complexity:** moderate.

```markdown
Context: Work in github.com/peterjmorgan/mitmproxy-go at base 1c9f067. Existing
WithDialer accepts only *net.Dialer and proxy_dialer.go resolves destinations itself.
Objective: make every outbound path accept a cancellation-aware custom dialer without
changing WithDialer behavior.

Requirements:
- Define `type ContextDialer interface { DialContext(context.Context, string, string) (net.Conn, error) }` and `WithContextDialer(ContextDialer) Option` in option.go.
- Keep `WithDialer(*net.Dialer)` and default timeout behavior. Last supplied dialer option wins.
- Change proxyDialer/NewProxyDialer internals to use ContextDialer. Direct, eager TLS,
  lazy TLS, passthrough, HTTP/HTTPS proxy, and SOCKS proxy paths must call it.
- Do not resolve the destination before invoking a custom dialer. For an HTTP proxy,
  dial the proxy through the custom dialer and preserve the target hostname in CONNECT.
- Preserve context cancellation/deadlines; do not add background contexts.

Files to Read First:
- option.go:33-89, 231-248
- proxy_dialer.go:1-440, especially NewProxyDialer and dialWithMetadata
- mitm.go:194-263 and 502-628
- proxy_dialer_test.go:1-430 and socks5_test.go:210-255

Functions to Create or Modify:
- ContextDialer and WithContextDialer in option.go
- NewProxyDialer/newConfiguredProxyDialer and proxyDialer.dialWithMetadata
- newRuntimeConfigStateFromOptions/buildRuntimeConfig only as needed to carry the dialer

Pattern to Follow: preserve the OptionFunc pattern at option.go:244 and context deadline
handling at proxy_dialer.go:147-175.

Integration: existing *net.Dialer implements ContextDialer. proxyDialer must remain the
single outbound dial boundary used by mitm.go.

Testing:
- Custom recording dialer receives `mapped.test:443` verbatim and exactly once; arrange
  for net.DefaultResolver lookup of that name to fail to prove no pre-lookup occurs.
- HTTP proxy fixture receives CONNECT target `origin.test:443`, while the recording
  dialer receives only the local proxy address.
- Cancel a context before DialContext and assert context.Canceled and no leaked conn.
- Existing WithDialer, HTTPS proxy, SOCKS5, and `go test -race ./...` pass.

Do Not Modify: TLS fingerprint generation, certificate issuance, passthrough matching,
or interceptor behavior.

Success: both old and new dialer options work; go test -race ./... and go vet ./... pass.
```

### Step F2: Add the passthrough predicate

**Repository:** fork. **Dependencies:** none beyond base. **Complexity:** simple.

```markdown
Context: include/exclude host matching is currently implemented by
shouldPassthroughRequest in mitm.go:631-648.
Objective: add an opt-in exact predicate so Proxify can retain arbitrary regex rules.

Requirements:
- Define `type PassthroughFunc func(hostport string) bool` and
  `WithPassthroughFunc(PassthroughFunc) Option` in option.go.
- Carry it in runtimeConfigState/runtimeConfig snapshots so each connection has a stable
  configuration.
- In shouldPassthroughRequest, a non-nil predicate is authoritative and receives the
  normalized host:port. Return reason `passthrough_predicate`; false means intercept.
- When nil, preserve include/exclude precedence and defaults byte-for-byte.

Files: option.go:33-72, runtime_config.go:60-210, runtime_config_setters.go,
mitm.go:611-648, runtime_config_test.go:144-181, domain_tree_test.go.
Functions: add WithPassthroughFunc; modify newRuntimeConfigStateFromOptions,
runtimeConfigState.clone/buildRuntimeConfig, and shouldPassthroughRequest.
Pattern: use slices.Clone/snapshot semantics in runtime_config.go:180-205.
Integration: all ServeHTTP and ServeSOCKS5 decisions already converge at
shouldPassthroughRequest.
Testing:
- Predicate sees `api.example:443`, returns true, and no TLS interception occurs.
- Predicate false overrides an exclude-host match and intercepts.
- Nil predicate retains exclude then include behavior.
- Concurrent connections while runtime config changes retain their captured predicate.
Do Not Modify: dialing, certificate logic, or public host wildcard setters.
Success: predicate behavior and existing host-filter tests pass under race detector.
```

### Step F3: Inject a shared semantic RoundTripper

**Repository:** fork. **Dependencies:** F1. **Complexity:** moderate.

```markdown
Context: roundTripWithContext at mitm.go:1740-1790 always delegates to the
per-connection singleConnTransport.
Objective: allow an owner-supplied concurrent RoundTripper for both downstream H1 and H2.

Requirements:
- Add `WithRoundTripper(http.RoundTripper) Option`; nil means existing behavior.
- Snapshot the RoundTripper into runtimeConfig. Document that it must be concurrent-safe
  and remains owned/closed by the caller.
- roundTripWithContext selects injected transport first, otherwise connCtx.transport.
- Preserve request context/body/trailers and set `response.Request = req` when nil.
- Do not create or require connCtx.transport solely for an injected RoundTripper; eager
  default mode may continue constructing it until F5.
- H1 and serveHTTP2Handler must use the same selection path.

Files: option.go:474-568, runtime_config.go:60-210, mitm.go:598-604,
1740-1875, interceptor_test.go:71-105, transport_test.go:164-275.
Functions: add WithRoundTripper; modify runtime config builders and
roundTripWithContext; guard transport Close calls against nil.
Pattern: follow HTTPInterceptor snapshotting in runtime_config.go and response validation
at mitm.go:1775-1781.
Integration: the injected transport is passed as the final HTTPDelegatedInvoker, so
interceptor chains still wrap it.
Testing:
- Recording RoundTripper receives one H1 request and two concurrent H2 requests.
- Cancel one H2 request: it sees context.Canceled while sibling returns 200 `ok`.
- Request trailer `X-End: done` reaches the transport; response trailer returns intact.
- Cleanup does not call Close on an injected close-tracking transport.
Do Not Modify: WebSocket path, eager TLS fingerprinting, or passthrough.
Success: H1/H2 use the injected transport and all old transport tests pass with race.
```

### Step F4: Refactor leaf issuance into an authority-based helper

**Repository:** fork. **Dependencies:** none. **Complexity:** moderate.

```markdown
Context: initiateSSLHandshakeWithClientHello at mitm.go:926-966 clones origin subject
and SANs inline and writes serverCertPool.
Objective: establish one tested leaf issuance/cache helper that eager and lazy modes use.

Requirements:
- Add unexported `serverCertificate(ctx, serverName, authority string,
  template certificateIdentity) (tls.Certificate, error)` on mitmProxyHandler.
- Normalize cache key with SNI first, then CONNECT authority host. certificateIdentity
  contains subject, DNS names, and IPs; lazy callers may provide only authority/SNI.
- Reuse priKeyPool and serverCertPool; publish only fully built certificates.
- Replace the certificate cache's multiple-of-256 restriction with exact capacity. A
  configured capacity of 1 stores at most one leaf and 257 stores at most 257; preserve
  expiry and background cleanup.
- Existing eager path builds certificateIdentity from the origin certificate and calls
  the helper with unchanged validity behavior.

Files: mitm.go:310-348 and 816-974, keycert_pool.go:14-62,
keycert_pool_test.go:1-80, internal/cache/cache.go:40-103,
internal/cert/cert.go:200-290.
Pattern: preserve certificateCacheKey normalization at mitm.go:969-974 and cache setup
at keycert_pool.go:43-61.
Integration: replace the eager inline block immediately so the helper is not orphaned.
Testing:
- First call for `API.Example.COM` generates; second returns same DER and cache count.
- Empty SNI plus authority `127.0.0.1:443` yields an IP SAN.
- Signing error does not create a cache entry.
- Expired/evicted entry regenerates; concurrent first use produces valid certs without race.
- Capacities 1, 256, and 257 construct successfully and never exceed the exact bound.
Do Not Modify: ALPN selection, origin dialing, or public options.
Success: eager TLS integration tests remain unchanged and cache state cases pass.
```

### Step F5: Implement opt-in lazy-upstream MITM

**Repository:** fork. **Dependencies:** F1, F2, F3, F4. **Complexity:** complex.

```markdown
Context: Serve currently dials at mitm.go:533-600 before passthrough and coordinates
downstream TLS with an eager upstream uTLS handshake at 1035-1158.
Objective: in opt-in lazy mode, terminate downstream TLS/H1/H2 without opening origin;
leave the eager default untouched.

Requirements:
- Add `WithLazyUpstreamMITM() Option` and immutable runtime state.
- Refactor Serve so passthrough always dials and relays; eager mode preserves current
  dial-first path; lazy intercepted mode creates local/connCtx without remote conn.
- Lazy TLS GetConfigForClient calls F4 using SNI then CONNECT authority. Advertise h2
  only if client offered h2 and HTTP2 is enabled; include http/1.1 fallback. Never
  advertise a protocol the client did not offer.
- Lazy cleartext H1 and h2c prior knowledge use the injected RoundTripper. With no
  injected RoundTripper, lazily construct the existing per-connection transport so the
  fork remains independently usable.
- For intercepted SOCKS5, write success without speculative origin dial; passthrough
  retains dial-before-success. Use a zero bind address when no upstream socket exists.
- All nil remote/transport close paths must be safe.

Files: option.go, runtime_config.go, mitm.go:194-263, 502-663, 1035-1195,
1260-1305, 1793-1875; mitm_test.go:42-275; socks5_test.go:210-255.
Functions: modify Serve and handleTunnelRequest; add a small
`downstreamTLSConfig(ctx, capturedClientHello) (*tls.Config,error)` helper using F4.
Pattern: use existing handshake deadline handling at mitm.go:1084-1127 and H2 ServeConn
at 1149-1157.
Integration: F3 handles actual requests; WebSockets keep a dedicated lazy dial and are
completed in F7.
Testing:
- A counting dialer remains zero through CONNECT and downstream TLS handshake, then the
  injected transport returns 200.
- Client offers h2/http1: negotiated h2; offers only http1: negotiated http1; HTTP2
  disabled: http1.
- H2 client to H1-returning injected transport and H1 client to H2 response both succeed.
- Regex predicate passthrough dials once and carries opaque h2 TLS bytes.
- SOCKS intercepted handshake has zero dials until first HTTP request; dial failure is
  surfaced without panic.
Do Not Modify: eager ClientHello mirroring behavior or WebSocket interception semantics.
Success: lazy tests plus all eager tests pass with `go test -race ./...`.
```

### Step F6: Add stable connection identity and lifecycle events

**Repository:** fork. **Dependencies:** F5. **Complexity:** moderate.

```markdown
Context: ErrorHandler lacks CONNECT status/passthrough visibility and there is no robust
public identity shared by H2 stream contexts.
Objective: expose immutable per-connection identity/events without serializing streams.

Requirements:
- New lifecycle.go defines `type ConnectionEventKind uint8`, constants
  ConnectReceived, ConnectResponse, PassthroughDecided, TerminalError,
  ConnectionClosed; `type ConnectionEvent struct { Kind ConnectionEventKind;
  ConnectionID, Hostport string; Request *http.Request; StatusCode int;
  Passthrough bool; Err error }`; and `type ConnectionLifecycleHook func(context.Context, ConnectionEvent)`.
- Add WithConnectionLifecycleHook and
  `ConnectionIDFromContext(context.Context) (string,bool)`.
- Assign IDs from a package-level atomic uint64 formatted as decimal at connection
  bootstrap. Put the ID in every derived H1/H2/WebSocket request context.
- Emit CONNECT received only for HTTP CONNECT, then selected status before bytes are
  written; emit passthrough for HTTP and SOCKS; terminal error at most once per terminal
  connection path; closed exactly once. Existing ErrorHandler remains compatible.
- Invoke hooks synchronously in that connection's goroutine, without any package-global
  hook mutex; document hooks must return promptly.

Files: mitm.go:40-68, 194-296, 421-628, 1793-1835; runtime_config.go;
runtime_config_setters.go; metadata/metadata.go (read only unless context propagation
requires it); mitm_internal_test.go.
Pattern: use atomic.Pointer runtime snapshots at mitm.go:286-336 and sync.Once close
semantics at localClientConn.Close.
Integration: context accessor is usable inside HTTPInterceptor for every H2 stream.
Testing:
- CONNECT event order is received, response(200), passthrough(false), closed.
- Failed target emits response(502 where applicable), terminal error once, closed once.
- Two concurrent H2 streams return distinct request observations but the same non-empty
  ConnectionIDFromContext value.
- Two reconnects receive different IDs; passthrough event reports true.
Do Not Modify: metadata public API, HTTP interceptor signature, or ErrorHandler contract.
Success: event order and identity tests pass under race and existing error tests remain.
```

### Step F7: Intercept WebSocket handshakes through HTTPInterceptor

**Repository:** fork. **Dependencies:** F1, F3, F5, F6. **Complexity:** complex.

```markdown
Context: relayConnForWS at mitm.go:1559-1723 performs the upstream/downstream upgrade
before invoking only WebsocketInterceptor for frames.
Objective: wrap the upgrade request and response in the ordinary HTTPInterceptor while
retaining frame relay.

Requirements:
- In relayConnForWS, construct a delegated invoker closure that lazily dials upstream,
  performs websocket.DialWithPreparedRequestAndNetConn, and retains its websocket conn.
- Run cfg.httpInt around the request/invoker exactly once. Request mutation must affect
  the upstream handshake. Response mutation must affect the downstream handshake.
- If interceptor returns a non-101 response or short-circuits without invoking, write
  that ordinary response downstream, close any opened upstream conn, and do not relay.
- If it returns error/nil response, close resources and propagate through lifecycle.
- Preserve bounded headers/body, Connection/Upgrade sanitization, frame limits,
  cancellation, and existing WebsocketInterceptor behavior.
- Use F6 connection context/ID and F1 dialer in eager and lazy modes.

Files: mitm.go:1415-1437, 1552-1723, 1740-1790; header.go:57-113;
header_test.go:37-67; interceptor.go; mitm_internal_test.go.
Functions: modify relayConnForWS and extract only a small unexported handshake invoker
if needed.
Pattern: mirror roundTripWithContext's interceptor validation at mitm.go:1758-1781 and
existing resource cleanup at 1582-1591.
Integration: frame relay begins only after the intercepted 101 response is accepted.
Testing:
- Interceptor adds `X-Request: changed`; local WS origin observes it.
- Interceptor changes response header `X-Response: changed`; client observes it.
- Synthetic 403 never dials origin and no frame relay starts.
- Successful text frame `ping` -> `pong` still relays; cancellation releases buffers.
Do Not Modify: WsFrame API or frame payload interception behavior.
Success: handshake mutation/rejection and existing WebSocket race tests pass.
```

### Step F8: Verify and publish the fork revision

**Repository:** fork. **Dependencies:** F1-F7. **Complexity:** moderate.

```markdown
Context: all required fork extensions now exist and defaults must remain upstream-compatible.
Objective: complete a clean fork validation and create the immutable handoff SHA.

Requirements:
- Add/finish one table-driven integration matrix in mitm_test.go covering eager default,
  lazy H1, lazy H2, h2c prior knowledge, injected transport, passthrough, SOCKS5, and WS.
- Confirm public option docs state ownership/concurrency/default behavior.
- Keep extension commits reviewable against the josexy base, then make a final mechanical
  fork commit changing `module github.com/josexy/mitmproxy-go` to
  `module github.com/peterjmorgan/mitmproxy-go` and rewrite every self-import (including
  `/buf`, `/internal/...`, and `/metadata`). This is required so Proxify can consume the
  fork without a replace directive; upstream PRs should be prepared from the preceding
  extension commits.
- Run gofmt, go mod tidy, go vet ./..., go test ./..., and go test -race ./....
- Commit all fork work, push to github.com/peterjmorgan/mitmproxy-go, and record
  `FORK_SHA=$(git rev-parse HEAD)`. Verify the commit descends from 1c9f067 with
  `git merge-base --is-ancestor 1c9f067 "$FORK_SHA"`.
- Do not tag a mutable/pre-release branch as Proxify's dependency.

Files: all changed fork files; README.md option documentation; go.mod; all files found by
`rg 'github.com/josexy/mitmproxy-go'`; .github/workflows/go-test.yml.
Pattern: use local origin fixture/buildMitmHandler in mitm_test.go:42-275.
Testing fixtures/expected values: `/proto` returns observed protocol, `/stream` sends
`part1` then `part2` and trailer `X-End: done`, `/cancel` blocks until canceled, WS
echoes `ping`; assert no public internet access.
Do Not Modify: minimum Go version 1.26.5 or third-party dependency versions except tidy-required changes.
Success: pristine validation output and a pushed immutable SHA available to Go modules.
```

### Step P1: Establish local Proxify characterization fixtures

**Repository:** Proxify. **Dependencies:** none. **Complexity:** moderate.

```markdown
Context: Proxify currently has no *_test.go files. Martian remains the serving core.
Objective: create reusable local-only fixtures and characterize current H1 behavior.

Requirements:
- New package internal/testutil/proxytest provides `NewCA(t)`, `NewH1Origin(t,handler)`,
  `NewH2Origin(t,handler)`, `NewHTTPUpstream(t)`, `NewSOCKS5Upstream(t)`, and
  `ProxyClient(t, proxyURL, caPool, forceH2)` cleanup-safe helpers.
- New proxy_test.go starts current Proxy on 127.0.0.1:0 using temp config/output dirs.
- Characterize H1 HTTP, HTTPS CONNECT, request/response callbacks, proxify `/cacert`,
  regex passthrough, and Stop's current no-op as a skipped TODO (do not encode no-op as desired).
- All origins/proxies are local; no external DNS or internet.

Files: proxy.go:84-204, 207-324, 408-493, 703-729;
pkg/certs/mitm.go:45-135; internal/runner/runner.go:20-69.
Functions: test helpers above; no production API changes.
Pattern: use httptest.Server/UnstartedServer and tls.Config from Go stdlib; do not copy
candidate test helpers across module boundaries.
Testing: GET `/hello` => `200 hello`; callback adds `X-Test: request` and response adds
`X-Test: response`; `/cacert` DER parses as current CA; passthrough origin sees client
ALPN opaquely.
Do Not Modify: proxy.go production behavior, go.mod, Docker, or workflows.
Success: `go test ./...` passes with local fixtures and current Martian behavior recorded.
```

### Step P2: Introduce FlowContext and migrate callback types

**Repository:** Proxify. **Dependencies:** P1. **Complexity:** moderate.

```markdown
Context: OnRequestFunc/OnResponseFunc at proxy.go:46-47 publicly expose *martian.Context.
Objective: introduce Proxify-owned concurrent flow state and intentionally break callbacks.

Requirements:
- New flow_context.go defines FlowContext with private RWMutex/value map, id,
  connectionID, secure bool; exported methods exactly ID, ConnectionID, Get, Set,
  IsSecure as specified. Constructor remains unexported:
  `newFlowContext(id, connectionID string, secure bool) *FlowContext`.
- Change callback typedefs to accept *FlowContext.
- Current Martian ModifyRequest creates one FlowContext using martian context ID for both
  IDs, stores it under a private request context key, and ModifyResponse retrieves it.
- Use github.com/google/uuid already present to generate a fallback flow ID only when
  no protocol adapter supplies one.

Files: proxy.go:46-97, 207-324; pkg/types/userdata.go:12-19; go.mod:44.
Functions: FlowContext methods, private request context helpers, callback typedefs,
ModifyRequest/ModifyResponse bridge.
Pattern: follow explicit RWMutex locking; do not expose the map or candidate context.
Integration: types.UserData.ID uses FlowContext.ID; callbacks and response share the
same pointer.
Testing:
- ID/ConnectionID/IsSecure return fixture values `flow-1`, `conn-1`, true.
- 100 goroutines Set/Get unique keys under `go test -race`.
- Request callback sets `callback-value=seen`; response callback reads it.
- Separate current H1 requests receive distinct flow IDs.
Do Not Modify: Martian setup, transport, certificate code, or callback execution order.
Success: callback API contains no martian type and tests/race pass.
```

### Step P3: Decouple certificate files and CA generation from Martian

**Repository:** Proxify. **Dependencies:** P1. **Complexity:** moderate.

```markdown
Context: pkg/certs/mitm.go imports martian only for NewConfig/NewAuthority and hides paths.
Objective: make existing cacert.pem/cakey.pem directly consumable by the fork.

Requirements:
- Add `func CACertPath(dir string) string` and `func CAKeyPath(dir string) string`.
- Replace mitm.NewAuthority in generateCertificate with stdlib rsa.GenerateKey and
  x509.CreateCertificate preserving CA name `Proxify CA`, 2048 bits, one-year validity,
  CA/key usages, and current PEM formats/0600 writes.
- Keep GetMitMConfig temporarily in a separate Martian bridge file so old serving builds;
  core mitm.go must no longer import Martian.
- Existing valid files load without rewrite; malformed/expired behavior and GetRawCA,
  SaveCAToFile remain.

Files: pkg/certs/mitm.go:1-135; internal/runner/runner.go:20-33.
Functions: CACertPath, CAKeyPath, generateCertificate; move GetMitMConfig to
pkg/certs/martian.go.
Pattern: use x509.ParseCertificate/readPemFromDisk currently at lines 87-119.
Integration: path accessors will feed candidate options in P9; Martian bridge calls
loaded cert/key accessors within package. Note the package keeps process-global `cert`/
`pkey` populated by `LoadCerts(dir)`; `CACertPath(dir)`/`CAKeyPath(dir)` must return the
on-disk `cacert.pem`/`cakey.pem` under the same `dir` (P9 passes `options.Directory`,
which the runner sets from `ConfigDir`). Adding the accessors does not change who calls
`LoadCerts` — see P10 for ensuring the files exist before the fork reads them.
Testing:
- LoadCerts(tempDir) creates both exact filenames and valid matching CA/key.
- Second LoadCerts preserves file hashes and mtimes.
- SaveCAToFile output parses and equals GetRawCA.
- Existing pre-generated PKCS#1 key fixture loads; expired cert returns documented error.
Do Not Modify: `/cacert`, runner CLI, or candidate dependency.
Success: cert core has no Martian import and current proxy tests still pass.
```

### Step P4: Extract the protocol-neutral unified interceptor

**Repository:** Proxify. **Dependencies:** P2. **Complexity:** complex.

```markdown
Context: ModifyRequest/ModifyResponse at proxy.go:207-324 are Martian-shaped and special
host handling hijacks a session.
Objective: make one net/http policy function usable by Martian bridge tests and candidate.

Requirements:
- New interceptor.go defines private
  `type delegatedRoundTripper func(*http.Request) (*http.Response,error)` and
  `func (p *Proxy) interceptHTTP(ctx context.Context, flow *FlowContext, req *http.Request, next delegatedRoundTripper) (*http.Response,error)`.
- Exact order: proxy-local short circuit; request policy/callback; next; ensure non-nil
  body and resp.Request=effective req; response policy/callback; return.
- Extract `modifyRequest(req,flow)` and `modifyResponse(resp,flow)` preserving DSL,
  match/replace, remove-br, logging, redirects, and callback short-circuit semantics.
- Replace hijackNServe with `serveProxyLocal(req) *http.Response` using httptest recorder;
  support proxify, proxify:80, proxify:443, and bound listenAddr.
- Request/response bodies stream unless MatchReplace or logger configuration explicitly
  invokes existing buffering. Do not add unconditional io.ReadAll.
- Keep Martian ModifyRequest/ModifyResponse thin and operational until P17.

Files: proxy.go:207-405, 682-729; pkg/util/util.go:1-90;
pkg/logger/logger.go:103-219; pkg/types/userdata.go.
Functions: interceptHTTP, modifyRequest, modifyResponse, serveProxyLocal; shrink current
ModifyRequest/ModifyResponse wrappers.
Pattern: preserve existing DSL evaluation and UserData stored in FlowContext key
`user-data`; use httptest.NewRecorder pattern from old hijackNServe.
Integration: wrappers call extracted policy; candidate P9 calls interceptHTTP directly.
Testing:
- Ordered markers are request-callback, transport, response-callback.
- Synthetic proxify `/cacert` never invokes transport and response.Request is effective req.
- Transport response with nil Request/body is repaired.
- Request/response match-replace fixtures mutate `old` to `new` and preserve linkage.
Do Not Modify: listener serving, upstream transport construction, logger format.
Success: extracted path is fully tested and current Martian E2E still passes.
```

### Step P5: Correct the direct standard transport

**Repository:** Proxify. **Dependencies:** P1. **Complexity:** simple.

```markdown
Context: getStandardRoundTripper at proxy.go:506-540 supplies TLSClientConfig but omits
ForceAttemptHTTP2 and direct DialContext.
Objective: create a concurrent standard transport that preserves fastdialer policy and H2.

Requirements:
- Move transport code to transport.go.
- Add `newStandardTransport(dialer *fastdialer.Dialer) *http.Transport` with current
  pooling/TLS minimum/insecure behavior, DialContext calling dialer.Dial, and
  ForceAttemptHTTP2 true.
- getStandardRoundTripper uses it for direct mode. Keep proxy branches unchanged until P6.
- Add private `closeIdleRoundTripper(http.RoundTripper)` helper using interface
  `{ CloseIdleConnections() }` for later owner cleanup.

Files: proxy.go:475-540; fastdialer Dial at module fastdialer/dialer.go:207;
Go http.Transport docs.
Functions: newStandardTransport, closeIdleRoundTripper; modify getStandardRoundTripper.
Pattern: preserve TLS settings from proxy.go:508-516.
Integration: existing setupHTTPProxy still receives returned transport.
Testing:
- Local mapped hostname reaches local TLS H2 origin and origin sees HTTP/2.
- Denied local CIDR causes RoundTrip error before origin handler runs.
- Response.Request equals original after unified interceptor.
Do Not Modify: upstream proxy branches or tls-client adapter.
Success: direct H1/H2 and fastdialer allow/deny tests pass under race.
```

### Step P6: Make HTTP/SOCKS upstream routing request-based and concurrent

**Repository:** Proxify. **Dependencies:** P5. **Complexity:** complex.

```markdown
Context: rbtransport.Next is called from Transport.Proxy or Dial, so retries/concurrent
dials can change route mid-request.
Objective: select exactly one configured upstream route per RoundTrip with current
count-based round robin and precedence.

Requirements:
- Define private `routeSelector` with mutex, routes, rotateEvery, index, used; constructor
  rejects empty route and rotateEvery <= 0; `Next() string` follows state space above.
- Define `routedRoundTripper` holding one http.RoundTripper per route; RoundTrip selects
  once then delegates. Build HTTP route transports with fixed Proxy URL and fastdialer
  DialContext to proxy. Build SOCKS5 route transports with context-aware SOCKS dialers
  whose forward dial uses fastdialer.
- HTTP list takes precedence over SOCKS list. Direct uses P5.
- Remove use of projectdiscovery/roundrobin from new path, but keep module until P17.

Files: proxy.go:156-168, 506-540; transport.go from P5;
roundrobin transport module transport.go:21-35; x/net/proxy APIs.
Functions: newRouteSelector, routeSelector.Next, newHTTPProxyTransport,
newSOCKSProxyTransport, routedRoundTripper.RoundTrip/CloseIdleConnections.
Pattern: fixed per-route http.Transport copies P5's TLS/H2 settings.
Integration: Proxy owns one routed transport; no per-request mutation of transports.
Testing:
- Routes `[proxyA,proxyB]`, rotateEvery=2 produce A,A,B,B,A under 100 concurrent calls
  when results are sorted by selector sequence number.
- Two local HTTP proxies observe exactly requests 1-2 and 3-4.
- Two SOCKS proxies observe same distribution; canceled request stays on selected route.
- Invalid URL/zero rotation fails NewProxy.
Do Not Modify: TLS-profile transport or listeners.
Success: request-based routing tests pass under race with no route fallback.
```

### Step P7: Harden TLS-profile transport and route selection

**Repository:** Proxify. **Dependencies:** P6. **Complexity:** complex.

```markdown
Context: tlsClientRoundTripper at proxy.go:605-675 drops request context/Request linkage;
getTLSClientRoundTripper uses only the first upstream proxy.
Objective: preserve named profiles, fastdialer, concurrency, trailers, and route rotation.

Requirements:
- Build one tls-client HttpClient per route (or one direct client) and select via P6
  routeSelector once per RoundTrip.
- Always use tls_client.WithProxyDialerFactory. Factory returns a proxy.ContextDialer
  backed by fastdialer for direct; for HTTP/SOCKS URLs, it dials the proxy via fastdialer
  and preserves target hostname/auth semantics.
- Conversion copies request context, Host, body, ContentLength, TransferEncoding,
  trailers, and headers without aliasing mutable maps. Response conversion sets Request
  to the effective net/http request and copies trailers.
- Prove tls-client clients are safe for concurrent Do calls; if upstream API is not
  safe, add a pool of clients per route, not a global request mutex (which would
  serialize H2 streams).
- Implement CloseIdleConnections where supported.

Files: proxy.go:543-675; tls-client client_options.go:123-134 and client.go:122-142 in
module cache; fhttp request/response definitions; transport.go P6.
Functions: getTLSClientRoundTripper, tlsClientRoundTripper.RoundTrip,
convertToFHTTPRequest, convertFromFHTTPResponse, proxy dialer factory.
Pattern: follow P6 selection ownership and clone headers explicitly.
Integration: getRoundTripper chooses this only when TLSFingerprint; candidate later sees
it only as http.RoundTripper.
Testing:
- Profile chrome_120 reaches local TLS origin and returns non-empty negotiated protocol.
- Context cancellation reaches tls-client request; sibling concurrent request succeeds.
- Request/response trailers `X-End: done` and response.Request pointer are preserved.
- HTTP and SOCKS route lists rotate A,A,B,B at count 2 in fingerprint mode.
- fastdialer denial prevents direct and proxy socket establishment.
Do Not Modify: profile registry pkg/tlsprofile or CLI flags.
Success: race test with 50 concurrent requests and all conversion/route tests pass.
```

### Step P8: Upgrade toolchain and pin the immutable fork

**Repository:** Proxify. **Dependencies:** F8 and P1-P7. **Complexity:** moderate.

```markdown
Context: the fork requires a newer Go than Proxify (expected Go 1.26.5, but the fork's
own go.mod is authoritative). Proxify module says 1.24.1/toolchain 1.24.4 while CI
(build-test, lint-test, release-test, release-binary — the only four workflows that run
setup-go, each pinned `go-version: 1.21.x`) and Docker (`golang:1.21.4-alpine`) say 1.21.
Objective: establish a reproducible toolchain and immutable module dependency before use.

Requirements:
- Determine `GO_VERSION` from the published fork's own `go.mod` `go`/`toolchain` line as
  recorded by F8 — do not hardcode from this plan. `1.26.5` is the expected value; the
  fork's actual declaration wins. Before pinning a Docker base image, confirm the
  `golang:${GO_VERSION}-alpine` tag actually exists on Docker Hub; if it does not yet
  exist, use the newest published patch of the same minor that still satisfies the fork
  minimum, and record which was used.
- Set go.mod `go ${GO_VERSION}` and `toolchain go${GO_VERSION}`.
- Run `go get github.com/peterjmorgan/mitmproxy-go@${FORK_SHA}` using F8's full SHA;
  commit the resulting pseudo-version and go.sum. No replace directive.
- Set Docker builder to `golang:${GO_VERSION}-alpine`.
- Set every setup-go in build-test.yml, lint-test.yml, release-test.yml,
  release-binary.yml to `${GO_VERSION}`; verify no stale 1.21.x/1.24 declarations.
- Do not rely on GOTOOLCHAIN auto-download in CI/Docker.

Files: go.mod, go.sum, Dockerfile:1-8, .github/workflows/{build-test,lint-test,
release-test,release-binary}.yml; fork go.mod.
Pattern: retain existing workflow steps/actions, changing only toolchain declaration.
Integration: verify `go list -m -json github.com/peterjmorgan/mitmproxy-go` reports a
Version pseudo-version whose origin hash matches FORK_SHA.
Testing: go mod verify; go test ./...; go test -race ./...; go vet ./...; go build
./cmd/...; scope the toolchain grep to the files that declare it so dependency versions
in go.sum do not false-positive — `rg -n '1\.21|1\.24' go.mod Dockerfile .github/workflows`
returns no matches, and `rg -n 'replace .*mitmproxy' go.mod` returns no matches.
Do Not Modify: other dependency versions except tidy-required transitive changes.
Success: exact fork commit is reproducibly resolved and all commands use the recorded
${GO_VERSION}.
```

### Step P9: Build and directly test the candidate adapter

**Repository:** Proxify. **Dependencies:** P3, P4, P7, P8. **Complexity:** complex.

```markdown
Context: protocol-neutral policy and transports exist; Martian still owns Run.
Objective: construct a candidate handler and test it directly without switching serving.

Requirements:
- New mitmproxy_adapter.go defines private `mitmproxyAdapter` containing fork handler,
  Proxy pointer, and sync.Map of CONNECT FlowContexts.
- `newMitmproxyAdapter(p *Proxy, rt http.RoundTripper) (*mitmproxyAdapter,error)` supplies
  cert paths via `certs.CACertPath(p.options.Directory)` / `certs.CAKeyPath(p.options.Directory)`
  (P3 accessors; `options.Directory` is already populated from the runner's ConfigDir and is
  otherwise unused today), exact requested cache size (`p.options.CertCacheSize`, default 256),
  WithContextDialer fastdialer adapter, WithPassthroughFunc using util.MatchAnyRegex over
  `p.options.PassThrough`, WithLazyUpstreamMITM, WithRoundTripper, the HTTP interceptor, and the
  lifecycle hook. Explicitly enable the fork's HTTP/2 handling (semantic H2 is the primary
  migration outcome — do not depend on the fork's default being on).
- Precondition: the CA cert/key files must already exist at `options.Directory`. Return a
  descriptive error from `newMitmproxyAdapter` if either path is missing rather than letting
  the fork fail opaquely at first handshake. NewProxy (P10) is responsible for ensuring the CA
  is loaded before the adapter is built (see P10).
- HTTP interceptor obtains ConnectionIDFromContext; creates a fresh UUID flow per
  request/stream with IsSecure from URL/TLS; calls p.interceptHTTP.
- Lifecycle hook creates CONNECT flow on received, passes synthetic CONNECT request and
  selected response through callbacks/logging exactly once, records passthrough/error,
  and deletes on closed. Do not run ordinary request DSL twice.
- Adapter exposes ServeHTTP, ServeSOCKS5, Cleanup only as private methods.

Files: interceptor.go P4; flow_context.go P2; transport.go P7; proxy.go:49-97;
pkg/certs/mitm.go P3; fork lifecycle.go/option.go/interceptor.go.
Functions: newMitmproxyAdapter, HTTP interceptor closure, lifecycle event handler,
adapter methods.
Pattern: use FlowContext concurrent storage and errors.Join only during cleanup.
Integration: tests instantiate adapter under httptest HTTP server; Proxy.Run remains Martian.
Testing:
- One H1 CONNECT logs/callbacks CONNECT request and 200 once, then inner GET once.
- Two concurrent H2 requests have different flow IDs and same connection ID.
- regex `.*\\.opaque\.test:443` invokes passthrough predicate with full hostport.
- CACertPath/CAKeyPath load existing P3 files; cache option honors exact 1, 256, and 257 inputs.
Do Not Modify: Proxy.Run/Stop, Martian imports, SOCKS listener, README.
Success: direct adapter integration passes race while old Martian E2E remains green.
```

### Step P10: Switch HTTP and SOCKS serving to the candidate

**Repository:** Proxify. **Dependencies:** P9. **Complexity:** complex.

```markdown
Context: adapter is tested directly; Proxy.Run still calls martian.Proxy.Serve and local
go-socks5 tunnel.
Objective: make the candidate the default serving core while retaining old Martian
helpers compileable until P17.

Requirements:
- Proxy owns `adapter *mitmproxyAdapter`, `httpServer *http.Server`, HTTP/SOCKS net.Listener,
  run context/cancel, waitgroup, and one upstream RoundTripper.
- NewProxy builds transport once, then adapter. Do not create old Martian core by default.
  Before building the adapter, ensure the CA exists for `options.Directory` by calling
  `certs.LoadCerts(options.Directory)` (idempotent: it loads existing files or generates
  them). Today only `runner.NewRunner` calls LoadCerts, so a direct library caller of
  NewProxy would otherwise hand the adapter cert paths that do not exist yet.
- HTTP outer handler serves clear proxy-local requests before adapter; all CONNECT and
  absolute-form proxy requests go to adapter.ServeHTTP.
- Run binds listeners synchronously so bind errors return. HTTP uses http.Server.Serve.
  SOCKS accept loop calls adapter.ServeSOCKS5 in tracked goroutines and handles temporary
  accept errors/context cancellation.
- Support HTTP-only, SOCKS-only, and combined configurations. Do not tunnel SOCKS through
  HTTP.
- Keep old setupHTTPProxy and Martian bridge compiling and covered only by baseline tests;
  remove in P17.

Files: proxy.go:84-204, 408-493, 678-729; mitmproxy_adapter.go P9;
internal/runner/runner.go:84-141; candidate MitmProxyHandler interface mitm.go:273-284.
Functions: NewProxy, Run, private serveSOCKS/outerHTTPHandler; update Proxy fields.
Pattern: TinyDNS Close exists at tinydns.go:160; candidate examples/dumper accept loop
at examples/dumper/main.go:170-190 is reference only.
Integration: adapter gets the one owned transport; listenAddr is set from actual listener
before requests, including :0 tests.
Testing:
- HTTP-only and SOCKS-only GET `/hello` return 200.
- Combined listeners process simultaneous requests.
- Occupied HTTP or SOCKS port makes Run return non-nil and closes the other listener.
- Clear `http://proxify/cacert` bypasses candidate transport.
Do Not Modify: shutdown implementation beyond recording resources; P16 completes it.
Success: candidate is default serving core and old core still compiles/tests.
```

### Step P11: Validate proxy-local, callbacks, DSL, logging, and passthrough

**Repository:** Proxify. **Dependencies:** P10. **Complexity:** moderate.

```markdown
Context: candidate now serves both listeners.
Objective: lock down policy-level compatibility before broader protocol tests.

Requirements:
- Extend root E2E tests, production changes only for observed regressions.
- Test HTTP and HTTPS request DSL, response DSL, request/response match-replace,
  callback Set/Get, logger export, CONNECT request/response visibility, proxify static
  root and /cacert, and regex passthrough.
- CONNECT must have one flow ID; inner request a different flow ID; both share connection ID.
- Passthrough carries bytes opaquely and produces no inner HTTP callback/log entry.

Files: proxy_test.go P1; interceptor.go P4; mitmproxy_adapter.go P9;
pkg/logger/logger.go:103-219; pkg/util/util.go.
Pattern: use local fixtures from internal/testutil/proxytest and temp output paths.
Testing fixtures:
- Request header `X-Old: old` -> `X-Old: new`; response body `old` -> `new`.
- DSL `contains(request, 'needle')` and response status 201 produce Match true output.
- CONNECT log contains method CONNECT/status 200 exactly once.
- TLS passthrough origin negotiates h2 with client while callbacks see zero inner flows.
Do Not Modify: logger on-disk schema, DSL library, transports, or shutdown.
Success: all listed compatibility cases pass under `go test -race`.
```

### Step P12: Add the HTTP/1 and HTTP/2 protocol matrix

**Repository:** Proxify. **Dependencies:** P10. **Complexity:** complex.

```markdown
Context: semantic H2 is the primary migration outcome.
Objective: verify downstream/upstream independence, stream identity, streaming, trailers,
and cancellation locally.

Requirements:
- Add table-driven TestProtocolMatrix for H1->H1, H1->H2 TLS, H2->H2, H2->H1 TLS.
- Assert downstream callback req.Proto and upstream origin observed protocol separately.
- Add two concurrent H2 streams: distinct FlowContext.ID, one ConnectionID.
- Streaming origin flushes `part1`, blocks, then `part2`; client must observe part1 before
  release and trailer `X-End: done` after EOF.
- Cancel `/cancel` stream while `/ok` remains blocked; canceled request ends with
  context cancellation/RST_STREAM and `/ok` returns 200 without a new downstream connection.
- Include h2c prior knowledge through candidate if supported by listener harness.

Files: proxy_test.go; proxytest fixtures P1; mitmproxy_adapter.go; transport.go P5-P7;
candidate serveHTTP2Handler at fork mitm.go:1793-1875.
Functions: test functions only unless a concrete failure requires scoped production fix.
Pattern: candidate transport_test.go:164-275 is the cancellation concurrency reference.
Testing: use channels `part1Seen`, `releasePart2`, `cancelStarted`, `okStarted`; every wait
has a 2-second timeout and cleanup.
Do Not Modify: DSL/logger formats, WebSocket, CLI, HTTP/3 dependencies.
Success: all protocol pairs, stream isolation, streaming, trailers, and cancellation pass race.
```

### Step P13: Validate DNS policy, route rotation, and TLS modes end to end

**Repository:** Proxify. **Dependencies:** P10, P6, P7. **Complexity:** complex.

```markdown
Context: transport unit tests exist; verify them through actual candidate interception.
Objective: prove no migration bypasses fastdialer or request-based routes.

Requirements:
- Test DNS mapping `mapped.test -> 127.0.0.1` reaches a local origin without public DNS.
- Test deny 127.0.0.0/8 rejects before origin; matching allow permits.
- Through candidate, send four requests with rotateEvery=2 to two HTTP proxies and then
  two SOCKS5 proxies; assert A,A,B,B independently.
- Repeat standard TLS and named TLS profile `chrome_120`; assert origin sees valid request,
  response.Request linkage, and non-empty negotiated TLS/HTTP protocol.
- Run 50 concurrent fingerprint requests under race; no shared conversion map/body race.

Files: proxy_test.go; transport_test.go P5-P7; internal/testutil/proxytest upstream fixtures;
internal/runner/options.go:103-135 (read only).
Functions: tests and only minimal fixes in transport.go.
Pattern: route-selector fixtures from P6; do not use external fingerprint services.
Testing expected values: exact proxy ID response headers `[A,A,B,B]`; denied origin hit
counter remains zero; mapped.test hit counter is one.
Do Not Modify: candidate fork APIs, CLI flags, TLS profile registry.
Success: compatibility scenarios 11-14 pass locally under race.
```

### Step P14: Validate SOCKS listener and WebSocket behavior

**Repository:** Proxify. **Dependencies:** P10, fork F7. **Complexity:** moderate.

```markdown
Context: candidate-native SOCKS and intercepted WebSocket handshake are wired.
Objective: prove both listener surfaces execute the same policy and WS frames still relay.

Requirements:
- Through HTTP proxy and SOCKS5 listener, test HTTP and HTTPS interception callbacks,
  request mutation, response mutation, and shared policy output.
- Local WS origin requires request header `X-Handshake: changed`, sends response header
  `X-Origin: yes`, and echoes text `ping` as `pong`.
- Response callback adds `X-Response: changed`; client observes both headers.
- Callback synthetic 403 rejects upgrade, origin hit count zero.
- Stop/connection cancellation closes WS relay without leaked goroutines (full Stop is P16).

Files: proxy_test.go; proxytest WebSocket fixture (add `NewWebSocketOrigin` if absent);
mitmproxy_adapter.go; fork mitm.go relayConnForWS.
Functions: test helper and tests; production only for observed adapter defects.
Pattern: use candidate's websocket library/client or gorilla-compatible local client already
resolved transitively; do not add a second server framework.
Testing: exact 101 headers and `ping`/`pong`; HTTP/SOCKS callback counters each one.
Do Not Modify: frame payload API, upstream transport selection, logger formats.
Success: compatibility scenarios 15-16 pass race with no goroutine leak timeout.
```

### Step P15: Make logger shutdown drain safely

**Repository:** Proxify. **Dependencies:** P11. **Complexity:** moderate.

```markdown
Context: logger.NewLogger starts AsyncWrite at pkg/logger/logger.go:98, but Close closes
the channel without waiting and is neither producer-safe nor idempotent.
Objective: make logger ownership safe so Proxy can stop producers, drain exports, and
return from shutdown without lost queued records or send-on-closed panic.

Requirements:
- Add a producer/close mutex, closeOnce, and worker WaitGroup to Logger. LogRequest and
  LogResponse must either enqueue while open or return a package error `ErrLoggerClosed`.
- Close marks closed while excluding producers, closes asyncqueue exactly once, waits
  for AsyncWrite to drain, then closes sWriter exactly once.
- Preserve queue size, Store behavior, log formats, and ordering. Do not silently drop
  items accepted before Close.
- Concurrent repeated Close calls return only after the same drain completes. Retain
  public `Close()` signature; record writer close failures with existing gologger style.

Files: pkg/logger/logger.go:41-100, 102-228; pkg/logger/writer.go implementations;
pkg/types/userdata.go.
Functions: modify NewLogger, LogRequest, LogResponse, AsyncWrite, Close; add only
ErrLoggerClosed as new API artifact.
Pattern: use sync.Once plus WaitGroup; hold the producer mutex only through the channel
send/closed decision, never while draining.
Integration: P16 stops all proxy producers before calling Logger.Close.
Testing:
- Enqueue 100 numbered transactions, call Close, and assert fake Store receives all 100
  in order before Close returns.
- 20 concurrent producers racing Close return nil or ErrLoggerClosed and never panic
  under race detector.
- 20 repeated Close calls all return; structured writer closes once.
Do Not Modify: serialization schema, MaxSize truncation, Elastic/Kafka implementations.
Success: focused logger tests and `go test -race ./pkg/logger/...` pass.
```

### Step P16: Implement idempotent graceful proxy shutdown

**Repository:** Proxify. **Dependencies:** P10-P14. **Complexity:** complex.

```markdown
Context: Stop at proxy.go:473 is no-op; P10 records all owned resources.
Objective: implement the shutdown state machine and make Run return cleanly.

Requirements:
- Add stopOnce, stopDone, stopErr, and lifecycle mutex/state to Proxy. Proxy is not restartable.
- Keep public `func (p *Proxy) Stop()` source-compatible; have it call private
  `func (p *Proxy) stop() error`, which performs: cancel accept
  context; close listeners; http.Server.Shutdown with 5-second context; adapter.Cleanup;
  wait serving goroutines; close idle owned transports; TinyDNS.Close; logger.Close.
- Prevent send-on-closed logger queue by stopping request producers before P15 Logger.Close.
- Join non-benign errors; ignore net.ErrClosed/http.ErrServerClosed. Concurrent/repeated
  callers receive the same result after stopDone.
- Run returns nil after Stop, returns initial bind/serve errors otherwise.
- Runner.Close remains source-compatible and calls Stop; signal path does not os.Exit
  before cleanup completes.

Files: proxy.go:84-97, 408-473; pkg/logger/logger.go:98, 222-228;
internal/runner/runner.go:135-141; cmd/proxify/proxify.go:25-39;
candidate Cleanup mitm.go:369-415; TinyDNS.Close module line 160.
Functions: Proxy.Stop(), private Proxy.stop() error, Run cleanup/error propagation,
Runner.Close(), signal handler update.
Pattern: sync.Once plus closed done channel; errors.Join for cleanup.
Integration: candidate cleanup force-closes remaining H2/WS after HTTP grace period.
Testing:
- Stop before Run, during idle Run, during active H1, two H2 streams, and WS.
- 20 concurrent Stop calls all return; second sequential call is identical.
- After Stop, both listener addresses refuse connections and Run goroutine exits <2s.
- Inject one listener close error and prove later resources still close.
Do Not Modify: protocol policy, CLI flags, candidate fork.
Success: shutdown state-space cases and `go test -race ./...` pass.
```

### Step P17: Remove Martian and obsolete SOCKS tunnel dependencies

**Repository:** Proxify. **Dependencies:** P11-P16 all green. **Complexity:** moderate.

```markdown
Context: candidate is validated; old Martian bridge/helper code is no longer needed.
Objective: leave exactly one proxy core and no obsolete tunnel path.

Requirements:
- Remove Martian imports, fields, setupHTTPProxy, Modifier wrappers, pkg/certs/martian.go,
  and module requirement.
- Remove things-go/go-socks5, haxii/fastproxy, projectdiscovery/roundrobin imports/fields
  and requirements only when `go mod why` shows no remaining use.
- Remove httpTunnelDialer, hijackNServe, socks5tunnel, bufioPool, rbhttp/rbsocks5.
- Run go mod tidy and prove `rg 'martian|things-go/go-socks5|haxii/fastproxy|projectdiscovery/roundrobin'` has no production/dependency matches (planning docs excepted).
- Do not retain runtime/build-tag core selection.

Files: proxy.go; pkg/certs; go.mod/go.sum; all files reported by rg.
Functions: deletions and import/field cleanup only; no behavioral refactor.
Pattern: candidate fields/paths from P10 are the sole replacements.
Testing: run every root unit/E2E test, race, vet, and `go build ./cmd/...`; explicitly run
protocol matrix, passthrough, both listeners, WebSocket, and repeated shutdown.
Do Not Modify: logger/DSL implementation, replay, swaggergen, socket proxy.
Success: no Martian dependency/import and all compatibility tests remain green.
```

### Step P18: Document the breaking callback API and complete release verification

**Repository:** Proxify. **Dependencies:** P17. **Complexity:** moderate.

```markdown
Context: implementation is complete; public callback context types changed and H2 is
now semantically intercepted. Proxy.Stop retained its public signature.
Objective: document migration and execute final release-grade verification.

Requirements:
- README documents HTTP/1.1/H2/h2c support, H2 protocol translation, TLS passthrough,
  named TLS profiles, and that HTTP/3 is future work.
- Add migration note showing callbacks now accept *proxify.FlowContext and listing ID,
  ConnectionID, Get/Set, IsSecure. Document that Stop is idempotent and drains resources.
- Document fork module pseudo-version/full SHA in planning completion notes or dependency
  comment without adding mutable references.
- Verify all Go declarations in go.mod, Docker, and workflows equal the ${GO_VERSION}
  pinned in P8 (expected 1.26.5) and are mutually consistent.
- No QUIC dependency or HTTP/3 claim is introduced.

Files: README.md; go.mod; Dockerfile; .github/workflows; planning/mitmproxy-go-migration.
Pattern: retain README's existing CLI/reference structure; add concise compatibility section.
Testing/verification:
- gofmt check; go mod tidy followed by clean git diff; go mod verify; go vet ./...;
  go test ./...; go test -race ./...; go build ./cmd/....
- `docker build -t proxify-mitmproxy-go-test .` succeeds with declared builder.
- `go list -m -json` fork origin hash matches F8 SHA; `go mod graph` has no Martian.
- Run all 18 spec compatibility scenarios and attach command/results to final change summary.
Do Not Modify: unrelated command behavior, log schema, release action versions.
Success: documentation is accurate, container builds, all checks are pristine, and the
working tree contains no generated test output.
```

## Testing Strategy

### Unit Tests

The fork tests each option and internal transition at its owning boundary: custom dial
arguments/cancellation, predicate precedence, transport ownership, leaf cache states,
lazy ALPN, event order/identity, and WebSocket handshake outcomes. Proxify tests
FlowContext concurrency, route-selector transitions, net/http/fhttp conversion, cert
path/loading behavior, interceptor ordering, and shutdown idempotence.

### Integration Tests

Both repositories use local listeners and generated test CAs. Fork integration tests
exercise its handler directly in eager and lazy modes. Proxify tests the candidate
adapter directly before switching, then tests through real HTTP proxy and SOCKS5
listeners. All waits use bounded contexts/channels; no `time.Sleep` is used as the sole
synchronization mechanism.

### End-to-End Matrix

The final Proxify suite covers all specification scenarios:

1. H1 -> H1 and H1 -> H2-capable origin.
2. H2 -> H2 and H2 -> H1-only origin.
3. Concurrent H2 identities, streaming/trailers, isolated cancellation.
4. HTTP/HTTPS DSL and match/replace.
5. CONNECT logging/callbacks and regex opaque passthrough.
6. DNS mapping and allow/deny.
7. HTTP/SOCKS upstream rotation in standard and fingerprint modes.
8. HTTP and SOCKS listener interception.
9. WebSocket handshake mutation/rejection and frame relay.
10. Proxy-local static `/` and `/cacert`.
11. Graceful/repeated shutdown.

### Test Data

- Generated one-year RSA test CA in `t.TempDir()`; no checked-in private keys.
- Hostnames `mapped.test`, `origin.test`, `api.example`, and `opaque.test` resolved only
  through custom dialers/local fixtures.
- Bodies `hello`, `old`, `new`, `part1`, `part2`; trailer `X-End: done`.
- Proxy IDs `A`, `B`; rotation count 2; four sequential requests.
- WebSocket text `ping` -> `pong`.
- Every network test binds `127.0.0.1:0` and registers cleanup.

Every substantive step runs its focused tests. Fork F8 and Proxify P18 run `go test
-race ./...`, `go vet ./...`, and full builds. The final container build verifies no
implicit toolchain download is required.

## Resolved Decisions

- **Stable H2 connection identity:** fork-generated atomic opaque ID exposed only by a
  context accessor. Address/timestamp hashing was rejected as collision-prone.
- **Fork API shape:** shared RoundTripper rather than factory. Proxify transports are
  concurrent-safe, and a shared transport is required for upstream H2 pooling.
- **Injected transport ownership:** caller closes it; fork cleanup never does.
- **Lazy SOCKS behavior:** intercepted SOCKS acknowledges after valid command without
  speculative origin dial; passthrough dials first. This is necessary to inspect the
  client TLS hello while avoiding an unused upstream connection.
- **Passthrough precedence:** explicit predicate is authoritative; nil retains existing
  include/exclude rules.
- **CONNECT flow lifecycle:** separate CONNECT flow sharing connection ID with inner
  flows; cleaned on explicit closed event.
- **WebSocket HTTP interception:** use a retained-connection delegated invoker so the
  existing HTTPInterceptor can mutate/reject the handshake without a second dial.
- **Route semantics:** one selection per RoundTrip, fixed route through retries/dials,
  HTTP list precedence, no silent failover.
- **TLS-profile concurrency:** one stable client per route and no global serialization;
  custom ProxyDialerFactory supplies fastdialer.
- **Migration mechanism:** candidate adapter is tested directly while old default runs;
  after switch, old code remains compile-tested only until dedicated removal. No final
  feature flag or dual core.
- **Toolchain:** one exact Go version throughout, taken from the published fork's own
  go.mod as recorded by F8 (expected 1.26.5, but the fork's declaration is authoritative
  and the Docker image tag must be confirmed to exist); implicit CI downloads are forbidden.
- **Immutable handoff:** full fork SHA -> Go pseudo-version, pushed before Proxify import;
  no branch dependency or replace directive.

## Open Decisions

No blocking decisions remain.

Deferrable implementation observations:

- **Candidate upstream PR split (after F8):** decide whether to propose F1-F3, F5-F6,
  and F7 as separate upstream PRs. This does not affect the controlled fork pin.
- **Exact Go pseudo-version (P8):** mechanically determined from the published F8 SHA;
  the immutable SHA, not a preselected version string, is authoritative.
- **Stop documentation wording (P18):** wording can be finalized after implementation;
  retaining `Stop()` and making it idempotent is resolved.

## Deferred / Out of Scope

- HTTP/3 ingress/egress, QUIC, UDP capture, TUN/VPN, CONNECT-UDP, and MASQUE. The unified
  net/http interceptor and RoundTripper boundary provide line of sight without adding a
  QUIC dependency now.
- Runtime mutation of Proxify upstream proxy lists. Current options are construction-time
  settings; adding live synchronization would expand scope.
- SOCKS5 authentication and UDP ASSOCIATE. Existing Proxify listener is unauthenticated
  CONNECT-only, so candidate parity is sufficient.
- Logger/export redesign and unconditional streaming logging. Existing configured
  logging may buffer bodies; formats and subsystem replacement are explicit non-goals.
- h2c Upgrade semantic interception. Candidate intentionally tunnels RFC 7540 Upgrade
  after the H1 handshake; prior-knowledge h2c is semantically supported. The spec only
  requires h2c prior knowledge.
- Upstream contribution acceptance. Fork changes are designed for contribution, but
  migration completion depends only on the controlled immutable fork.

## Rollout Order

There are no identified P0 security/crash fixes. Ordering prioritizes P1 correctness
(dial/DNS policy, transport linkage, cancellation, lifecycle cleanup) before P2 protocol
features and P3 documentation.

1. **Parallel track A, fork P1 correctness:** F1-F4.
2. **Parallel track B, Proxify safety net:** P1-P3.
3. **Fork P2 core capability:** F5-F7, then F8 publish/pin candidate.
4. **Proxify P1 transport correctness:** P4-P7 (P4 can run beside P5-P7).
5. **Immutable handoff:** P8 only after F8 SHA is pushed and verified.
6. **P2 integration:** P9 direct adapter, then P10 serving switch.
7. **P1 compatibility gates:** P11-P14 can run in parallel after P10; P15 hardens logger
   drain independently; P16 waits for active protocol behavior to be stable.
8. **Removal gate:** P17 only when every compatibility suite is green under race.
9. **P3 release/documentation:** P18 and container verification.

The plan contains **26 executable steps** (F1-F8 and P1-P18). Each code-producing step
is scoped to one primary objective, includes concrete local fixtures, and leaves all new
production paths either immediately used or directly integration-tested. No final code
path, dependency, or feature flag is left orphaned.
