# Proxify mitmproxy-go Migration Specification

## Status

- Planning branch: `migrate-mitmproxy-go`
- Candidate upstream: `github.com/josexy/mitmproxy-go`
- Audited revision: `1c9f0671f96d897fd57b0966a64cd7721718cf0a`
- Intended controlled fork: `github.com/peterjmorgan/mitmproxy-go`
- Candidate validation: `go test -race ./...` passes with Go 1.26.5

## Problem

Proxify currently uses `github.com/projectdiscovery/martian/v3` for its HTTP/HTTPS
intercepting proxy. The original Google Martian repository is archived and the
ProjectDiscovery fork currently used by Proxify does not provide semantic HTTP/2
interception through Proxify's request and response modifier pipeline.

Proxify needs a maintained protocol core that:

1. Intercepts HTTP/1.1 and HTTP/2 requests and responses as `net/http` messages.
2. Preserves Proxify's DNS, network policy, upstream proxy, TLS fingerprinting,
   logging, DSL, callback, passthrough, SOCKS5, and certificate behavior.
3. Separates downstream protocol handling from upstream transport selection so an
   HTTP/3 ingress or egress adapter can be introduced later without rewriting the
   policy pipeline.

## Decision

Replace Martian with a controlled fork of `mitmproxy-go`. Do not perform a direct
dependency swap. The controlled fork must first add a decoupled mode that removes
its eager dependency on an upstream TLS connection and permits Proxify to supply
its own dialing, passthrough, and `http.RoundTripper` behavior.

The fork retains its existing behavior by default. New extension points must be
opt-in so they are suitable for an upstream pull request.

## Goals

### Protocol behavior

- Terminate intercepted HTTP/1.1 and HTTP/2 connections semantically.
- Route every intercepted H1 request and every H2 stream through the same Proxify
  request/response pipeline.
- Allow downstream and upstream protocols to differ. In particular, support H2 to
  H1 and H1 to H2 translation through `net/http` semantics.
- Support TLS ALPN negotiation with `h2` and `http/1.1` without requiring an eager
  origin connection.
- Preserve cleartext HTTP/1.1 behavior and h2c prior-knowledge support.
- Preserve opaque TLS passthrough for configured hosts.
- Preserve WebSocket handshake mutation/logging and frame relay behavior.

### Existing Proxify behavior

- Preserve request and response DSL filtering and match/replace.
- Preserve request and response logging/export.
- Preserve the special `proxify` host and `/cacert` endpoint.
- Preserve custom DNS mapping and fallback resolution.
- Preserve IP/CIDR allow and deny policy through `fastdialer`.
- Preserve round-robin HTTP and SOCKS5 upstream proxy lists and request-count
  switching.
- Preserve standard upstream TLS mode and opt-in named TLS fingerprint profiles.
- Preserve CONNECT request/response visibility to logging and callbacks.
- Preserve passthrough regular-expression semantics.
- Continue supporting both the HTTP proxy listener and SOCKS5 listener.
- Implement functional shutdown instead of the current no-op `Stop` method.

### Maintainability

- Remove all Martian imports and the Martian module dependency from Proxify.
- Keep Proxify's policy and logging pipeline independent of `mitmproxy-go` types.
- Pin the fork dependency to an immutable revision.
- Keep fork changes narrow, covered by tests, and suitable for proposing upstream.
- Upgrade build, test, lint, release, and container toolchains consistently.

## Non-Goals

- Implementing HTTP/3 interception in this migration.
- Implementing QUIC, UDP capture, TUN/VPN routing, CONNECT-UDP, or MASQUE.
- Replacing the logger/export subsystem.
- Rewriting the DSL implementation.
- Changing the on-disk log formats except where HTTP/2 protocol fields naturally
  report `HTTP/2.0`.
- Adding a UI.
- Broadly refactoring unrelated commands such as replay or swagger generation.

## Required Fork Extensions

The controlled `mitmproxy-go` fork must expose the following capabilities. Exact
names may vary only if the final names are clearer and retain these contracts.

### Context-aware dialing

Add an interface accepted by configuration rather than requiring `*net.Dialer`:

```go
type ContextDialer interface {
    DialContext(context.Context, string, string) (net.Conn, error)
}
```

Requirements:

- Existing `WithDialer(*net.Dialer)` remains supported.
- A new option accepts `ContextDialer` or an equivalent function adapter.
- Direct, passthrough, TLS, HTTP proxy, and SOCKS proxy connections use the
  configured abstraction.
- Context cancellation and deadlines are preserved.
- Dialing must not perform an independent DNS lookup before invoking a custom
  dialer.

### Passthrough predicate

Add an optional predicate:

```go
type PassthroughFunc func(hostport string) bool
```

When present, it decides whether the target is tunneled opaquely. Existing include
and exclude host options remain available and retain their current defaults.

### Lazy upstream MITM mode

Add an opt-in mode in which the downstream TLS handshake does not first connect to
the origin.

Requirements:

- Generate the leaf certificate from CONNECT authority and SNI using the configured
  CA instead of cloning the origin certificate.
- Advertise `h2` when the client offers it and HTTP/2 is enabled; always retain an
  HTTP/1.1 fallback.
- Do not create an unused upstream connection.
- Maintain certificate caching and bounded cache behavior.
- Retain the current eager, ClientHello-mirroring behavior as the fork's default.

### Injectable RoundTripper

Add an optional `http.RoundTripper` or factory used by the semantic HTTP interceptor
for actual upstream requests.

Requirements:

- It must support concurrent H2 streams safely.
- The request context, cancellation, body, trailers, and response request pointer
  must be preserved.
- The existing per-connection transport remains the default when none is supplied.
- The injected transport must be used for both H1 and H2 downstream requests.
- WebSocket handshakes may use a separate dial path where required, but must still
  pass through the HTTP interception hooks.

### Connection lifecycle hooks

Expose enough lifecycle information to preserve CONNECT observability without
parsing raw bytes in Proxify. Hooks must cover:

- CONNECT request received.
- CONNECT response/status selected.
- Passthrough decision.
- Terminal connection error.

Hooks must not serialize independent H2 streams or introduce global locks.

### WebSocket handshake interception

Run the HTTP request/response interceptor around WebSocket upgrade handshakes before
starting frame relay. Request mutation, response mutation, logging, rejection, and
error propagation must work consistently with ordinary H1 requests.

## Proxify Architecture

### FlowContext

Replace the public use of `*martian.Context` with a Proxify-owned context:

```go
type FlowContext struct {
    // implementation-private synchronization and value storage
}

func (c *FlowContext) ID() string
func (c *FlowContext) ConnectionID() string
func (c *FlowContext) Get(key string) (any, bool)
func (c *FlowContext) Set(key string, value any)
func (c *FlowContext) IsSecure() bool
```

Each H2 stream receives a distinct flow ID. Requests sharing a downstream connection
share a connection ID. Flow value storage is safe for concurrent access.

Update callback types to accept `*FlowContext`. This is an intentional source-level
breaking change for library consumers and must be documented. Do not keep Martian as
a compatibility-only dependency.

### Unified interceptor

The Proxify HTTP interceptor must execute this order:

1. Establish or obtain `FlowContext`.
2. Run special-host routing when applicable.
3. Run `ModifyRequest` and the request callback/DSL/logging behavior.
4. Delegate to the configured upstream `RoundTripper` unless short-circuited.
5. Ensure `resp.Request` references the effective request.
6. Run `ModifyResponse` and the response callback/DSL/logging behavior.
7. Return the response to `mitmproxy-go`.

Request and response bodies remain streaming unless a configured match/replace or
logger operation explicitly buffers them.

### Transport

- Standard mode uses `http.Transport` with `ForceAttemptHTTP2: true` and Proxify's
  dial/proxy policies.
- TLS fingerprint mode retains `bogdanfinn/tls-client` and named profiles.
- HTTP upstream proxy selection retains request-count round robin.
- SOCKS5 upstream selection retains request-count round robin.
- Transport implementations must be safe for concurrent H2 streams.

### Listeners and shutdown

- Serve the HTTP proxy through `http.Server` with a small outer handler for special
  proxy-local routing and CONNECT lifecycle integration.
- Either use the candidate's native SOCKS5 serving path or retain the existing
  SOCKS listener only if tests demonstrate identical interception behavior. Prefer
  the candidate-native path to remove the local HTTP tunnel indirection.
- `Stop` closes HTTP and SOCKS listeners, shuts down active servers, calls candidate
  cleanup, closes idle transports, and is idempotent.

## Certificate Requirements

- Continue using `cacert.pem` and `cakey.pem` in the configured Proxify directory.
- Add safe path accessors to `pkg/certs` rather than duplicating filename knowledge.
- Existing valid Proxify CA files must load without regeneration.
- `/cacert` and `--out-ca` behavior remain unchanged.
- Certificate cache size continues to honor `--cert-cache-size`.

## Toolchain Requirements

- Upgrade `go.mod` and `toolchain` to Go 1.26.5 or the minimum version required by
  the pinned fork revision.
- Upgrade Docker builder and every GitHub Actions Go setup consistently.
- Do not rely on implicit toolchain downloads in CI or Docker builds.

## Compatibility Requirements

The migration is not complete unless these scenarios pass:

1. H1 client -> H1 origin.
2. H1 client -> H2-capable TLS origin.
3. H2 client -> H2 origin.
4. H2 client -> H1-only TLS origin.
5. Two concurrent H2 streams with distinct flow IDs and one connection ID.
6. H2 streaming response and trailers.
7. H2 request cancellation without closing unrelated streams.
8. HTTP and HTTPS request/response DSL mutation.
9. CONNECT request and response logging.
10. Regex passthrough carrying H2 opaquely.
11. Custom DNS mapping and allow/deny decisions.
12. HTTP upstream proxy rotation.
13. SOCKS5 upstream proxy rotation.
14. Standard TLS and named TLS-profile modes.
15. HTTP proxy and SOCKS5 listener interception.
16. WebSocket handshake mutation and frame relay.
17. `http://proxify/cacert` and proxy-local static content.
18. Graceful and repeated shutdown.

## Testing Requirements

- Fork changes require unit and integration tests in the fork repository.
- Proxify requires table-driven unit tests for flow context, transport selection,
  passthrough decisions, and lifecycle behavior.
- Proxify requires local end-to-end tests using generated test CAs and local H1/H2
  origins. Tests must not require public internet access.
- Run `go test -race ./...` in both repositories.
- Run `go vet ./...` and build all commands.
- Add a container build verification using the declared Go toolchain.

## Rollout Constraints

- Work occurs on `migrate-mitmproxy-go` until the full compatibility matrix passes.
- Fork extension points land and are pinned before Proxify switches its serving path.
- Keep the old Martian implementation buildable until the new interceptor and
  integration tests are working; remove Martian in a dedicated later step.
- Do not leave both proxy cores selectable in the final state unless a temporary
  compile-time migration mechanism is explicitly required by the implementation
  plan.

## HTTP/3 Line of Sight

The final policy pipeline must accept ordinary `*http.Request` and return
`*http.Response` without assuming TCP or HTTP/2. Future work should be able to add:

- `quic-go/http3` as an upstream `RoundTripper`.
- An HTTP/3 ingress adapter that supplies the same unified interceptor.
- UDP capture or MASQUE outside the HTTP policy layer.

No QUIC dependency is added by this migration.
