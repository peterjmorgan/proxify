# Initial Plan: Martian to mitmproxy-go

## Purpose

This document captures the coarse implementation sequence before the planner agent
turns the specification into right-sized, executable steps. The authoritative
requirements are in `spec.md`.

## Working Assumptions

- Maintain a controlled fork at `github.com/peterjmorgan/mitmproxy-go` based on
  audited commit `1c9f0671f96d897fd57b0966a64cd7721718cf0a`.
- Keep fork defaults compatible with upstream and introduce opt-in extension points.
- Upgrade the project to the fork's required Go toolchain rather than pinning an
  older, substantially less hardened candidate revision.
- Accept the intentional public callback migration from `*martian.Context` to
  `*proxify.FlowContext`.
- Preserve all CLI behavior, including named TLS fingerprint profiles and
  multi-proxy round robin.
- Defer actual HTTP/3 implementation while enforcing a protocol-neutral policy core.

## Phase 1: Establish Safety Nets

1. Add local H1 and H2 origin fixtures and a proxy client test harness.
2. Characterize current H1, CONNECT, passthrough, callback, DNS, and upstream proxy
   behavior before changing the proxy core.
3. Add focused tests for current TLS profile transport concurrency and response
   request linkage.

The baseline tests should distinguish intentional API changes from accidental
behavioral regressions.

## Phase 2: Extend the mitmproxy-go Fork

1. Generalize outbound dialing to a context-aware interface.
2. Add a passthrough predicate compatible with Proxify regex decisions.
3. Add lazy-upstream TLS interception and host/SNI leaf generation.
4. Add injectable semantic `http.RoundTripper` support for both H1 and H2.
5. Add CONNECT lifecycle hooks.
6. Route WebSocket handshakes through the HTTP interceptor.
7. Cover every extension with unit, H1, H2, cancellation, and race tests.

Fork work should be independently reviewable and suitable for upstream pull
requests. Proxify must consume an immutable fork revision.

## Phase 3: Introduce Protocol-Neutral Proxify Primitives

1. Add `FlowContext` with per-flow and per-connection identity.
2. Update public callback types and internal user-data storage.
3. Refactor request and response modification into a unified interceptor callable
   independently of Martian.
4. Replace connection hijacking for proxy-local content with ordinary short-circuit
   HTTP responses.

Martian remains wired during this phase so each primitive can be tested before the
serving-path switch.

## Phase 4: Correct and Unify Upstream Transports

1. Configure standard `http.Transport` with HTTP/2 enabled explicitly.
2. Inject `fastdialer` for direct upstream network policy and DNS behavior.
3. Preserve HTTP and SOCKS5 proxy rotation in concurrency-safe transports.
4. Preserve the named `bogdanfinn/tls-client` profile transport.
5. Ensure every returned response has the effective request attached.
6. Add transport cleanup and concurrency tests.

## Phase 5: Switch the HTTP Proxy Core

1. Construct the fork handler from Proxify options, certificate paths, predicate,
   dialer, transport, lifecycle hooks, and unified interceptor.
2. Replace `martian.Proxy.Serve` with `http.Server.Serve` and a narrow outer handler.
3. Preserve CONNECT logging and proxy-local routing.
4. Verify H1 and H2 protocol translation, concurrent streams, cancellation, trailers,
   callbacks, DSL mutation, and logging.

## Phase 6: Switch SOCKS5 and Shutdown

1. Route SOCKS5 connections through the candidate-native serving API.
2. Remove the local SOCKS-to-HTTP proxy tunnel and its supporting dependencies.
3. Track listeners and servers in `Proxy`.
4. Implement idempotent graceful `Stop` and active connection cleanup.
5. Test HTTP-only, SOCKS-only, combined listeners, bind failures, and repeated stop.

## Phase 7: Remove Martian and Complete Toolchain Migration

1. Remove Martian imports, context use, certificate construction, and module entry.
2. Remove obsolete proxy-core helpers and dependencies that are no longer reachable.
3. Upgrade `go.mod`, Docker, and GitHub Actions to the selected Go toolchain.
4. Update README usage and library callback documentation.
5. Run formatting, tidy, unit tests, race tests, vet, command builds, and container
   build verification.

## Key Risks for Detailed Planning

- The fork and Proxify changes span separate repositories and must have an explicit
  pin/update handoff.
- HTTP/2 tests must validate stream isolation rather than only protocol negotiation.
- The TLS-profile client must be proven concurrency-safe before serving multiple H2
  streams through one shared interceptor.
- Request/response logging may buffer bodies; tests must cover streaming and maximum
  export size behavior.
- CONNECT hooks must not cause requests to be logged twice.
- Candidate eager and lazy modes must not share connection state accidentally.
- Passthrough must avoid DNS or TLS preflight that would violate opacity.
- Shutdown ordering must avoid closing shared transports while active streams still
  reference them.

## Definition of Done

- The compatibility matrix in `spec.md` passes locally without internet access.
- Both fork and Proxify pass `go test -race ./...`.
- Proxify contains no Martian imports or dependency.
- HTTP/2 traffic is visible to callbacks, DSL mutation, and logging.
- Existing DNS, allow/deny, passthrough, upstream rotation, and TLS profile features
  remain functional.
- Toolchain declarations agree across module, CI, release, and container builds.
- The resulting request/response policy core has no HTTP/1- or HTTP/2-specific public
  contract that would block a future HTTP/3 adapter.
