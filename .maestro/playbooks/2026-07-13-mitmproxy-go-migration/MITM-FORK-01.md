# mitmproxy-go Migration — Fork Phase 1: Dial / Passthrough / Transport / Cert

**Repository:** the FORK `github.com/peterjmorgan/mitmproxy-go`, based on upstream commit
`1c9f0671f96d897fd57b0966a64cd7721718cf0a`. These tasks operate on the fork repo, NOT the
Proxify working directory — run this document from a checkout of the fork at that base commit.
Authoritative spec: `planning/mitmproxy-go-migration/plan.md` in the Proxify repo (Steps
F1–F4); copy that file alongside if the fork checkout lacks it. Keep the fork
backward-compatible: every new behavior is opt-in and the existing eager default is unchanged.

<!-- maestro:halt: Fork checkout missing — github.com/peterjmorgan/mitmproxy-go does not exist on GitHub and no local checkout is present. All FORK tasks (F1-F8) require writing to the fork repo, which lives outside this agent's only writable directory (proxify). Human must create the fork and resolve the write-scope conflict before the fork track can run. See notes below. -->

<!--
MAESTRO NOTE (proxify agent, loop 00001, 2026-07-13): F1 could NOT be started. Root cause:
  1. The fork repo `github.com/peterjmorgan/mitmproxy-go` returns "Repository not found" — it
     has not been created yet. Upstream `github.com/josexy/mitmproxy-go` IS reachable and its
     main HEAD is exactly the audited base commit 1c9f0671f96d897fd57b0966a64cd7721718cf0a.
  2. No local checkout of the fork exists anywhere on this machine (searched all of /home/pmorgan
     and the Go module cache).
  3. This agent's HARD write restriction limits writes to /mnt/c/projects/playground/proxify
     (and the Auto Run folder). The fork must live in a SEPARATE repo/directory outside that
     scope, so F1-F4 cannot be implemented here without violating the directory restriction.
  Unblock steps for a human: (a) create the peterjmorgan/mitmproxy-go fork from josexy@1c9f0671,
  (b) clone it to a checkout, (c) run the FORK-01..03 documents from an agent whose working
  directory IS that fork checkout, then (d) remove this halt marker. The PROXIFY-04..10 documents
  are a separate track and can run in this repo, but P8+ still depend on the published fork SHA.
-->
- [ ] **F1 — Generalize outbound dialing.** Make every outbound path accept a
  cancellation-aware custom dialer without changing `WithDialer` behavior.
  - Define `type ContextDialer interface { DialContext(context.Context, string, string) (net.Conn, error) }` and `WithContextDialer(ContextDialer) Option` in `option.go`; keep `WithDialer(*net.Dialer)` and default timeout — last dialer option wins.
  - Route `proxyDialer`/`NewProxyDialer` internals through `ContextDialer` for direct, eager TLS, lazy TLS, passthrough, HTTP/HTTPS proxy, and SOCKS proxy paths. Do NOT resolve the destination before invoking a custom dialer; for an HTTP proxy, dial the proxy through the custom dialer and preserve the target hostname in CONNECT. Preserve context cancellation/deadlines; add no background contexts.
  - Do Not Modify: TLS fingerprint generation, certificate issuance, passthrough matching, interceptor behavior.
  - Success: both old and new dialer options work; recording dialer receives the mapped host verbatim and exactly once with no pre-lookup; `go test -race ./...` and `go vet ./...` pass. Full detail: plan.md §Step F1.

- [ ] **F2 — Add the passthrough predicate.** Add an opt-in exact predicate so Proxify can
  keep arbitrary regex rules.
  - Define `type PassthroughFunc func(hostport string) bool` and `WithPassthroughFunc(PassthroughFunc) Option` in `option.go`; carry it in `runtimeConfigState`/`runtimeConfig` snapshots so each connection has stable config.
  - In `shouldPassthroughRequest`, a non-nil predicate is authoritative, receives the normalized `host:port`, and returns reason `passthrough_predicate` (false = intercept). When nil, preserve include/exclude precedence and defaults byte-for-byte.
  - Do Not Modify: dialing, certificate logic, public host wildcard setters.
  - Success: predicate true prevents interception; predicate false overrides exclude-host and intercepts; nil retains existing behavior; concurrent connections keep their captured predicate under `-race`. Full detail: plan.md §Step F2.

- [ ] **F3 — Inject a shared semantic RoundTripper (depends on F1).** Allow an owner-supplied
  concurrent `http.RoundTripper` for both downstream H1 and H2.
  - Add `WithRoundTripper(http.RoundTripper) Option`; nil = existing behavior. Snapshot it into `runtimeConfig`; document it must be concurrent-safe and stays owned/closed by the caller (the fork never closes an injected transport).
  - `roundTripWithContext` selects the injected transport first, else `connCtx.transport`; H1 and `serveHTTP2Handler` use the same selection path. Preserve request context/body/trailers and set `response.Request = req` when nil. Do not construct `connCtx.transport` solely for an injected RoundTripper (eager default may keep constructing it until F5). Guard transport `Close` calls against nil.
  - Do Not Modify: WebSocket path, eager TLS fingerprinting, passthrough.
  - Success: injected transport receives one H1 and two concurrent H2 requests; canceling one H2 yields `context.Canceled` while sibling returns 200; trailers survive; cleanup never calls `Close` on the injected transport; old transport tests pass with `-race`. Full detail: plan.md §Step F3.

- [ ] **F4 — Refactor leaf issuance into an authority-based helper.** One tested leaf
  issuance/cache helper used by eager and lazy modes.
  - Add unexported `serverCertificate(ctx, serverName, authority string, template certificateIdentity) (tls.Certificate, error)` on `mitmProxyHandler`; normalize the cache key SNI-first then CONNECT authority host; lazy callers may supply only authority/SNI. Reuse `priKeyPool`/`serverCertPool`; publish only fully built certificates.
  - Replace the cert cache's multiple-of-256 restriction with EXACT capacity (capacity 1 → at most 1 leaf; 257 → at most 257); preserve expiry and background cleanup. Existing eager path builds `certificateIdentity` from the origin cert and calls the helper with unchanged validity; replace the eager inline block immediately so the helper is not orphaned.
  - Do Not Modify: ALPN selection, origin dialing, public options.
  - Success: repeat call returns identical DER and cache count; empty SNI + authority `127.0.0.1:443` yields an IP SAN; signing error creates no cache entry; capacities 1/256/257 never exceed the exact bound; concurrent first-use is race-free. Full detail: plan.md §Step F4.

- [ ] Run `gofmt -l .`, `go vet ./...`, `go test ./...`, and `go test -race ./...` across the
  fork after F1–F4; all must be clean before starting Fork Phase 2 (`MITM-FORK-02.md`).
