# mitmproxy-go Migration — Proxify Phase 9: Shutdown and Martian Removal

**Repository:** Proxify (this working directory). Authoritative spec:
`planning/mitmproxy-go-migration/plan.md` Steps P16–P17. P17 is gated on ALL compatibility
suites (P11–P16) being green under `-race`.

- [ ] **P16 — Idempotent graceful shutdown (depends on P10–P14).** Add `stopOnce`, `stopDone`,
  `stopErr`, and lifecycle mutex/state to `Proxy` (not restartable). Keep public
  `func (p *Proxy) Stop()` source-compatible; have it call private `func (p *Proxy) stop() error`
  that: cancels the accept context; closes listeners; `http.Server.Shutdown` with a 5-second
  context; `adapter.Cleanup`; waits for serving goroutines; closes idle owned transports;
  `TinyDNS.Close`; `logger.Close`. Stop request producers BEFORE `logger.Close` (P15) to prevent
  send-on-closed. Join non-benign errors; ignore `net.ErrClosed`/`http.ErrServerClosed`;
  concurrent/repeated callers get the same result after `stopDone`. `Run` returns nil after Stop,
  else the initial bind/serve error. `Runner.Close` stays source-compatible and calls Stop; the
  signal path does not `os.Exit` before cleanup completes. Do Not Modify: protocol policy, CLI
  flags, candidate fork. Success: Stop works before Run, during idle Run, during active H1, two
  H2 streams, and WS; 20 concurrent Stop calls all return; after Stop both listener addresses
  refuse connections and the Run goroutine exits <2s; an injected listener-close error still lets
  later resources close; `go test -race ./...` passes. Full detail: plan.md §Step P16.

- [ ] **P17 — Remove Martian and obsolete tunnel dependencies (depends on P11–P16 all green).**
  Leave exactly one proxy core. Remove Martian imports/fields, `setupHTTPProxy`, Modifier
  wrappers, `pkg/certs/martian.go`, and the module requirement. Remove
  `things-go/go-socks5`, `haxii/fastproxy`, `projectdiscovery/roundrobin` imports/fields/requires
  ONLY when `go mod why` shows no remaining use. Remove `httpTunnelDialer`, `hijackNServe`,
  `socks5tunnel`, `bufioPool`, `rbhttp`/`rbsocks5`. Run `go mod tidy`. Do not retain
  runtime/build-tag core selection. Do Not Modify: logger/DSL implementation, replay, swaggergen,
  socket proxy. Success: `rg 'martian|things-go/go-socks5|haxii/fastproxy|projectdiscovery/roundrobin'`
  has no production/dependency matches (planning docs excepted); every root unit/E2E test, plus
  `-race`, `vet`, and `go build ./cmd/...` pass — explicitly re-run the protocol matrix,
  passthrough, both listeners, WebSocket, and repeated shutdown. Full detail: plan.md §Step P17.

- [ ] Run the full suite — `go test ./...`, `go test -race ./...`, `go vet ./...`,
  `go build ./cmd/...` — all clean before Proxify Phase 10.
