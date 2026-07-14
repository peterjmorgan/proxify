# mitmproxy-go Migration — Proxify Phase 4: Safety Net (Fixtures / FlowContext / Certs)

**Repository:** Proxify (this working directory), branch `migrate-mitmproxy-go`. Authoritative
spec: `planning/mitmproxy-go-migration/plan.md` Steps P1–P3 — read the relevant step before each
task for full Files/Testing detail. Martian remains the serving core throughout this phase; do
not switch serving. Every network test binds `127.0.0.1:0` and registers cleanup; no external
DNS or internet.

- [x] **P1 — Local characterization fixtures.** New package `internal/testutil/proxytest`
  provides cleanup-safe helpers `NewCA(t)`, `NewH1Origin(t,handler)`, `NewH2Origin(t,handler)`,
  `NewHTTPUpstream(t)`, `NewSOCKS5Upstream(t)`, `ProxyClient(t, proxyURL, caPool, forceH2)`
  (use `httptest` + stdlib `tls.Config`). New `proxy_test.go` starts the current `Proxy` on
  `127.0.0.1:0` with temp config/output dirs and characterizes: H1 HTTP, HTTPS CONNECT,
  request/response callbacks, proxify `/cacert`, regex passthrough, and `Stop`'s current no-op
  recorded as a SKIPPED TODO (do not encode the no-op as desired behavior).
  - Do Not Modify: `proxy.go` production behavior, `go.mod`, Docker, or workflows.
  - Success: `go test ./...` passes with local fixtures; GET `/hello` → `200 hello`; callbacks add `X-Test: request`/`X-Test: response`; `/cacert` DER parses as the current CA. Full detail: plan.md §Step P1.
  - ✅ **DONE 2026-07-13** — `internal/testutil/proxytest` (7 helpers incl. `NewPlainOrigin`, 5 self-tests) + root `proxy_test.go` (5 PASS + Stop-no-op SKIP referencing P16). All success probes verified; `go vet` clean; no production file touched. Passthrough characterized via opaque-ALPN h2 + origin-cert assertions; MITM via `Proxify CA` issuer.
  - ⚠️ **FINDING for the race-gate task below:** `go test -race .` fails on a PRE-EXISTING production race (not test code): `pkg/logger/logger.go` — `LogRequest` enqueues the live `*http.Request`; the async `AsyncWrite` goroutine runs `httputil.DumpRequest(req, true)` (drains/replaces body) while martian concurrently forwards the same request. Fires on every logged transaction. The logger must snapshot synchronously before enqueueing (or the migration's logging rework must land) before the final `-race` checkbox can pass. `go test -race ./internal/testutil/proxytest/` is clean.

- [ ] **P2 — Introduce FlowContext, migrate callback types (depends on P1).** New
  `flow_context.go` defines `FlowContext` with a private `RWMutex`/value map, `id`,
  `connectionID`, `secure bool`, and exported methods exactly `ID`, `ConnectionID`, `Get`,
  `Set`, `IsSecure`; unexported constructor `newFlowContext(id, connectionID string, secure bool) *FlowContext`.
  - Change the callback typedefs (`OnRequestFunc`/`OnResponseFunc` at `proxy.go:46-47`) to accept `*FlowContext` instead of `*martian.Context` (intentional breaking change). Current Martian `ModifyRequest` creates one `FlowContext` using the martian context ID for BOTH ids, stores it under a private request-context key, and `ModifyResponse` retrieves it. Use `github.com/google/uuid` (already a dependency) only as a fallback flow id when no protocol adapter supplies one.
  - Do Not Modify: Martian setup, transport, certificate code, callback execution order.
  - Success: `ID`/`ConnectionID`/`IsSecure` return fixture values; 100 goroutines `Set`/`Get` unique keys under `-race`; request callback sets `callback-value=seen` and response callback reads it; callback API contains no martian type. Full detail: plan.md §Step P2.

- [ ] **P3 — Decouple certificate files and CA generation from Martian (depends on P1).** Add
  `func CACertPath(dir string) string` and `func CAKeyPath(dir string) string` to
  `pkg/certs/mitm.go` (return the on-disk `cacert.pem`/`cakey.pem` under `dir`). Replace
  `mitm.NewAuthority` in `generateCertificate` with stdlib `rsa.GenerateKey` +
  `x509.CreateCertificate`, preserving CA name `Proxify CA`, 2048 bits, one-year validity,
  CA/key usages, and current PEM formats / `0600` writes. Move `GetMitMConfig` into a new
  `pkg/certs/martian.go` bridge file so old serving still builds while core `mitm.go` no longer
  imports Martian. The package keeps its process-global `cert`/`pkey` populated by `LoadCerts`.
  - Do Not Modify: `/cacert`, runner CLI, or the candidate dependency.
  - Success: `LoadCerts(tempDir)` creates both exact filenames with a valid matching CA/key; a second `LoadCerts` preserves file hashes/mtimes; `SaveCAToFile` output equals `GetRawCA`; expired cert returns the documented error; cert core has no Martian import and current proxy tests still pass. Full detail: plan.md §Step P3.

- [ ] Run `go test ./...`, `go test -race ./...`, and `go vet ./...`; all clean before Proxify
  Phase 5.
