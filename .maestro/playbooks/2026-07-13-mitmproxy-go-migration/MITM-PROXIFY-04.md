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

- [x] **P2 — Introduce FlowContext, migrate callback types (depends on P1).** New
  `flow_context.go` defines `FlowContext` with a private `RWMutex`/value map, `id`,
  `connectionID`, `secure bool`, and exported methods exactly `ID`, `ConnectionID`, `Get`,
  `Set`, `IsSecure`; unexported constructor `newFlowContext(id, connectionID string, secure bool) *FlowContext`.
  - Change the callback typedefs (`OnRequestFunc`/`OnResponseFunc` at `proxy.go:46-47`) to accept `*FlowContext` instead of `*martian.Context` (intentional breaking change). Current Martian `ModifyRequest` creates one `FlowContext` using the martian context ID for BOTH ids, stores it under a private request-context key, and `ModifyResponse` retrieves it. Use `github.com/google/uuid` (already a dependency) only as a fallback flow id when no protocol adapter supplies one.
  - Do Not Modify: Martian setup, transport, certificate code, callback execution order.
  - Success: `ID`/`ConnectionID`/`IsSecure` return fixture values; 100 goroutines `Set`/`Get` unique keys under `-race`; request callback sets `callback-value=seen` and response callback reads it; callback API contains no martian type. Full detail: plan.md §Step P2.
  - ✅ **DONE 2026-07-13** — `flow_context.go` (struct with private `sync.RWMutex`+map, unexported `newFlowContext`, exactly 5 exported methods verified via `go doc`) + `flow_context_test.go` (accessors, Get/Set presence-absence, uuid-fallback-only-on-empty, 100-goroutine `-race`). Callback typedefs now `*FlowContext` (no martian token). Bridge: `ModifyRequest` builds one `FlowContext(ctx.ID(), ctx.ID(), req.TLS != nil)`, stores under unexported `flowContextKey` before the hijack/callback early-returns; `ModifyResponse` retrieves the same pointer. `types.UserData.ID` sourced from `flow.ID()`. `proxy_test.go` migrated off martian (import removed) + 2 new integration tests (shared-pointer `callback-value=seen`, distinct flow IDs). `go build`/`vet`/`test ./...` clean; `go test -race -run TestFlowContext` clean; `go mod tidy` promoted uuid to direct. **secure flag from `req.TLS != nil`**: martian fork has `MarkSecure()` commented out, so `Session().IsSecure()` is always false — `req.TLS` is the reliable TLS signal. Forge review: CLEAN on pointer-sharing, race-safety, uuid fallback, hijack/ordering. Root `go test -race ./.` still blocked by the pre-existing logger race (P1 FINDING), unchanged by P2.

- [x] **P3 — Decouple certificate files and CA generation from Martian (depends on P1).** Add
  `func CACertPath(dir string) string` and `func CAKeyPath(dir string) string` to
  `pkg/certs/mitm.go` (return the on-disk `cacert.pem`/`cakey.pem` under `dir`). Replace
  `mitm.NewAuthority` in `generateCertificate` with stdlib `rsa.GenerateKey` +
  `x509.CreateCertificate`, preserving CA name `Proxify CA`, 2048 bits, one-year validity,
  CA/key usages, and current PEM formats / `0600` writes. Move `GetMitMConfig` into a new
  `pkg/certs/martian.go` bridge file so old serving still builds while core `mitm.go` no longer
  imports Martian. The package keeps its process-global `cert`/`pkey` populated by `LoadCerts`.
  - Do Not Modify: `/cacert`, runner CLI, or the candidate dependency.
  - Success: `LoadCerts(tempDir)` creates both exact filenames with a valid matching CA/key; a second `LoadCerts` preserves file hashes/mtimes; `SaveCAToFile` output equals `GetRawCA`; expired cert returns the documented error; cert core has no Martian import and current proxy tests still pass. Full detail: plan.md §Step P3.
  - ✅ **DONE 2026-07-13** — `mitm.go`: martian import removed; `CACertPath`/`CAKeyPath` added (LoadCerts now uses them, so accessors point at the exact files it writes); `newAuthority` replicates martian's `mitm.NewAuthority` line-for-line via stdlib (CN+DNSNames `Proxify CA`, SHA-1 SubjectKeyId of PKIX pubkey, serial < 2^160, KeyEncipherment|DigitalSignature|CertSign + ServerAuth, backdated NotBefore, 2048 bits, 1-year validity; PEM formats/0600 unchanged). `GetMitMConfig` moved verbatim to new bridge `pkg/certs/martian.go` (proxy.go:513 still builds). New `mitm_test.go`: 6 tests covering all success probes + full authority-shape parity (NotBefore backdating, SubjectKeyId, DNSNames, serial bound). `go build`/`vet`/`test ./...` clean; `go test -race ./pkg/certs/` clean. Forge review: CLEAN (parity verified line-by-line against martian mitm.go:65-117); its one low-severity finding — 4 untested parity properties — closed with added assertions. Root `go test -race ./.` still blocked by pre-existing logger race (P1 FINDING), untouched by P3.

- [x] Run `go test ./...`, `go test -race ./...`, and `go vet ./...`; all clean before Proxify
  Phase 5.
  - ✅ **DONE 2026-07-13** — all three gates exit 0, zero `WARNING: DATA RACE` (stress-verified
    `-race -count=3` root + `-count=5` pkg/logger). Unblocked by fixing the P1-FINDING logger race
    at its ingestion point: `LogRequest`/`LogResponse` (pkg/logger/logger.go) now snapshot
    synchronously before enqueueing — `snapshotRequest` buffers the request body and hands live +
    queued copies independent readers (read errors preserved via `errReader`); `snapshotResponse`
    clones struct/Header/Trailer/Request and buffers a 4097-byte body prefix (AsyncWrite's
    ResponseChain 4096 cap +1 so oversize bodies trip the same partial-log path), live body
    replays prefix then streams the remainder (`compositeBody` keeps the original closer).
    `AsyncWrite`, on-disk formats, proxy.go, go.mod all untouched. 13 new tests in
    `pkg/logger/logger_test.go` incl. ResponseChain parity (locks the +1 boundary:
    `x-nuclei-ignore-error` marker at >4096, none at =4096) and live/snapshot error propagation.
    RootCauseAnalysis confirmed the fix kills all four race branches (request dump, response
    chain fill, post-enqueue `resp.Close` mutation, consumer-side ReadAlls). Forge review:
    race eliminated; its two test gaps closed same-run.
  - ⚠️ **KNOWN TRADEOFF (deferred to P15/logging rework):** snapshotting is synchronous in the
    modifier hooks — full request-body buffer before forwarding (parity with the old async
    `DumpRequest(req,true)` memory profile, but now blocks until the client body is read) and
    up to 4097 response bytes buffered before client delivery (delays first byte on slow
    streaming responses; note the old code *corrupted* streams instead — the async chain
    drained/closed the live body mid-delivery). Revisit when P15 reworks logger ownership.
