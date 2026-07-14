---
task: P1 — local characterization fixtures for Proxify (mitmproxy-go migration)
slug: p1-characterization-fixtures
effort: E3
phase: complete
progress: 35/36 (ISC-31 deferred)
mode: algorithm
started: 2026-07-13
updated: 2026-07-13
---

# ISA — P1 Local Characterization Fixtures

## Problem

Proxify has zero `*_test.go` files. The mitmproxy-go migration (P4–P18) will replace the
Martian serving core; without characterization tests pinning today's behavior, regressions
during the swap are undetectable. P1 is the safety net everything downstream depends on.

## Vision

`go test ./...` exercises the real proxy end-to-end on loopback — plain H1, MITM'd CONNECT,
callbacks, `/cacert`, passthrough — so any P4+ change that alters observable behavior fails
a named test immediately instead of surfacing in production.

## Out of Scope

DSL/match-replace tests (P11), upstream-proxy characterization (later phases — helpers are
built now but only smoke-tested), SOCKS listener characterization, FlowContext (P2), cert
decoupling (P3), any production-code change.

## Constraints

- Do Not Modify: `proxy.go` production behavior, `go.mod`, Docker, workflows.
- All network binds `127.0.0.1:0`-style ephemeral loopback; no external DNS/internet.
- Use `httptest` + stdlib `tls.Config`; do not copy candidate test helpers across modules.
- Martian remains the serving core; `Stop()` no-op recorded as SKIP, not encoded as desired.

## Goal

A reusable `internal/testutil/proxytest` fixture package plus root `proxy_test.go` that
start the current `Proxy` on ephemeral loopback with temp config/output dirs and pin H1,
HTTPS-CONNECT-MITM, callback, `/cacert`, and passthrough behavior — all tests green.

## Criteria

- [x] ISC-1: `internal/testutil/proxytest` compiles (`go build ./...`)
- [x] ISC-2: `NewCA(t)` exists, returns CA exposing an `*x509.CertPool`
- [x] ISC-3: CA-issued leaf serves TLS for 127.0.0.1 (self-test)
- [x] ISC-4: `NewH1Origin` negotiates exactly HTTP/1.1 over TLS (self-test)
- [x] ISC-5: `NewH2Origin` negotiates h2 with an h2 client (self-test)
- [x] ISC-6: `NewHTTPUpstream` tunnels CONNECT (self-test)
- [x] ISC-7: `NewHTTPUpstream` forwards absolute-form plain HTTP (self-test)
- [x] ISC-8: `NewHTTPUpstream` records hosts seen (self-test)
- [x] ISC-9: `NewSOCKS5Upstream` tunnels TCP via x/net SOCKS5 dialer (self-test)
- [x] ISC-10: every listening helper registers `t.Cleanup` (grep)
- [x] ISC-11: fixtures bind only 127.0.0.1 (grep for listen addrs)
- [x] ISC-12: `ProxyClient(t, proxyURL, caPool, forceH2)` routes via given proxy
- [x] ISC-13: `ProxyClient` with forceH2 can negotiate HTTP/2.0
- [x] ISC-14: root `proxy_test.go` in `package proxify` (internal access to `listenAddr` not required — free-port helper)
- [x] ISC-15: test proxy uses `t.TempDir()` for Directory and OutputDirectory
- [x] ISC-16: `certs.LoadCerts(tempDir)` called before `NewProxy` (grep + no Fatal exit)
- [x] ISC-17: H1: GET `http://origin/hello` via proxy → `200` body `hello`
- [x] ISC-18: H1: `br` pruned from Accept-Encoding before origin sees it
- [x] ISC-19: CONNECT MITM: GET https origin via proxy (proxify CA pool) → `200 hello`
- [x] ISC-20: CONNECT MITM: presented leaf issuer organization is `Proxify CA`
- [x] ISC-21: request callback header `X-Test: request` observed by origin
- [x] ISC-22: response callback header `X-Test: response` observed by client
- [x] ISC-23: GET `http://proxify/cacert` via proxy → `200` + attachment headers
- [x] ISC-24: `/cacert` body PEM-decodes and `x509.ParseCertificate` succeeds
- [x] ISC-25: `/cacert` cert Raw bytes equal on-disk `cacert.pem` cert
- [x] ISC-26: passthrough host: client sees ORIGIN cert, not Proxify CA
- [x] ISC-27: passthrough + forceH2: end-to-end HTTP/2.0 (ALPN passes opaquely)
- [x] ISC-28: non-passthrough origin under same config still MITM'd (issuer Proxify CA)
- [x] ISC-29: Stop no-op recorded as `t.Skip` TODO referencing P16 shutdown work
- [x] ISC-30: `go test ./...` passes
- [DEFERRED-VERIFY] ISC-31: root-package `go test -race` — blocked by pre-existing logger race (see Changelog); follow-up: MITM-PROXIFY-04 final checkbox. Fixture package race-clean.
- [x] ISC-32: `go vet ./...` clean
- [x] ISC-33: Anti: `git diff` touches no production file (`proxy.go`, `go.mod`, `go.sum`, Dockerfile, workflows unchanged)
- [x] ISC-34: Anti: no non-loopback URL/host in any new test file (grep)
- [x] ISC-35: playbook checkbox P1 flipped to `[x]` with note
- [x] ISC-36: `MAESTRO:`-prefixed commit pushed to `migrate-mitmproxy-go`

## Test Strategy

| isc | type | check | tool |
|---|---|---|---|
| 1–13 | unit/self-test | proxytest package self-tests + grep | `go test ./internal/...`, Grep |
| 14–29 | characterization | root proxy_test.go E2E over loopback | `go test .` |
| 30–32 | gate | full suite, race, vet | Bash |
| 33–34 | anti | git diff name-only, grep | Bash/Grep |
| 35–36 | process | file read-back, git log/push output | Read/Bash |

## Features

| name | satisfies | depends_on | parallelizable |
|---|---|---|---|
| proxytest CA + origins | ISC-1..5,10,11 | — | no |
| proxytest upstreams + client | ISC-6..13 | CA | no |
| proxy_test.go characterization | ISC-14..29 | proxytest | no |
| gates + commit | ISC-30..36 | all | no |

## Decisions

- 2026-07-13: ISA lives in `.maestro/playbooks/Working/` — Maestro write restriction
  (workdir-only) overrides the PAI `MEMORY/WORK` task-ISA home; inline scaffold instead of
  `Skill("ISA")` for the same reason.
- 2026-07-13: Tests pre-pick a free ephemeral port (listen on `127.0.0.1:0`, close, reuse)
  instead of reading `Proxy.listenAddr` from the `Run` goroutine — avoids a data race under
  `-race` without touching production code. Honors the loopback/ephemeral intent of ":0".
- 2026-07-13: FirstPrinciples (inline, Skill file not loaded — Maestro budget): a
  characterization test must pin what a CLIENT can observe, not internals. Irreducible
  observables: status/body, presented certificate chain (MITM vs passthrough), negotiated
  protocol (ALPN opacity), and header mutations (callbacks, br-pruning). All ISCs derive
  from these four observables.
- 2026-07-13: Delegation floor: Forge invoked post-build as diff reviewer (codex present).
  Second delegation slot skipped — show-your-math: characterization requires observing THIS
  live repo's behavior by execution; the test run itself is the stronger verifier.
- 2026-07-13: `Options.Elastic`/`Kafka` must be non-nil (logger dereferences `.Addr`
  unconditionally) — tests mirror `runner.NewRunner`'s construction.

## Changelog

- 2026-07-13 — conjectured: new characterization tests would run race-clean since they
  only add test code. refuted_by: `go test -race .` — pre-existing production race:
  `logger.LogRequest` enqueues the live `*http.Request` and the async `AsyncWrite`
  goroutine calls `httputil.DumpRequest(req, true)` (drains/replaces the body) while
  martian concurrently forwards the same request (`pkg/logger/logger.go:109,139` vs
  martian `roundTrip`). learned: proxify's async logging pipeline shares mutable request
  state across goroutines on EVERY logged transaction — the migration's logging step must
  snapshot synchronously before enqueueing. criterion_now: ISC-31 scoped to the new fixture
  package (race-clean); root-package `-race` is DEFERRED-VERIFY to this doc's final
  checkbox task, which must resolve the logger race first.

## Verification

- ISC-1..13: `go test ./internal/testutil/proxytest/` — 5/5 self-tests PASS (H1 ALPN,
  h2 ALPN, CONNECT tunnel+record, plain-forward+record, SOCKS5 tunnel+record).
- ISC-10/11: Grep — every listener helper registers `t.Cleanup`; only `127.0.0.1` binds.
- ISC-14..29: `go test . -v` — 5 PASS + 1 deliberate SKIP (TestCharacterizeStopIsNoOp,
  TODO references P16 shutdown).
- ISC-17: body `hello`, status 200 via proxy. ISC-18: `X-Echo-Accept-Encoding` contains
  no `br`. ISC-20/28: leaf issuer org `Proxify CA`. ISC-21/22: `X-Echo-Test: request`,
  `X-Test: response`. ISC-24/25: served PEM parses and `Equal`s on-disk `cacert.pem`.
  ISC-26/27: passthrough leaf issuer `Proxytest CA` + `ProtoMajor == 2` (opaque ALPN).
- ISC-30: `go test ./...` → ok both packages. ISC-32: `go vet ./...` clean.
- ISC-31: `[DEFERRED-VERIFY]` for root package — pre-existing logger race (see Changelog);
  follow-up: MITM-PROXIFY-04 final checkbox (race gate before Phase 5). Fixture package
  itself race-clean: `go test -race ./internal/testutil/proxytest/` → ok.
- ISC-33: `git status` — only new test files + playbook/ISA docs; `proxy.go`, `go.mod`,
  Dockerfile, workflows untouched. ISC-34: loopback grep clean.
- Forge (GPT-5.4) cross-review: 3 findings — #2 (missing `resp2.TLS` nil-guard) and
  #3 (`t.Logf` from hijacked-tunnel goroutine) fixed; #1 (freeAddr TOCTOU can
  `gologger.Fatal` the binary if the port is stolen between close and re-listen)
  accepted as structural until P10 gives `Run` pre-bound listeners — documented here.
- ISC-35/36: playbook checkbox flipped + MAESTRO commit pushed (evidence in git log).
