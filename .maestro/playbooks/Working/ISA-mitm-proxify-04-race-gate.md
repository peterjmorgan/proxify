---
task: MITM-PROXIFY-04 final gate — go test / go test -race / go vet all clean
slug: mitm-proxify-04-race-gate
effort: E3
phase: complete
progress: 32/32
mode: task
started: 2026-07-13
updated: 2026-07-13
---

# ISA — Proxify Phase 4 Gate: race-clean test suite

## Problem

`go test -race ./...` fails on a pre-existing production race (documented as the P1
FINDING): `pkg/logger` enqueues the live `*http.Request`/`*http.Response` into its async
queue; `AsyncWrite` then mutates them (`DumpRequest` rewrites `req.Body`;
`ResponseChain.Fill` drains and closes `resp.Body`) concurrently with Martian forwarding
the request and copying the response to the client. Fires on every logged transaction.
The Phase 4 gate (all three Go verification commands clean) is blocked until the logger
snapshots synchronously before enqueueing.

## Vision

Phase 5 starts from a repo where every `go test -race ./...` run is boringly green, and
the logger's async boundary carries only owned snapshots — no latent landmine for the
P11–P14 compatibility suites that rerun `-race` repeatedly.

## Out of Scope

Logger shutdown/drain semantics (P15). Logger on-disk output format changes. The Stop
no-op (P16). Any serving-path change — Martian remains the core. Streaming-logger rework
(tee-based capture) — deferred to the migration's logging steps.

## Constraints

- Fix lives in `pkg/logger` (the ingestion boundary), not in callers.
- `AsyncWrite` consumer logic unchanged — snapshot must satisfy it as-is.
- ResponseChain 4096 body cap behavior preserved (oversize bodies still fail to log the
  body, exactly as today); client delivery must carry the FULL body.
- No new dependencies; `go.mod` untouched.
- Maestro write boundary: all files under the project tree.

## Goal

`go test ./...`, `go test -race ./...`, and `go vet ./...` all exit 0 on branch
`migrate-mitmproxy-go`, achieved by snapshotting requests/responses synchronously in
`LogRequest`/`LogResponse` before enqueueing, verified by new focused logger tests.

## Criteria

- [x] ISC-1: `go vet ./...` exits 0 (Bash)
- [x] ISC-2: `go test ./...` exits 0, all packages ok (Bash)
- [x] ISC-3: `go test -race ./...` exits 0 (Bash)
- [x] ISC-4: `go test -race .` output contains zero `WARNING: DATA RACE` (Bash grep)
- [x] ISC-5: `LogRequest` enqueues `snapshotRequest(req)`, never the live pointer (Read logger.go)
- [x] ISC-6: `LogResponse` enqueues a `snapshotResponse(resp)` clone (Read logger.go)
- [x] ISC-7: after `snapshotRequest`, live `req.Body` yields the original bytes (go test)
- [x] ISC-8: snapshot clone body is an independent reader — concurrent dump + live read race-free (go test -race)
- [x] ISC-9: clone `GetBody` is nil — no shared rewind func crosses the boundary (go test)
- [x] ISC-10: nil / `http.NoBody` request body passes through without panic (go test)
- [x] ISC-11: request body read error is preserved for the live consumer (go test)
- [x] ISC-12: response body > 4096 bytes — client still receives ALL bytes (go test)
- [x] ISC-13: response snapshot prefix capped at 4097 bytes (go test)
- [x] ISC-14: response body ≤ 4096 — clone and live both yield full body (go test)
- [x] ISC-15: `resp.Close = true` after snapshot does not alias the clone (go test — RCA Branch C)
- [x] ISC-16: response Header map cloned, not shared (go test)
- [x] ISC-17: response Trailer map cloned, not shared (Read logger.go)
- [x] ISC-18: response entries carry a snapshotted `Request`, not `resp.Request` live (Read)
- [x] ISC-19: closing the live wrapped response body closes the original upstream body (go test)
- [x] ISC-20: `AsyncWrite` body unchanged (git diff shows no hunk in AsyncWrite)
- [x] ISC-21: `proxy.go` untouched (git diff --stat)
- [x] ISC-22: `go.mod`/`go.sum` untouched (git diff --stat)
- [x] ISC-23: characterization suite passes under `-race` (`go test -race -run TestCharacterize .`)
- [x] ISC-24: `go test -race ./pkg/certs/` still clean (Bash)
- [x] ISC-25: `go test -race -run TestFlowContext .` still clean (Bash)
- [x] ISC-26: new logger tests pass under `-race` (`go test -race ./pkg/logger/...`)
- [x] ISC-27: Anti: no mutex/lock added around `DumpRequest` — symptom patch rejected (Grep logger.go)
- [x] ISC-28: Anti: `pkg/logger/file/file.go` untouched — on-disk format preserved (git diff)
- [x] ISC-29: Anti: Stop no-op SKIP in proxy_test.go remains a SKIP, not encoded as desired (Grep)
- [x] ISC-30: playbook checkbox flipped to `[x]` with completion notes (Read MITM-PROXIFY-04.md)
- [x] ISC-31: commit exists with `MAESTRO: ` prefix containing the fix (git log)
- [x] ISC-32: branch pushed — `git status` shows not ahead of origin (Bash)

## Test Strategy

| isc | type | check | threshold | tool |
|-----|------|-------|-----------|------|
| 1–4 | gate | command exit code + race-warning grep | exit 0 / 0 matches | Bash |
| 5–6, 17–18 | code | snapshot call sites in enqueue path | present | Read/Grep |
| 7–16, 19 | unit | new `pkg/logger/logger_test.go` under `-race` | all PASS | go test -race |
| 20–22, 27–29 | anti | diff/grep confinement | no hits | git diff / Grep |
| 23–26 | regression | existing suites under `-race` | exit 0 | Bash |
| 30–32 | process | doc + VCS state | present | Read / git |

## Features

| name | satisfies | depends_on | parallelizable |
|------|-----------|------------|----------------|
| snapshot primitives (`snapshotRequest`/`snapshotResponse` + body wrappers) | 5–19 | — | no |
| wire into `LogRequest`/`LogResponse` | 5, 6, 18 | primitives | no |
| focused logger tests | 7–16, 19, 26 | wiring | no |
| full gate run | 1–4, 20–29 | tests | no |
| doc + commit + push | 30–32 | gates | no |

## Decisions

- 2026-07-13: Snapshot-at-enqueue in `pkg/logger` chosen over mutex-around-DumpRequest
  (stdlib transport isn't lock-aware; doesn't restore ownership) and over caller-side
  snapshots (leaves the queue contract unsafe for future producers). RootCauseAnalysis
  5-Whys confirmed ingestion-point fix; kills all four race branches (request dump,
  response chain fill, post-enqueue `resp.Close` mutation, consumer-side ReadAlls).
- 2026-07-13: Response snapshot buffers a 4097-byte prefix only (matches AsyncWrite's
  hardcoded 4096 ResponseChain cap +1 so oversize bodies trip the same error path),
  then hands the client a replay-then-stream body. Preserves logging semantics exactly,
  bounds memory, fixes today's corruption where the async chain drains/closes the live
  body mid-delivery.
- 2026-07-13: Request snapshot buffers the full body — parity with existing
  `DumpRequest(req, true)` semantics; the DSL path (`util.HTTPRequestToMap`) already
  ReadAlls request bodies synchronously, so this matches established codebase behavior.
- 2026-07-13: Delegation floor (E3 soft ≥2) relaxed to 1 — show-math: the diff is one
  file plus tests; Forge (GPT-5.4) provides the cross-vendor review; a second delegate
  (Anvil) would re-review the same ~100 lines with no independent signal source.
- 2026-07-13: ISA written to the playbook Working folder — Maestro hard write boundary
  prohibits `~/.claude/PAI/MEMORY/`; noted per file-access rules.

## Verification

- ISC-1–3: Bash — `FINAL GATES: test=0 race=0 vet=0` (full module, post-fix)
- ISC-4: Bash grep — `race-warnings=0`; stress `-race -count=3 .` and `-count=5 ./pkg/logger/` also 0
- ISC-5–6, 17–18: Read logger.go — enqueue sites pass `snapshotRequest(req)` / `snapshot` + `snapshot.Request`; `clone.Trailer = resp.Trailer.Clone()`
- ISC-7–16, 19: go test -race ./pkg/logger/ — 13 tests PASS ×2 (`TestSnapshotRequest*`, `TestSnapshotResponse*`, `TestLoggerEndToEndRaceFree`); 10KB body `bytes.Equal` locks the replay seam; ChainParity subtest locks the 4096/4097 boundary incl. `x-nuclei-ignore-error` marker
- ISC-20: git diff grep — `Mutex` 0 hits; AsyncWrite hunk absent (comment refs only)
- ISC-21–22, 28: `git diff --stat -- proxy.go go.mod go.sum pkg/logger/file/` → empty
- ISC-23–26: contained in full `-race` run — root, proxytest, certs, logger all `ok`
- ISC-27: Grep — no lock added; snapshot-at-enqueue instead (RCA-confirmed)
- ISC-29: Grep proxy_test.go:375 — `t.Skip("TODO(migration P16)...` intact
- ISC-30: Edit applied to MITM-PROXIFY-04.md final checkbox with notes + tradeoff record
- ISC-31–32: git — commit `b93fa6e` "MAESTRO: P4 gate — fix logger data race..."; pushed `d106e05..b93fa6e`, status shows branch level with origin

## Changelog

- conjectured: the P1 FINDING's request-side race was the only `-race` blocker.
  refuted_by: RootCauseAnalysis 5-Whys — same run also races on ResponseChain.Fill
  (Branch B) and latently on post-enqueue `resp.Close` mutation (Branch C).
  learned: the defect class is "live single-owner net/http objects crossing an async
  boundary", not one bad dump call; any fix short of ownership transfer leaves branches.
  criterion_now: ISC-15 (Close decoupling) and ISC-18 (snapshotted Request on response
  entries) exist specifically to pin the non-reported branches.
