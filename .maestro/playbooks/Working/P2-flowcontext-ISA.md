---
task: P2 — introduce FlowContext, migrate callback types off *martian.Context
slug: p2-flowcontext
effort: E3
phase: complete
progress: 36/36
mode: standard
started: 2026-07-13
updated: 2026-07-13
---

## Problem

Proxify's public library callback API (`OnRequestFunc`/`OnResponseFunc` at `proxy.go:46-47`)
exposes `*martian.Context`, hard-coupling every library consumer to the Martian serving engine.
The migration to the mitmproxy-go fork (P4+) cannot proceed while the callback surface leaks a
Martian type. There is no engine-neutral per-flow state carrier shared between the request and
response halves of a transaction.

## Vision

A library consumer writes callbacks against a small, obvious, Proxify-owned `FlowContext` —
sets a value on the request side, reads it on the response side, asks "which flow is this, which
connection, was it TLS?" — and never imports Martian. When P4 swaps the serving core, callback
code doesn't change at all.

## Out of Scope

- Any change to Martian setup, transports, certificate code, or callback execution order (P4+/P3).
- Real per-connection IDs distinct from flow IDs (protocol adapters supply those in P4+; here both ids come from the martian context ID).
- Graceful `Stop` (P16), the logger race fix (separate race-gate task), and cert decoupling (P3).

## Constraints

- Exported surface of `FlowContext` is exactly: `ID`, `ConnectionID`, `Get`, `Set`, `IsSecure`. Constructor stays unexported: `newFlowContext(id, connectionID string, secure bool) *FlowContext`.
- Internal state is a private `sync.RWMutex` + value map — never exposed.
- `github.com/google/uuid` (already in go.mod) is used ONLY as fallback flow id.
- Breaking the callback typedefs is intentional and confined to this repo (only `proxy_test.go` consumes them).
- Martian fork fact (verified): `session.MarkSecure()` is commented out — `req.TLS != nil` is the reliable TLS-termination signal.

## Goal

`flow_context.go` provides a race-safe, engine-neutral `FlowContext`; both callback typedefs
accept `*FlowContext`; ModifyRequest creates and stores one per flow under a private key,
ModifyResponse retrieves the same pointer; all tests (including a 100-goroutine `-race` probe)
pass and no martian type remains in the callback API.

## Criteria

### FlowContext type (flow_context.go)
- [ ] ISC-1: `flow_context.go` exists in package `proxify` (probe: Read)
- [ ] ISC-2: struct holds unexported `id`, `connectionID`, `secure` fields (probe: Read)
- [ ] ISC-3: struct holds unexported `sync.RWMutex` + `map[string]interface{}` (probe: Read)
- [ ] ISC-4: constructor is exactly `newFlowContext(id, connectionID string, secure bool) *FlowContext` (probe: Grep)
- [ ] ISC-5: `ID()` returns constructor id (probe: unit test)
- [ ] ISC-6: `ConnectionID()` returns constructor connectionID (probe: unit test)
- [ ] ISC-7: `IsSecure()` returns constructor secure (probe: unit test)
- [ ] ISC-8: `Get` returns `(value, true)` for a set key (probe: unit test)
- [ ] ISC-9: `Get` returns `(nil, false)` for a missing key (probe: unit test)
- [ ] ISC-10: `Set` uses write lock, `Get` uses read lock (probe: Read)
- [ ] ISC-11: empty id falls back to a google/uuid value (probe: unit test parses uuid)
- [ ] ISC-12: exported method set is exactly ID, ConnectionID, Get, Set, IsSecure — nothing else (probe: `go doc`/Grep)

### Callback typedef migration (proxy.go)
- [ ] ISC-13: `OnRequestFunc` signature is `func(*http.Request, *FlowContext) error` (probe: Grep)
- [ ] ISC-14: `OnResponseFunc` signature is `func(*http.Response, *FlowContext) error` (probe: Grep)
- [ ] ISC-15: typedef lines contain no `martian` token (probe: Grep)

### Martian bridge (ModifyRequest/ModifyResponse)
- [ ] ISC-16: ModifyRequest constructs one FlowContext with martian `ctx.ID()` for BOTH ids (probe: Read)
- [ ] ISC-17: secure flag derived from `req.TLS != nil` — true for MITM'd HTTPS (probe: Read + integration test)
- [ ] ISC-18: FlowContext stored under a private (unexported) key before any early return (probe: Read)
- [ ] ISC-19: ModifyResponse retrieves the SAME pointer for the flow (probe: integration test via Set/Get round-trip)
- [ ] ISC-20: `types.UserData.ID` populated from `FlowContext.ID()` (probe: Read)
- [ ] ISC-21: request callback invoked with the FlowContext (probe: integration test)
- [ ] ISC-22: response callback invoked with the FlowContext (probe: integration test)
- [ ] ISC-23: hijack path (`proxify` host) unchanged and still works (probe: existing TestCharacterizeCacert passes)

### Tests
- [ ] ISC-24: unit test asserts fixtures `flow-1`/`conn-1`/`true` via ID/ConnectionID/IsSecure (probe: go test)
- [ ] ISC-25: 100 goroutines Set/Get unique keys, clean under `-race` (probe: go test -race -run FlowContext)
- [ ] ISC-26: integration — request callback `Set("callback-value","seen")`, response callback `Get` reads `"seen"` (probe: go test)
- [ ] ISC-27: integration — two separate H1 requests receive distinct non-empty flow IDs (probe: go test)
- [ ] ISC-28: `proxy_test.go` updated to new signatures, P2 NOTE comment removed (probe: Grep)
- [ ] ISC-29: `proxy_test.go` no longer imports martian (probe: Grep count 0)

### Gates
- [ ] ISC-30: `go build ./...` clean (probe: Bash)
- [ ] ISC-31: `go vet ./...` clean (probe: Bash)
- [ ] ISC-32: `go test ./...` passes (probe: Bash)
- [ ] ISC-33: `go test -race` on FlowContext tests passes (probe: Bash)
- [ ] ISC-34: go.mod uuid dependency no longer marked indirect (probe: Grep)
- [ ] ISC-35: Anti: no change to `setupHTTPProxy`, round trippers, `pkg/certs`, or callback execution order (probe: git diff scope)
- [ ] ISC-36: Anti: `FlowContext` does not expose the values map or any martian/candidate type (probe: Read)

## Test Strategy

| isc | type | check | threshold | tool |
|-----|------|-------|-----------|------|
| 1-4, 10, 12, 16-18, 20, 36 | inspection | code shape matches spec | exact | Read/Grep |
| 5-9, 11, 24 | unit | accessor + map behavior | pass | go test -run TestFlowContext |
| 25, 33 | race | 100-goroutine Set/Get | race-clean | go test -race -run FlowContext |
| 19, 21-22, 26 | integration | Set on request / Get on response through live proxy | value "seen" observed | go test -run Callbacks |
| 27 | integration | distinct flow ids across requests | 2 unique non-empty | go test -run FlowID |
| 13-15, 28-29, 34 | inspection | typedefs/imports/go.mod | grep exact | Grep |
| 23, 30-32 | regression | full suite + build + vet | all pass | Bash |
| 35 | anti | diff touches only allowed files | scope respected | git diff --stat |

## Features

| name | description | satisfies | depends_on | parallelizable |
|------|-------------|-----------|------------|----------------|
| flow-context-type | new flow_context.go with struct, ctor, 5 methods | ISC-1..12 | — | no |
| callback-migration | typedefs + ModifyRequest/ModifyResponse bridge | ISC-13..23, 34 | flow-context-type | no |
| unit-tests | flow_context_test.go accessors/fallback/race | ISC-24..25 | flow-context-type | no |
| integration-tests | proxy_test.go signature update + Set/Get + distinct-ID tests | ISC-26..29 | callback-migration | no |
| gates | build/vet/test/race + scope check | ISC-30..36 | all | no |

## Decisions

- 2026-07-13 — ISA located in Maestro Working folder (not `MEMORY/WORK/`): Maestro hard rule restricts writes to the proxify tree; deviation documented here.
- 2026-07-13 — secure flag from `req.TLS != nil`: verified in the martian fork source that `MarkSecure()` is commented out, so `Session().IsSecure()` is always false; `req.TLS` IS set for TLS conns (proxy.go:584-589 of the fork).
- 2026-07-13 — FlowContext stored via martian `ctx.Set(privateKey, …)`: same per-request storage the existing `user-data` pattern uses; response side gets the same map entry via `NewContext(resp.Request)`. "Private request-context key" satisfied by an unexported const.
- 2026-07-13 — uuid fallback lives inside `newFlowContext`: single enforcement point; call sites stay clean.
- 2026-07-13 — show-your-math (delegation floor): task is single-file surgical + tests with a contained breaking change; a second delegation agent would add coordination cost inside a 10-min Maestro budget with no correctness gain. Forge attempted per E3 auto-include binding.
