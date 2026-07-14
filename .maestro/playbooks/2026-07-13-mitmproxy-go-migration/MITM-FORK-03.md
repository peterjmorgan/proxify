# mitmproxy-go Migration — Fork Phase 3: Verify and Publish Immutable SHA

**Repository:** the FORK `github.com/peterjmorgan/mitmproxy-go` (base `1c9f067`), run from a
fork checkout. Authoritative spec: `planning/mitmproxy-go-migration/plan.md` Step F8. Do this
only after `MITM-FORK-02.md` is green. This produces the immutable handoff the Proxify side
pins in P8 — never a branch, never a `replace` directive.

- [ ] **F8 — Verify the fork.** Add/finish one table-driven integration matrix in
  `mitm_test.go` covering: eager default, lazy H1, lazy H2, h2c prior knowledge, injected
  transport, passthrough, SOCKS5, and WebSocket. Fixtures: `/proto` returns the observed
  protocol, `/stream` sends `part1` then `part2` and trailer `X-End: done`, `/cancel` blocks
  until canceled, WS echoes `ping`; assert no public-internet access. Confirm public option
  docs state ownership/concurrency/default behavior. Run `gofmt`, `go mod tidy`,
  `go vet ./...`, `go test ./...`, and `go test -race ./...` — all clean.

- [ ] **F8 — Module rename (mechanical, final commit).** Keep the extension commits reviewable
  against the josexy base, then make ONE mechanical commit changing
  `module github.com/josexy/mitmproxy-go` → `module github.com/peterjmorgan/mitmproxy-go` in
  `go.mod` and rewriting every self-import (including `/buf`, `/internal/...`, `/metadata`) —
  use `rg 'github.com/josexy/mitmproxy-go'` to find all of them. This lets Proxify consume the
  fork without a replace directive. Do Not Modify the minimum Go version declared by the fork's
  own `go.mod` or third-party dependency versions except tidy-required changes.

- [ ] **F8 — Publish and record the SHA.** Commit all fork work, push to
  `github.com/peterjmorgan/mitmproxy-go`, and record `FORK_SHA=$(git rev-parse HEAD)`. Verify
  it descends from the base with `git merge-base --is-ancestor 1c9f067 "$FORK_SHA"`. Do NOT tag
  a mutable/pre-release branch as Proxify's dependency. Write the full `FORK_SHA` and the fork's
  declared Go version into `planning/mitmproxy-go-migration/` (or a handoff note) so the Proxify
  P8 task can consume both. Success: pristine validation output and a pushed immutable SHA
  available to Go modules. Full detail: plan.md §Step F8.
