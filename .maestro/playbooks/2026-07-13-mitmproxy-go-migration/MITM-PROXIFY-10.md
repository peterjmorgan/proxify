# mitmproxy-go Migration — Proxify Phase 10: Documentation and Release Verification

**Repository:** Proxify (this working directory). Authoritative spec:
`planning/mitmproxy-go-migration/plan.md` Step P18. Final phase; the callback API changed
(`*proxify.FlowContext`) and H2 is now semantically intercepted.

- [ ] **P18 — Docs and release-grade verification (depends on P17).** Update the README to
  document HTTP/1.1 / H2 / h2c support, H2 protocol translation, TLS passthrough, named TLS
  profiles, and that HTTP/3 is future work. Add a migration note: callbacks now accept
  `*proxify.FlowContext` (listing `ID`, `ConnectionID`, `Get`/`Set`, `IsSecure`) and `Stop` is
  idempotent and drains resources. Record the pinned fork tag `v1.2.0` (commit `7040e4f`) in the
  planning completion notes or a dependency comment (no mutable references). Verify all Go
  declarations in `go.mod`, Docker, and workflows equal `1.26.5` (the version pinned in P8) and
  are mutually consistent. Introduce no QUIC dependency or HTTP/3 claim.
  - Do Not Modify: unrelated command behavior, log schema, release action versions.
  - Note: the fork repo is PRIVATE, so `go mod verify` and the Docker build must have
    `GOPRIVATE=github.com/peterjmorgan/*` and git credentials available (see P8); the
    `docker build` needs those passed in (build secret / SSH mount) or the module fetch fails.
  - Success/verification: `gofmt` check; `go mod tidy` then a clean `git diff`; `go mod verify`; `go vet ./...`; `go test ./...`; `go test -race ./...`; `go build ./cmd/...`; `docker build -t proxify-mitmproxy-go-test .` succeeds with the declared builder; `go list -m github.com/peterjmorgan/mitmproxy-go` reports `v1.2.0` (commit `7040e4f`); `go mod graph` has no Martian; all 18 spec compatibility scenarios run with command/results attached to the final change summary; the working tree contains no generated test output. Full detail: plan.md §Step P18.
