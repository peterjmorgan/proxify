# mitmproxy-go Migration — Proxify Phase 6: Toolchain and Immutable Fork Pin

**Repository:** Proxify (this working directory). Authoritative spec:
`planning/mitmproxy-go-migration/plan.md` Step P8.

**The fork is published.** Tag `v1.2.0` (commit `7040e4f`) on
`github.com/peterjmorgan/mitmproxy-go`, descends from the audited base `1c9f067`, and its
`go.mod` declares Go `1.26.5`. No `replace` directive is ever allowed.

**The fork repo is PRIVATE**, so `go get` / `go mod download` — locally, in CI, and inside the
Docker build — must be configured to reach it, or module resolution fails with a
`sum.golang.org` 404 / `git ... exit status 128`:
- `GOPRIVATE=github.com/peterjmorgan/*` (bypasses proxy.golang.org and sum.golang.org), and
- git auth for GitHub: SSH (`git config --global url."git@github.com:".insteadOf "https://github.com/"`) or a token in `~/.netrc` / `GH_TOKEN`.

- [ ] **P8 — Toolchain and pin.** Establish a reproducible toolchain and immutable module
  dependency.
  - Set `go.mod` `go 1.26.5` and `toolchain go1.26.5` (the fork's declared minimum, confirmed from its `go.mod`). Confirm the `golang:1.26.5-alpine` image tag exists on Docker Hub before pinning it; if not, use the newest published `1.26.x` patch that still satisfies the fork minimum and record which was used.
  - Configure GOPRIVATE + git auth (see header), then run `go get github.com/peterjmorgan/mitmproxy-go@v1.2.0` (equivalently the commit `@7040e4f`); commit the resulting `go.mod`/`go.sum`. No `replace` directive.
  - Set the Docker builder to `golang:1.26.5-alpine` (currently `golang:1.21.4-alpine`). Set every `setup-go` in `build-test.yml`, `lint-test.yml`, `release-test.yml`, `release-binary.yml` to `1.26.5` (these four are the only workflows running `setup-go`, each currently `go-version: 1.21.x`). Do not rely on GOTOOLCHAIN auto-download. CI and the Docker build also need GOPRIVATE + git credentials for the private fork (a CI secret / build SSH mount).
  - Do Not Modify: other dependency versions except tidy-required transitive changes.
  - Success: `go mod verify`; `go test ./...`; `go test -race ./...`; `go vet ./...`; `go build ./cmd/...` all pass. `go list -m github.com/peterjmorgan/mitmproxy-go` reports `v1.2.0` (a semantic tag — not a pseudo-version, since a tag was pinned). Scoped checks — `rg -n '1\.21|1\.24' go.mod Dockerfile .github/workflows` returns no matches, and `rg -n 'replace .*mitmproxy' go.mod` returns no matches. Full detail: plan.md §Step P8.
