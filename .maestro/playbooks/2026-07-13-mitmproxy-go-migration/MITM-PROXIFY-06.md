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

- [x] **P8 — Toolchain and pin.** Establish a reproducible toolchain and immutable module
  dependency.
  - Set `go.mod` `go 1.26.5` and `toolchain go1.26.5` (the fork's declared minimum, confirmed from its `go.mod`). Confirm the `golang:1.26.5-alpine` image tag exists on Docker Hub before pinning it; if not, use the newest published `1.26.x` patch that still satisfies the fork minimum and record which was used.
  - Configure GOPRIVATE + git auth (see header), then run `go get github.com/peterjmorgan/mitmproxy-go@v1.2.0` (equivalently the commit `@7040e4f`); commit the resulting `go.mod`/`go.sum`. No `replace` directive.
  - Set the Docker builder to `golang:1.26.5-alpine` (currently `golang:1.21.4-alpine`). Set every `setup-go` in `build-test.yml`, `lint-test.yml`, `release-test.yml`, `release-binary.yml` to `1.26.5` (these four are the only workflows running `setup-go`, each currently `go-version: 1.21.x`). Do not rely on GOTOOLCHAIN auto-download. CI and the Docker build also need GOPRIVATE + git credentials for the private fork (a CI secret / build SSH mount).
  - Do Not Modify: other dependency versions except tidy-required transitive changes.
  - Success: `go mod verify`; `go test ./...`; `go test -race ./...`; `go vet ./...`; `go build ./cmd/...` all pass. `go list -m github.com/peterjmorgan/mitmproxy-go` reports `v1.2.0` (a semantic tag — not a pseudo-version, since a tag was pinned). Scoped checks — `rg -n '1\.21|1\.24' go.mod Dockerfile .github/workflows` returns no matches, and `rg -n 'replace .*mitmproxy' go.mod` returns no matches. Full detail: plan.md §Step P8.
  - **COMPLETION NOTES (2026-07-13):** All success commands pass. Deviations/findings, each verified empirically:
    1. **No `toolchain go1.26.5` line** — Go 1.26 hard-fails every build ("updates to go.mod needed") while go.mod carries a toolchain directive equal to the go directive, and strips it on any module write. `go 1.26.5` alone is the complete pin (verified: in-module `go version` → go1.26.5).
    2. **Grep false positive** — the as-written grep's only hit is transitive dep `pierrec/lz4/v4 v4.1.21` in go.mod (a version string, untouchable per Do-Not-Modify). Dockerfile + workflows grep is clean; go.mod go/toolchain lines are clean.
    3. **Tag anatomy** — v1.2.0 is an annotated tag: `7040e4f` is the tag object, peeled commit is `38fd1be` (both confirmed via ls-remote). go.sum content-hash pins immutability regardless.
    4. **`go mod tidy` must NOT run until P9 imports the fork** — tidy drops the unimported require (confirmed with `tidy -diff`); warning comment added on the require line. The `.goreleaser.yml` tidy before-hook is non-fatal (mutates only the ephemeral CI checkout; binary identical while fork is unimported).
    5. **MANUAL STEP REQUIRED:** repo has no `GH_TOKEN` secret (`gh secret list` empty). Create a fine-grained PAT with read access to `peterjmorgan/mitmproxy-go` and add it as secret `GH_TOKEN` on `peterjmorgan/proxify`, else CI fork-download fails loudly (a probe step in build-test.yml was added deliberately to surface this). Docker builds need `--secret id=github_token,env=GH_TOKEN`.
    6. Advisor-driven hardening: explicit `go mod download github.com/peterjmorgan/mitmproxy-go` probe step in build-test.yml; Dockerfile wipes git credentials from the builder layer after `go mod download`.
