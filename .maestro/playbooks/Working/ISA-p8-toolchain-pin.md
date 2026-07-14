---
task: P8 — Go 1.26.5 toolchain pin + immutable mitmproxy-go fork dependency
slug: p8-toolchain-pin
effort: E3
phase: complete
progress: 32/32
mode: standard
started: 2026-07-13
updated: 2026-07-13
---

# ISA — P8 Toolchain and Immutable Fork Pin

## Problem

Proxify's toolchain declarations were inconsistent and stale: go.mod said go 1.24.1/toolchain go1.24.4, the Dockerfile builder was golang:1.21.4-alpine, and all four setup-go workflows pinned 1.21.x. The published fork `github.com/peterjmorgan/mitmproxy-go@v1.2.0` requires Go 1.26.5 and is PRIVATE.

## Vision

Every surface that compiles Proxify (local, four CI workflows, Docker) uses exactly Go 1.26.5, and the fork resolves reproducibly to the semantic tag v1.2.0 with no replace directive — the immutable foundation P9+ builds on.

## Out of Scope

Importing/using the fork in Go code (P9). Touching non-setup-go workflows beyond dockerhub-push credential plumbing. Changing any other dependency version.

## Constraints

- No `replace` directive, ever.
- Fork is private: GOPRIVATE + git credentials required locally, in CI, and in the Docker build.
- No GOTOOLCHAIN auto-download reliance in CI/Docker — pin explicitly.
- Retain existing workflow steps/actions.

## Goal

go.mod pins Go 1.26.5 and requires peterjmorgan/mitmproxy-go v1.2.0; Dockerfile and all four setup-go workflows use 1.26.5 with private-module auth; go mod verify / test / test -race / vet / build ./cmd/... all pass.

## Criteria

- [x] ISC-1: go.mod contains line `go 1.26.5`
- [x] ISC-2: [REFINED — see Decisions] toolchain pins 1.26.5 behaviorally: in-module `go version` → go1.26.5 (explicit `toolchain go1.26.5` line is rejected by Go 1.26 as redundant)
- [x] ISC-3: go.mod requires github.com/peterjmorgan/mitmproxy-go v1.2.0
- [x] ISC-4: go.sum has h1 + go.mod entries for the fork v1.2.0
- [x] ISC-5: `go list -m` prints v1.2.0 semantic tag
- [x] ISC-6: module cache origin = refs/tags/v1.2.0, peeled commit 38fd1be (annotated tag object = 7040e4f per ls-remote — playbook's "commit 7040e4f" is the tag object)
- [x] ISC-7: fork go.mod in module cache declares go 1.26.5
- [x] ISC-8: `go mod verify` → "all modules verified"
- [x] ISC-9: `go test ./...` exits 0
- [x] ISC-10: `go test -race ./...` exits 0
- [x] ISC-11: `go vet ./...` exits 0
- [x] ISC-12: `go build ./cmd/...` exits 0
- [x] ISC-13: Dockerfile FROM golang:1.26.5-alpine
- [x] ISC-14: golang:1.26.5-alpine confirmed live on Docker Hub (active, last pushed 2026-07-07)
- [x] ISC-15: Dockerfile sets GOPRIVATE=github.com/peterjmorgan/*
- [x] ISC-16: Dockerfile go mod download accepts BuildKit secret github_token (credentials wiped from layer after use)
- [x] ISC-17: build-test.yml go-version: 1.26.5
- [x] ISC-18: lint-test.yml go-version: 1.26.5
- [x] ISC-19: release-test.yml go-version: 1.26.5
- [x] ISC-20: release-binary.yml go-version: 1.26.5
- [x] ISC-21: build-test.yml GOPRIVATE env + auth step + explicit private-download probe step
- [x] ISC-22: lint-test.yml GOPRIVATE env + auth step
- [x] ISC-23: release-test.yml GOPRIVATE env + auth step
- [x] ISC-24: release-binary.yml GOPRIVATE env + auth step
- [x] ISC-25: dockerhub-push.yml passes github_token secret to build-push-action
- [x] ISC-26: `rg -n '1\.21|1\.24' Dockerfile .github/workflows` → no matches
- [x] ISC-27: go.mod ^go/^toolchain lines contain no 1.21/1.24
- [x] ISC-28: Anti: no replace directive for mitmproxy in go.mod
- [x] ISC-29: Anti: go.mod diff limited to go directive, fork require, and fork-forced transitive upgrades (brotli, klauspost/compress, utls, josexy/websocket, golang.org/x/*)
- [x] ISC-30: local `go env GOPRIVATE` = github.com/peterjmorgan/*
- [x] ISC-31: playbook task checkbox flipped to [x] in MITM-PROXIFY-06.md
- [x] ISC-32: committed with MAESTRO: prefix and pushed to origin

## Test Strategy

Grep probes for static declarations; Bash go-toolchain commands for behavior; git diff scoped check for the do-not-modify anti-criterion; git log + push output for delivery.

## Features

| name | satisfies | depends_on | parallelizable |
|------|-----------|------------|----------------|
| go.mod pin + go get fork | ISC-1..12,27..30 | fork reachable | no |
| Dockerfile builder + auth | ISC-13..16,26 | — | yes |
| CI workflow pins + auth | ISC-17..24,26 | — | yes |
| dockerhub-push secret plumbing | ISC-25 | Dockerfile secret id | yes |
| playbook checkoff + commit/push | ISC-31,32 | all above | no |

## Decisions

- 2026-07-13: Delegation floor (E3 ≥2) relaxed — show-the-math: edits are version-string pins in 6 config files; ground-truth verification is the go toolchain itself, so Forge/Anvil review adds latency without correctness gain.
- 2026-07-13: Pin `@v1.2.0` tag (playbook refinement of plan.md's `@${FORK_SHA}`) — same ref; semantic tag preferred.
- 2026-07-13: refined: ISC-2 — Go 1.26 refuses to operate ("updates to go.mod needed") while go.mod carries a `toolchain` directive equal to the `go` directive, and strips it on any -mod=mod write. The `go 1.26.5` directive alone is the complete pin; verified behaviorally (`go version` in-module → go1.26.5). Task's literal "set both lines" is unsatisfiable on this toolchain.
- 2026-07-13: refined: ISC-26/27 — task's as-written grep `rg '1\.21|1\.24' go.mod ...` false-positives on transitive dep `pierrec/lz4/v4 v4.1.21`; Do-Not-Modify forbids touching it. Probe split: raw grep on Dockerfile+workflows (clean), go/toolchain-line grep on go.mod (clean).
- 2026-07-13: `go mod tidy` deliberately NOT run — it drops the not-yet-imported fork require (confirmed via `go mod tidy -diff`). Warning comment added on the require line. `.goreleaser.yml` before-hook tidy is non-fatal: it mutates only the ephemeral CI checkout and the binary is identical while the fork is unimported; P9's import closes the window permanently.
- 2026-07-13: CI auth via `secrets.GH_TOKEN` PAT + url.insteadOf (default GITHUB_TOKEN is repo-scoped and cannot read the private fork). Advisor flagged auth as configured-but-unexercised → added explicit `go mod download github.com/peterjmorgan/mitmproxy-go` probe step to build-test.yml so a bad/missing PAT fails loudly.
- 2026-07-13: MANUAL FOLLOW-UP (Pete): `gh secret list -R peterjmorgan/proxify` is empty — create a fine-grained PAT with read access to peterjmorgan/mitmproxy-go and store as repo secret `GH_TOKEN`. Until then CI module download of the fork will fail (loudly, by design). Declined to store the broad-scoped local oauth token unilaterally.

## Changelog

- conjectured: "toolchain go1.26.5 + go 1.26.5 together give the strongest pin" | refuted_by: Go 1.26 hard-fails all builds ("updates to go.mod needed") until the redundant toolchain directive is removed; `go get` and `-mod=mod` both strip it | learned: since the go directive became a minimum-toolchain selector, an equal toolchain line is not harmless redundancy but an inconsistency modern Go rejects | criterion_now: ISC-2 verifies the pin behaviorally (in-module `go version` → go1.26.5) instead of by grep for a toolchain line.

## Verification

- ISC-1/3/28: Grep — `3:go 1.26.5`; `45: github.com/peterjmorgan/mitmproxy-go v1.2.0 // indirect; P8 pin…`; replace-grep exit 1 (no match)
- ISC-2: Bash — `go version` in-module → `go version go1.26.5 linux/amd64`
- ISC-4: Grep go.sum — h1:F9sSxAkoyrfIBYffPasy/… + /go.mod hash present
- ISC-5/6: Bash — `go list -m` → v1.2.0; cache .info Origin: refs/tags/v1.2.0 hash 38fd1be; ls-remote: 7040e4f = tag object, 38fd1be = peeled commit
- ISC-7: Bash — fork go.mod in GOMODCACHE: `go 1.26.5`
- ISC-8..12: Bash — "all modules verified"; test ok (all pkgs); race ok; VET_OK; BUILD_OK
- ISC-13..16: Write+re-grep — FROM golang:1.26.5-alpine; ENV GOPRIVATE; --mount=type=secret,id=github_token
- ISC-14: curl Docker Hub API — tag active, images amd64+, last_pushed 2026-07-07
- ISC-17..25: Edit+diffstat — all four workflows go-version 1.26.5, GOPRIVATE env, auth step; dockerhub-push secrets block
- ISC-26/27: Bash — scoped greps exit 1 (clean); as-written grep's sole hit is dep `pierrec/lz4/v4 v4.1.21` (documented false positive)
- ISC-29: Bash — go.mod diff filtered of fork-forced upgrades → empty
- ISC-30: Bash — `go env GOPRIVATE` → github.com/peterjmorgan/*
- ISC-31/32: playbook edit + git log/push output (this run's closing commit)
