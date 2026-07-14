# syntax=docker/dockerfile:1
# Base
FROM golang:1.26.5-alpine AS builder

RUN apk add --no-cache git build-base
WORKDIR /app
COPY . /app
# github.com/peterjmorgan/mitmproxy-go is a private module: bypass the Go proxy
# and authenticate to GitHub with a read-scoped PAT passed as a BuildKit secret:
#   docker build --secret id=github_token,env=GH_TOKEN .
ENV GOPRIVATE=github.com/peterjmorgan/*
RUN --mount=type=secret,id=github_token \
    sh -c 'if [ -s /run/secrets/github_token ]; then \
             git config --global url."https://x-access-token:$(cat /run/secrets/github_token)@github.com/".insteadOf "https://github.com/"; \
           fi; \
           go mod download; status=$?; rm -f ~/.gitconfig; exit $status'
RUN go build ./cmd/proxify

FROM alpine:3.18.2
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/proxify /usr/local/bin/

ENTRYPOINT ["proxify"]
