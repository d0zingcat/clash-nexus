# syntax=docker/dockerfile:1.7

ARG NODE_VERSION=25-alpine
ARG GO_VERSION=1.26.2-alpine

FROM node:${NODE_VERSION} AS web-builder
WORKDIR /src

RUN apk add --no-cache make
RUN npm install -g pnpm@11.0.8

COPY Makefile package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile

COPY components.json postcss.config.js tailwind.config.ts tsconfig.json vite.config.ts ./
COPY web ./web
RUN make web

FROM golang:${GO_VERSION} AS go-builder
WORKDIR /src

RUN apk add --no-cache make
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
COPY --from=web-builder /src/internal/web/static ./internal/web/static
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    make build-linux

FROM alpine:3.22 AS runtime
RUN addgroup -S clash && adduser -S clash -G clash && apk add --no-cache ca-certificates
USER clash
WORKDIR /app

COPY --from=go-builder /out/clash-nexus /usr/local/bin/clash-nexus

EXPOSE 8080
ENTRYPOINT ["clash-nexus"]
CMD ["serve", "-addr", "0.0.0.0:8080"]
