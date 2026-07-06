# syntax=docker/dockerfile:1

# --- Build stage -------------------------------------------------------------
# Templates, static assets and SQL migrations are all embedded via go:embed,
# so the compiled binary is fully self-contained.
FROM golang:1.26-alpine AS build

WORKDIR /src

# Download dependencies first so this layer is cached unless go.mod/go.sum change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Build the statically-linked binary. CGO is off (all deps, including the
# modernc.org/sqlite driver, are pure Go), and -trimpath / -ldflags keep the
# binary small and reproducible.
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o /out/loupe ./cmd/loupe

# Pre-create a writable data directory owned by the non-root runtime user so the
# embedded SQLite backend (DB_DRIVER=sqlite) can create its database file. The
# distroless "nonroot" user is uid/gid 65532.
RUN mkdir -p /data && chown 65532:65532 /data

# --- Runtime stage -----------------------------------------------------------
# distroless/static ships CA certificates (needed for HTTPS calls to IdPs) and
# runs as an unprivileged user. No shell or package manager in the image.
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/loupe /usr/local/bin/loupe

# Writable directory for the embedded SQLite database (used when DB_DRIVER=sqlite).
# Mount a volume here to persist history/profiles across container restarts.
COPY --from=build --chown=65532:65532 /data /data
VOLUME ["/data"]

# The server binds to :8080 by default (LISTEN_ADDR).
EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/loupe"]
