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

# Build the statically-linked binary. CGO is off (all deps are pure Go), and
# -trimpath / -ldflags keep the binary small and reproducible.
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o /out/loupe ./cmd/loupe

# --- Runtime stage -----------------------------------------------------------
# distroless/static ships CA certificates (needed for HTTPS calls to IdPs) and
# runs as an unprivileged user. No shell or package manager in the image.
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/loupe /usr/local/bin/loupe

# The server binds to :8080 by default (LISTEN_ADDR).
EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/loupe"]
