# ── Stage 1: build ─────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Copy module definition first — no external deps so no go.sum exists.
COPY go.mod ./

# Copy all source code.
COPY . .

# -mod=mod allows Go to resolve modules without a pre-existing go.sum.
# This is safe here because we have zero external dependencies.
RUN CGO_ENABLED=0 GOOS=linux go build -mod=mod -ldflags="-s -w" -o /janus ./cmd/janus

# ── Stage 2: minimal runtime ────────────────────────────────────────────
FROM scratch

COPY --from=builder /janus /janus
# CA certificates are needed for HTTPS connections to Traefik endpoints.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 9090

ENTRYPOINT ["/janus"]
