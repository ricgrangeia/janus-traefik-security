# ── Stage 1: build ─────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /janus .

# ── Stage 2: minimal runtime ────────────────────────────────────────────
FROM scratch

COPY --from=builder /janus /janus
# CA certificates are needed for any HTTPS Traefik endpoints.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 9090

ENTRYPOINT ["/janus"]
