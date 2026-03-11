### ─── Build stage ────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.26.1-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH

RUN apk add --no-cache git

WORKDIR /app

# Cache dependency downloads separately from source changes
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w" \
    -o noxway .

### ─── Final image ────────────────────────────────────────────────────────────
FROM alpine:3.20

# ca-certificates: required for outbound HTTPS requests to backends
# tzdata: correct timezone handling in logs
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S noxway && \
    adduser  -S -G noxway noxway

WORKDIR /app
RUN mkdir -p certs log && chown -R noxway:noxway /app

COPY --from=builder /app/noxway /app/noxway

USER noxway

EXPOSE 8080 443 80

CMD ["./noxway"]
