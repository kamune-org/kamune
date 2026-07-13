# Build context: repo root
#   docker build -f cmd/relay/Dockerfile -t kamune-relay .
#
# Default config is included; the container runs with no args or env vars.
# Override by mounting a config at /etc/kamune/relay.toml or setting the
# KAMUNE_RELAY_CONFIG env var.

FROM golang:1.26-alpine AS builder

WORKDIR /src

# Cache dependencies — copy only module manifests first.
# Root go.mod must exist before relay's replace directive can resolve.
COPY go.mod go.sum ./
COPY cmd/relay/go.mod cmd/relay/go.sum cmd/relay/

RUN go mod download
RUN cd cmd/relay && go mod download

# Copy source and build.
COPY . .

ARG RELAY_VERSION=dev
RUN cd cmd/relay && \
    VERSION="${RELAY_VERSION}" && \
    if [ "$VERSION" = "dev" ] && [ -f VERSION ]; then \
        VERSION="$(cat VERSION)"; \
    fi && \
    CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /relay .

# --- runtime ---

FROM alpine:3.23

RUN apk add --no-cache ca-certificates

COPY --from=builder /relay /usr/local/bin/relay
COPY cmd/relay/assets/config.toml /etc/relay.toml

ENTRYPOINT ["relay", "-c", "/etc/relay.toml"]
