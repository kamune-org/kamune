# Build context: repo root
#   docker build -f cmd/relay/Dockerfile -t kamune-relay .
#
# Default config is included; the container runs with no args or env vars.
# Override it by mounting a config at /etc/relay.toml. To use
# KAMUNE_RELAY_CONFIG instead, replace the entrypoint so relay runs without -c.
# The default config serves tls on 8890 and wss on 8891 (publish them with
# -p 8890:8890 -p 8891:8891). Plain tcp listens on the container's loopback
# only, and the UDP broker is off.
#
# The relay logs to stderr. Docker's default json-file driver keeps that log
# without limit, so cap it when running the container, for example:
#   docker run --log-opt max-size=10m --log-opt max-file=3 kamune-relay
#
# The relay runs as the unprivileged user relay (uid 10001) and needs no
# capabilities, as every default port is above 1024. It writes only to its
# home, the volume /var/lib/kamune-relay: the self-signed certificate for
# [tls] and [wss] goes in .config/kamune-relay there (see server.data_dir).
# Mount a named volume at /var/lib/kamune-relay so the certificate, and the
# fingerprint clients pin, survive re-creating the container. The rest of
# the file system can be read-only:
#   docker run --read-only --cap-drop=ALL \
#     -v kamune-relay:/var/lib/kamune-relay kamune-relay

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

RUN apk add --no-cache ca-certificates && \
    addgroup -g 10001 relay && \
    adduser -D -H -u 10001 -G relay -h /var/lib/kamune-relay \
        -s /sbin/nologin relay && \
    mkdir -m 0700 /var/lib/kamune-relay && \
    chown relay:relay /var/lib/kamune-relay

# Root owns the binary and the config, so the relay cannot change either.
COPY --from=builder /relay /usr/local/bin/relay
COPY cmd/relay/assets/config.toml /etc/relay.toml

ENV HOME=/var/lib/kamune-relay
USER 10001:10001
WORKDIR /var/lib/kamune-relay
VOLUME ["/var/lib/kamune-relay"]

ENTRYPOINT ["relay", "-c", "/etc/relay.toml"]
