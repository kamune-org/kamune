# Build context: repo root
#   docker build -f cmd/relay/Dockerfile -t kamune-relay .

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
RUN cd cmd/relay && CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.version=${RELAY_VERSION}" \
    -o /relay .

# --- runtime ---

FROM alpine:3.23

RUN apk add --no-cache ca-certificates

COPY --from=builder /relay /usr/local/bin/relay

ENTRYPOINT ["relay"]
