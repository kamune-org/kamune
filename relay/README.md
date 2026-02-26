# Relay

Relay acts as an intermediary server between peers of the Kamune project.

Kamune has been written to be peer-to-peer, without the need for any 3rd party
servers. On the other hand, NAT traversal techniques often need STUN or ICE
servers, and direct connection is not always a possibility. Therefore, this
project has been conceived to address such issues. Additionally, it may grow to
contain features beyond what Kamune was initially intended for.

## Features

- Public IP discovery
- Register and find other peers
- On-disk storage with [badger](https://github.com/hypermodeinc/badger)
- Rate limit via the embedded database
- Convey messages between peers with automatic fallback to queuing
- Store encrypted messages to enable non-realtime communication
- Queue and dequeue messages per sender/receiver/session tuple
- Configurable per-message size and per-queue length limits
- Health check endpoint with storage probe and uptime reporting
- WebSocket support for persistent bidirectional relay connections
- Peer refresh / heartbeat for automatic TTL renewal
- Batch queue drain (pop multiple messages in one request)
- Webhook / callback notifications on message arrival
- Metrics and observability (Prometheus-compatible `/metrics` endpoint)

## Endpoints

| Method   | Path             | Description                                      |
|----------|------------------|--------------------------------------------------|
| `GET`    | `/health`        | Health check (storage probe, uptime, identity)   |
| `GET`    | `/identity`      | Relay server's public key (multiple formats)     |
| `GET`    | `/ip`            | Client's public IP address                       |
| `GET`    | `/metrics`       | Prometheus-compatible metrics                    |
| `GET`    | `/ws`            | WebSocket endpoint for bidirectional relay       |
| `POST`   | `/peers`         | Register a peer                                  |
| `GET`    | `/peers`         | Inquiry a peer by public key                     |
| `DELETE` | `/peers/{id}`    | Discard a peer registration                      |
| `POST`   | `/peers/refresh` | Refresh peer TTL (heartbeat)                     |
| `POST`   | `/convey`        | Relay a message (direct delivery or auto-queue)  |
| `POST`   | `/queues`        | Push a message to the queue                      |
| `GET`    | `/queues`        | Pop a message from the queue                     |
| `GET`    | `/queues/length` | Peek at queue depth without consuming            |
| `GET`    | `/queues/batch`  | Pop multiple messages in one request             |
| `POST`   | `/webhooks`      | Register a webhook callback URL for a peer       |
| `DELETE` | `/webhooks`      | Remove a webhook registration                    |

## Identity

The `/identity` endpoint returns the relay server's public key. Use the
optional `format` query parameter to control the encoding:

```
GET /identity?format=<format>
```

| Format        | Description                                              | Example                                    |
|---------------|----------------------------------------------------------|--------------------------------------------|
| `base64`      | Base64 raw-URL encoding (default)                        | `MCowBQYDK2VwAyEA...`                      |
| `hex`         | Colon-separated uppercase hex bytes                      | `30:2A:30:05:06:03:...`                     |
| `emoji`       | 8 emoji symbols derived from a SHA-256 hash              | `😎 • 🔑 • 🍕 • 🐼 • 🎹 • 🌙 • ✨ • 🔒` |
| `fingerprint` | Base64 raw-URL encoded SHA-256 digest of the public key  | `qH7f9s...`                                 |

Response:

```json
{
  "identity": {
    "key": "MCowBQYDK2VwAyEA...",
    "format": "base64",
    "algorithm": "ed25519"
  }
}
```

The `format` parameter is case-insensitive and leading/trailing whitespace is
trimmed. An unrecognised value silently falls back to `base64`.

## WebSocket

The `/ws` endpoint upgrades an HTTP connection to a persistent WebSocket for
real-time bidirectional message relay. Connect with the peer's public key as a
query parameter:

```
GET /ws?key=<base64-raw-url-encoded-public-key>
```

### Inbound message types (client → server)

| Type      | Fields                               | Description                       |
|-----------|--------------------------------------|-----------------------------------|
| `message` | `receiver`, `session_id`, `data`     | Relay a message to another peer   |
| `ping`    | —                                    | Keepalive; server responds `pong` |

### Outbound message types (server → client)

| Type             | Description                                          |
|------------------|------------------------------------------------------|
| `connected`      | Handshake succeeded                                  |
| `message`        | Incoming message from another peer                   |
| `message_ack`    | Relayed message was delivered                        |
| `message_queued` | Relayed message could not be delivered and was queued |
| `pong`           | Response to a `ping`                                 |
| `error`          | Something went wrong processing a client message     |

All messages are JSON objects with a `type` field. Payloads use base64 raw URL
encoding, consistent with the REST API.

## Peer Refresh / Heartbeat

Peers can renew their registration TTL without re-registering by calling:

```
POST /peers/refresh?key=<base64-raw-url-encoded-public-key>
```

Optionally include a JSON body to update the peer's addresses:

```json
{
  "address": ["1.2.3.4:8080", "5.6.7.8:9090"]
}
```

If no body is provided, the existing addresses are preserved.

## Batch Queue Drain

Pop multiple messages in a single request:

```
GET /queues/batch?sender=<key>&receiver=<key>&session=<id>&limit=<n>
```

- `limit` is optional (default: 10, max: 100)
- Messages are returned in FIFO order
- Returns `204 No Content` if the queue is empty

Response:

```json
{
  "data": ["<base64-message-1>", "<base64-message-2>", "..."],
  "count": 2
}
```

## Webhooks

Register a callback URL to receive HTTP POST notifications when messages arrive
for a peer and are enqueued:

```
POST /webhooks
{
  "public_key": "<base64-raw-url-encoded-public-key>",
  "url": "https://example.com/hook"
}
```

Remove a registration:

```
DELETE /webhooks?key=<base64-raw-url-encoded-public-key>
```

Webhook payloads are JSON:

```json
{
  "event": "message_arrived",
  "sender": "<base64-public-key>",
  "receiver": "<base64-public-key>",
  "session_id": "...",
  "queue_len": 3,
  "timestamp": "2025-01-15T10:30:00Z"
}
```

Webhook delivery is best-effort and non-blocking — failures are logged but do
not affect message processing.

## Metrics

The `/metrics` endpoint exposes counters and gauges in the Prometheus text
exposition format. Key metrics include:

| Metric                                | Type    | Description                          |
|---------------------------------------|---------|--------------------------------------|
| `relay_uptime_seconds`                | gauge   | Time since server start              |
| `relay_http_requests_total`           | counter | Total HTTP requests (per route)      |
| `relay_http_request_errors_total`     | counter | HTTP 4xx/5xx responses (per route)   |
| `relay_http_request_duration_seconds_total` | counter | Cumulative request duration     |
| `relay_messages_relayed_total`        | counter | Messages delivered directly          |
| `relay_messages_queued_total`         | counter | Messages pushed to queues            |
| `relay_messages_popped_total`         | counter | Messages popped from queues          |
| `relay_peers_registered_total`        | counter | Peer registrations                   |
| `relay_peers_refreshed_total`         | counter | Peer TTL refreshes                   |
| `relay_rate_limit_hits_total`         | counter | Rate-limit rejections                |
| `relay_webhooks_fired_total`          | counter | Webhook notifications fired          |
| `relay_batch_drains_total`            | counter | Batch drain requests                 |
| `relay_ws_connections_active`         | gauge   | Active WebSocket connections         |
| `relay_ws_messages_in_total`          | counter | WebSocket messages received          |
| `relay_ws_messages_out_total`         | counter | WebSocket messages sent              |

## Configuration

The server is configured via a TOML file (default: `.assets/config.toml`):

```toml
[server]
identity = "ed25519"
address = "127.0.0.1:8888"
# delivery_timeout = "5s"  # optional; timeout for direct message delivery

[storage]
path = "./db"
log_level = "warn"
register_ttl = "30m"
max_message_size = 10240    # 10 KB per message; 0 = unlimited
max_queue_size = 10000      # max messages per queue; 0 = unlimited

[rate_limit]
enabled = true
time_window = "1m"
quota = 20
```

## Usage

```sh
# Run the relay server
make run

# Run with a custom config path
go run ./cmd/relay -config /path/to/config.toml

# Print version
go run ./cmd/relay -version

# Run tests
make test

# Regenerate protobuf
make gen-proto
```

## Building

Releases are built with [GoReleaser](https://goreleaser.com/):

```sh
goreleaser release --snapshot --clean
```

## Possible Future Additions

- Support for group chats and multicast delivery