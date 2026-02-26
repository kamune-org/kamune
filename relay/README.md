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

## Endpoints

| Method   | Path             | Description                                      |
|----------|------------------|--------------------------------------------------|
| `GET`    | `/health`        | Health check (storage probe, uptime, identity)   |
| `GET`    | `/identity`      | Relay server's public key                        |
| `GET`    | `/ip`            | Client's public IP address                       |
| `POST`   | `/peers`         | Register a peer                                  |
| `GET`    | `/peers`         | Inquiry a peer by public key                     |
| `DELETE` | `/peers/{id}`    | Discard a peer registration                      |
| `POST`   | `/convey`        | Relay a message (direct delivery or auto-queue)  |
| `POST`   | `/queues`        | Push a message to the queue                      |
| `GET`    | `/queues`        | Pop a message from the queue                     |
| `GET`    | `/queues/length` | Peek at queue depth without consuming            |

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

- WebSocket support for persistent bidirectional relay connections
- Peer refresh / heartbeat for automatic TTL renewal
- Batch queue drain (pop multiple messages in one request)
- Webhook / callback notifications on message arrival
- Metrics and observability (Prometheus, OpenTelemetry)
- Support for group chats and multicast delivery