# Kamune Relay

A stateless, blind session switch for the kamune secure messaging library.
The relay forwards encrypted traffic between two kamune peers without
being able to read it; it never sees plaintext, identity, or session
content. Transports: WebSocket, raw TCP, and TLS-wrapped variants of
both. Optional pre-shared key (PSK) authentication on registration.

**Protocol details** — see [`docs/SPEC.md`](../../docs/SPEC.md) (cipher
suite, exchange, handshake, message framing).

## Quick start

```bash
go run .                              # uses assets/config.toml
```

Or build and run:

```bash
go build -o relay .
./relay
```

The default config enables diagnose on `127.0.0.1:9090`, plain WebSocket on
`127.0.0.1:8888`, raw TCP on `127.0.0.1:8889`, kamune-over-TLS on
`127.0.0.1:8890`, and WSS on `127.0.0.1:8443`. Edit `assets/config.toml` to
change.

## Configuration

Sections in `assets/config.toml`:

| Section      | Fields                                                                                         | Notes                                                             |
| ------------ | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `server`     | `password`                                                                                     | Relay-wide PSK.                                                   |
| `diagnose`   | `enabled`, `address`                                                                           | Plain HTTP, always serves `/health` when enabled. Admin audience. |
| `ws`         | `enabled`, `address`                                                                           | Plain WebSocket, always serves `/ws`. Peer audience.              |
| `tcp`        | `enabled`, `address`                                                                           | Raw kamune-over-TCP. Peer audience.                               |
| `tls`        | `enabled`, `address`, `cert_file`, `key_file`                                                  | Raw kamune-over-TLS.                                              |
| `wss`        | `enabled`, `address`, `cert_file`, `key_file`                                                  | WebSocket over TLS, always serves `/ws`. Peer audience.           |
| `broker`     | `enabled`, `address`, `registration_ttl`                                                       | UDP signaling (STUN-like IP echo + signal intro). Off by default. |
| `session`    | `token_ttl`, `session_ttl`, `handshake_timeout`, `max_concurrent_sessions`, `max_message_size` |                                                                   |
| `rate_limit` | `disabled`, `time_window`, `quota`, `max_entries`                                              | Rate limit is **on** out of the box.                              |

At least one of `diagnose`, `ws`, `tcp`, `tls`, `wss`, or `broker` must
be enabled. The relay exits with status 1 otherwise.

### Listener matrix

| `ws` | `tcp` | `tls` | `wss` | `diagnose` | Listeners                   |
| ---- | ----- | ----- | ----- | ---------- | --------------------------- |
| ✓    | ✗     | ✗     | ✗     | ✗          | ws:8888                     |
| ✓    | ✓     | ✗     | ✗     | ✗          | ws:8888, tcp:8889           |
| ✓    | ✓     | ✓     | ✗     | ✗          | ws:8888, tcp:8889, tls:8890 |
| ✓    | ✓     | ✗     | ✓     | ✗          | ws:8888, tcp:8889, wss:8443 |
| ✓    | ✓     | ✓     | ✓     | ✓          | all 5                       |
| ✗    | ✓     | ✗     | ✓     | ✗          | tcp:8889, wss:8443          |
| ✗    | ✗     | ✗     | ✗     | ✗          | error: "no server enabled"  |

## TLS / Certificates

The `[tls]` and `[wss]` blocks are independent listeners with their own cert
settings. Each can be in one of three modes:

### 1. In-memory self-signed (default — zero config)

Leave `cert_file` and `key_file` empty in the block. The relay generates a fresh
self-signed certificate at startup and keeps it in memory only. Nothing is
written to disk. Suitable for dev and local testing. Clients will see a
certificate verification error; pin the cert or accept the warning on the client
side.

When both `[tls]` and `[wss]` are enabled with empty paths, the relay generates
two independent in-memory certs (one per listener). The two listeners present
different identities to clients. Operators who want the same identity on both
should point both blocks at the same on-disk cert.

### 2. On-disk self-signed

Generate a self-signed cert with `openssl`, then point the block at it:

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout assets/cert/server.key \
  -out    assets/cert/server.crt \
  -days 3650 -nodes \
  -subj "/CN=kamune-relay"
```

Then in `assets/config.toml`:

```toml
[tls]
enabled   = true
address   = "127.0.0.1:8890"
cert_file = "assets/cert/server.crt"
key_file  = "assets/cert/server.key"

[wss]
enabled   = true
address   = "127.0.0.1:8443"
cert_file = "assets/cert/server.crt"
key_file  = "assets/cert/server.key"
```

The relay **hard-errors on startup** if the configured cert is missing
or invalid — it never auto-generates or overwrites files at runtime.

### 3. Production cert

Replace the self-signed cert with one from a real CA (Let's Encrypt,
internal CA, etc.). Format must be PEM-encoded. The key file must be
`0600` and readable by the relay process. Same hard-error behavior as
mode 2.

## Cross-Transport Sessions

Sessions are transport-agnostic — any two peers that share a token can be
bridged across any of `ws`, `wss`, `tcp`, or `tls`. See
[`docs/RELAY.md`](../../docs/RELAY.md#cross-transport-sessions) for details.

## Broker (UDP signaling)

A single UDP listener that combines two functions needed for P2P hole-punching:
a STUN-like IP echo and signal introduction.

- **IP echo**: peer sends a 6-byte request, broker responds with the peer's
  perceived public IP:port (ASCII `ip:port\0`).
- **Signal introduction**: peer registers with a shared token (random or
  precomputed); when a second peer registers with the same token, both are
  notified of each other's claimed IP:port and ephemeral X25519 public key so
  they can attempt a direct UDP hole-punch.

The broker uses X25519 + XChaCha20-Poly1305 with a per-NOTIFY fresh ephemeral
broker key (forward secrecy). The wire format is small (60-byte REGISTER;
99/133-byte NOTIFYs) and the broker does not see plaintext, identities, or
public keys beyond what peers explicitly share.

## Build

```bash
make run                              # go run .
make test                             # go test -v ./...
bash scripts/build.sh                 # cross-platform release binaries
```

`scripts/build.sh` honors `RELAY_VERSION`, `RELAY_PLATFORMS`, and
`RELAY_DIST_DIR` env vars; outputs to `dist/relay/` and zips to
`dist/`.

## Testing

```bash
go test -v ./...
```

Tests use real implementations, interfaces, and standard `testing.T` —
no mocks. Assertions use `testify` (`assert` and `require`).

## Related

- [`docs/SPEC.md`](../../docs/SPEC.md) — protocol specification
- [`cmd/tui/`](../tui/) — Bubble Tea terminal client
- [`cmd/bus/`](../bus/) — Wails GUI client
- [`cmd/daemon/`](../daemon/) — JSON-over-stdio daemon
