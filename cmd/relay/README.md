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

The default config enables WebSocket on `127.0.0.1:8888`, TCP on
`127.0.0.1:8889`, and TLS on `127.0.0.1:8890`. Edit
`assets/config.toml` to change.

## Configuration

Sections in `assets/config.toml`:

| Section      | Purpose                                                              |
| ------------ | -------------------------------------------------------------------- |
| `server`     | HTTP/WS bind address; `/health` and `/ip` exposure flags             |
| `ws`         | WebSocket transport on/off                                           |
| `tcp`        | Raw TCP transport on/off and address                                 |
| `tls`        | TLS transport on/off, address, and cert paths (see below)            |
| `session`    | Token/session TTLs, handshake timeout, concurrency cap, message size |
| `rate_limit` | Per-IP request quota; sliding window                                 |

## TLS / Certificates

Three modes, in order of effort:

### 1. In-memory self-signed (default — zero config)

Leave `tls.cert_file` and `tls.key_file` empty in the config. The relay
generates a fresh self-signed certificate at startup and keeps it in
memory only. Nothing is written to disk. Suitable for dev and local
testing. Clients will see a certificate verification error; pin the cert
or accept the warning on the client side.

### 2. On-disk self-signed

Generate a self-signed cert with `openssl`, then point the config at it:

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
enabled = true
address = "127.0.0.1:8890"
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
