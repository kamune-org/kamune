# Kamune Relay

A stateless, blind session switch for the kamune secure messaging library.
The relay forwards encrypted traffic between two kamune peers and cannot read
their messages. A relay that forwards that traffic unchanged sees no identities
either; an active one can read the peers' names and public keys (see
[Threat Model](../../docs/RELAY.md#threat-model)). Transports: WebSocket, raw
TCP, and TLS-wrapped variants of both. Optional pre-shared key (PSK)
authentication on registration.

**Protocol details** — see [`docs/SPEC.md`](../../docs/SPEC.md) (cipher suite,
exchange, handshake, message framing).

## Quick start

```bash
go run . -c assets/config.toml
```

Or build and run:

```bash
go build -o relay .
./relay -c assets/config.toml
```

The default config enables kamune-over-TLS on `0.0.0.0:8890`, WSS on
`0.0.0.0:8891`, and raw TCP on `127.0.0.1:8889` (loopback only). The UDP
broker, the diagnose listener and plain WebSocket (`127.0.0.1:8888` when
enabled) are off. Plain TCP and WebSocket carry no TLS, so a client cannot tell
the relay from an impostor on the path; expose them only on a network you
trust, such as a LAN or VPN, or to a reverse proxy on the same host. Edit
`assets/config.toml` to change these defaults.

## Docker

Build the image from the repository root and run it:

```bash
docker build -f cmd/relay/Dockerfile -t kamune-relay .
docker run --read-only --cap-drop=ALL \
  --log-opt max-size=10m --log-opt max-file=3 \
  -p 8890:8890 -p 8891:8891 \
  -v kamune-relay:/var/lib/kamune-relay kamune-relay
```

The image runs the relay as the unprivileged user `relay` (uid 10001) with the
shipped config at `/etc/relay.toml`, so it serves only tls (8890) and wss
(8891) to the outside: raw TCP listens on the container's loopback and the
broker is off. Earlier images served raw TCP on all addresses and enabled the
broker; to keep either, mount a config of your own at `/etc/relay.toml` (and
publish `4788/udp` for the broker).

The only place the relay writes is its home, the volume
`/var/lib/kamune-relay`, which holds the self-signed certificate. Keep it in a
named volume so the certificate, and the fingerprint clients pin, survive
re-creating the container. The relay logs to stderr, and Docker's default
`json-file` log driver keeps that log without limit, hence the `--log-opt`
flags.

## Configuration

Sections in `assets/config.toml`:

| Section      | Fields                                                                                         | Notes                                                                              |
| ------------ | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `server`     | `password`, `trusted_proxies`, `client_ip_header`, `data_dir`, `log_level`                     | Relay-wide PSK, proxy CIDRs and client address header, state directory, log level. |
| `diagnose`   | `enabled`, `address`                                                                           | Plain HTTP, always serves `/health` when enabled. Admin audience.                  |
| `ws`         | `enabled`, `address`                                                                           | Plain WebSocket, always serves `/ws`. Peer audience.                               |
| `tcp`        | `enabled`, `address`                                                                           | Raw kamune-over-TCP. Peer audience.                                                |
| `tls`        | `enabled`, `address`, `cert_file`, `key_file`                                                  | Raw kamune-over-TLS.                                                               |
| `wss`        | `enabled`, `address`, `cert_file`, `key_file`                                                  | WebSocket over TLS, always serves `/ws`. Peer audience.                            |
| `broker`     | `enabled`, `address`, `registration_ttl`                                                       | UDP signaling (STUN-like IP echo + signal intro). Off by default.                  |
| `session`    | `token_ttl`, `session_ttl`, `handshake_timeout`, `max_concurrent_sessions`, `max_message_size` | `token_ttl` and `max_concurrent_sessions` are required.                            |
| `rate_limit` | `disabled`, `time_window`, `quota`, `max_entries`                                              | Rate limit is **on** out of the box.                                               |

At least one of `diagnose`, `ws`, `tcp`, `tls`, `wss`, or `broker` must be
enabled. The relay exits with status 1 otherwise. It also exits at startup on a
key it does not know or one in the wrong table, so a misspelt `password` cannot
leave the relay open. Without `-c`, the relay reads the TOML text itself from
the `KAMUNE_RELAY_CONFIG` environment variable. Every key's default and range
are listed in
[Configuration Reference](../../docs/RELAY.md#configuration-reference).

A WebSocket request's client address is read from a header only when the
connection's immediate peer matches a CIDR in `server.trusted_proxies`, and
then only from the header named by `server.client_ip_header`. The default,
`X-Forwarded-For`, is read from the right, skipping trusted hops; any other
header must hold the one address the proxy sets. Leave the list empty when the
relay is directly exposed. Behind a reverse proxy, CDN or tunnel, list the
addresses the proxy connects from (`127.0.0.1/32` for cloudflared on the same
host, the CDN's published ranges for a CDN) and name the header it writes (for
example `CF-Connecting-IP` behind Cloudflare), or every client shares the
proxy's rate limit (see
[CDN-Backed Deployments](../../docs/RELAY.md#cdn-backed-deployments)). Earlier
releases also read `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`,
`Fly-Client-IP` and `Fastly-Client-IP`; a proxy that sets only one of those now
needs `client_ip_header` set to its name.

If `[rate_limit]` is omitted, it defaults to 20 requests per minute and 100,000
tracked client IPs. Set `disabled = true` to turn it off.

### Listener matrix

| `ws` | `tcp` | `tls` | `wss` | `diagnose` | Listeners                                    |
| ---- | ----- | ----- | ----- | ---------- | -------------------------------------------- |
| ✓    | ✗     | ✗     | ✗     | ✗          | ws:8888                                      |
| ✓    | ✓     | ✗     | ✗     | ✗          | ws:8888, tcp:8889                            |
| ✓    | ✓     | ✓     | ✗     | ✗          | ws:8888, tcp:8889, tls:8890                  |
| ✓    | ✓     | ✗     | ✓     | ✗          | ws:8888, tcp:8889, wss:8891                  |
| ✓    | ✓     | ✓     | ✓     | ✓          | all 5                                        |
| ✗    | ✓     | ✗     | ✓     | ✗          | tcp:8889, wss:8891                           |
| ✗    | ✗     | ✗     | ✗     | ✗          | error: "at least one server must be enabled" |

## TLS / Certificates

The `[tls]` and `[wss]` blocks are independent listeners with their own cert
settings. Both accept TLS 1.3 only. Each can be in one of three modes:

### 1. Self-signed, kept in `data_dir` (default, zero config)

Leave `cert_file` and `key_file` empty in the block. The relay then uses a
self-signed certificate that it creates on first use in `server.data_dir` as
`relay-cert.pem` and `relay-key.pem`, and loads again on every later start.
`data_dir` defaults to `kamune-relay` in the user's config directory
(`~/.config/kamune-relay` on Linux, `/var/lib/kamune-relay/.config/kamune-relay`
in the Docker image). `[tls]` and `[wss]` share this certificate. It is issued
to `CN=localhost` and is valid for 10 years.

At startup the relay logs the SHA-256 fingerprint of each listener's
certificate:

```
INFO tls certificate listener=tls sha256=<64 hex digits>
```

Clients authenticate the relay by pinning that value; Go clients build the TLS
configuration with `relayconn.PinnedTLSConfig`. A client that turns certificate
checks off instead leaves the PSK and session tokens open to an active attacker.

The relay never replaces these files, so the pin stays valid across restarts.
To rotate the certificate, remove both files; the relay creates a new one at
the next start, and every client must then pin the new fingerprint. Startup
fails if only one of the two files is there.

### 2. On-disk self-signed

Generate a self-signed cert with `openssl`, then point the block at it:

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout assets/cert/server.key \
  -out    assets/cert/server.crt \
  -days 3650 -nodes \
  -subj "/CN=localhost"
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

The relay **hard-errors on startup** if the configured cert is missing or
invalid — it never auto-generates or overwrites files at runtime.

### 3. Production cert

Replace the self-signed cert with one from a real CA (Let's Encrypt, internal
CA, etc.). Format must be PEM-encoded. Keep the key file readable by the relay
process only (for example mode `0600`). Same hard-error behavior as mode 2.

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
  notified of each other's observed IP:port and ephemeral X25519 public key so
  they can attempt a direct UDP hole-punch.

The broker uses X25519 + XChaCha20-Poly1305 with a per-NOTIFY fresh ephemeral
broker key (forward secrecy). The wire format is small (60-byte REGISTER;
99/133-byte NOTIFYs) and the broker does not see plaintext, identities, or
public keys beyond what peers explicitly share.

## Build

```bash
make run                              # go run . -c assets/config.toml
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

Tests use real implementations, interfaces, and standard `testing.T` — no mocks.
Assertions use `testify` (`assert` and `require`).

## Related

- [`docs/SPEC.md`](../../docs/SPEC.md) — protocol specification
- [`cmd/tui/`](../tui/) — Bubble Tea terminal client
- [`cmd/bus/`](../bus/) — Wails GUI client
- [`cmd/daemon/`](../daemon/) — JSON-over-stdio daemon
