# Relay Protocol

Kamune includes a relay server for NAT traversal. The relay is a **blind
token-based session switch** — a listener connects, receives a random token,
shares it out of band, and the dialer connects with that token. The relay
bridges encrypted frames between the two and learns nothing about their
identities or message content.

## Design Goals

- **Blind**: the relay never sees public keys, identities, or message content
- **Stateless**: no persistent storage, no queues, no offline messages
  (tokens and rate limit counters are ephemeral in-memory state)
- **Zero metadata**: no social graph, no presence tracking, no persistent
  identifiers across connections
- **Out-of-band rendezvous**: the only thing peers exchange is a short random
  token — no key material, no addresses
- **Transport-agnostic**: same protocol over WebSocket, raw TCP, or TLS

## Relay Protobuf Schema

```protobuf
syntax = "proto3";
package relayconn;

message Frame {
    oneof kind {
        Register   register   = 1;  // Create or join a session
        Registered registered = 2;  // Relay responds with the session token
        Message    msg        = 3;  // Route data to the session peer
        Ping       ping       = 4;  // Keepalive
        Pong       pong       = 5;  // Keepalive response
        Auth       auth       = 6;  // PSK authentication (optional)
    }
}

message Register {
    bytes token = 1;  // Empty when creating a session (listener),
                      // 16-byte token when joining (dialer)
}

message Registered {
    bytes token = 1;  // The 16-byte session token
}

message Message {
    bytes data = 1;  // Encrypted payload — opaque to the relay
}

message Ping {}

message Pong {}

message Auth {
    bytes psk = 1;  // Pre-shared key for PSK mode
}
```

## Connection Flow

The protocol uses a single oneof frame type for session management.

### Listener (creates session)

1. Establish transport connection (WebSocket, TCP, or TLS).
2. Perform HPKE key exchange (`exchange.Initiate` — the relay calls `Accept`).
3. If PSK auth is configured, send `Frame.Auth{psk}` before registering.
4. Send `Frame.Register{token: nil}` to request a new session.
5. Receive `Frame.Registered{token: T}` — T is a random 16-byte token.
6. Send T to the dialer out of band (QR code, text message, NFC, etc.).
7. Enter read loop. The first incoming `Frame.Message{data}` establishes the
   session — the dialer has arrived.

### Dialer (joins session)

1. Establish transport connection.
2. Perform HPKE key exchange (`exchange.Initiate`).
3. If PSK auth is configured, send `Frame.Auth{psk}` before registering.
4. Send `Frame.Register{token: T}` with the token received from the listener.
5. The relay validates T, joins the dialer to the session, and sends the
   dialer a `Frame.Registered{token: T}` to confirm.
6. Enter read loop. Messages are now bridged.

```
Listener                                    Relay
   │                                          │
   ├── Connect ──────────────────────────────►│
   ├── HPKE Initiate ────────────────────────►│
   ├── (Auth if PSK) ────────────────────────►│
   ├── Register{token: nil} ─────────────────►│
   │◄─ Registered{token: T} ─────────────────┤
   │                                          │
   │  (send T to dialer OOB)                  │
   │                                          │
   │                              Dialer      │
   │                                 │        │
   │                                 ├── Connect ─────►│
   │                                 ├── HPKE Initiate─►│
   │                                 ├── (Auth if PSK)─►│
   │                                 ├── Register{T} ──►│
   │◄════ Message{data} ═══════════════════╝        │
   │══════ Message{data} ═══════════════════╗        │
   │                                 ◄══════╝        │
   │                                 ══════╗          │
```

The relay tracks which transport connection belongs to which session. When
one peer writes a `Frame.Message{data}`, the relay delivers it to the other
peer in the same session.

## Frame Flow

- **Session creation**: `Frame.Register{token: nil}` asks the relay to
  generate a new random token and create a session. The relay replies with
  `Frame.Registered{token: T}` containing the 16-byte token.
- **Session join**: `Frame.Register{token: T}` with a previously issued token
  adds the sender's connection to the session. The relay replies with
  `Frame.Registered{token: T}` to confirm.
- **Message relay**: `Frame.Message{data}` is delivered to the other peer
  in the session. If the other peer has not yet connected, the message is
  silently dropped (no queuing).
- **Ping/Pong**: `Frame.Ping` triggers an automatic `Frame.Pong` response
  at the relay connection level. The relay and client only respond to Pings;
  neither side initiates them.
- **Auth**: `Frame.Auth{psk}` authenticates the peer before registering.
  Required when the relay is in PSK mode. The relay replies with an empty
  `Frame.Auth{}` on success or disconnects on failure.

The relay applies no back-pressure, no queuing, no retry — if the recipient
disconnects, the message is silently dropped. The Kamune protocol layer
(running inside the encrypted channel) handles reliability.

### Token lifecycle

1. **Issued**: relay generates T = `crypto/rand` 16 bytes, creates an
   in-memory session, stores T → session mapping. The session has one
   participant: the listener.
2. **Consumed**: when a dialer sends `Register{token: T}`, the relay joins
   the dialer's connection to the session. The token is now consumed — no
   further peer can join with the same T.
3. **Expired**: if the listener disconnects before a dialer joins, the
   token is discarded and cannot be used.
4. **TTL**: tokens have a configurable time-to-live (default: 5 minutes).
   If no dialer joins within the TTL, the session is cleaned up.

Tokens are:

- **Single-use**: one dialer per token
- **Time-bound**: TTL enforced server-side
- **Opaque**: the relay does not embed any peer information in the token
- **Unpredictable**: generated by `crypto/rand`

## What the relay learns (and doesn't)

| The relay sees                    | The relay does NOT see          |
| --------------------------------- | ------------------------------- |
| Session S has 2 connections       | Public keys of either peer      |
| Connection A is in session S      | Identity of any peer            |
| Session S received a message at T | Persistent identifier (token is |
|                                   | ephemeral and single-use)       |
|                                   | Message content (E2E encrypted) |
|                                   | Social graph (each token is     |
|                                   | unique per rendezvous)          |

The relay never learns who any peer is — it sees only that two connections
share a token, nothing more.

## RelayListener

`ListenRelay` connects to the relay and performs the HPKE exchange, then:

1. Sends `Frame.Register{token: nil}` to create a session.
2. Receives `Frame.Registered{token: T}` and returns T to the caller.
3. Enters a read loop. When a `Frame.Message{data}` arrives, it creates a
   new `RelayConn` and pushes it to the accept channel.
4. The relay token is consumed by the first dialer that presents it.

All `RelayConn` instances for the same listener share the underlying relay
HPKE channel — the relay differentiates sessions by token.

## Transports

The relay supports three independent transport listeners, each configured
via its own section in the TOML config. Any combination can be active at once.

The client API takes the relay address and an optional password (for PSK
mode). No peer key or identity key is needed — the dialer discovers the
session via the token, and the HPKE exchange generates ephemeral keys per
connection.

### WebSocket (`[ws]`)

A WebSocket listener. Shares the HTTP server address from `[server].address`.
Suitable for permissive networks, local development, and deployments behind
a CDN.

```toml
[ws]
enabled = true
```

When `enabled` is `false`, the WebSocket listener is disabled.

For WebSocket over TLS (`wss://`), provide a TLS config to the client API
(see TLS section for certificate setup).

Client API:

```go
relayconn.DialRelay(ctx, addr, token)
relayconn.DialRelayWSS(ctx, addr, token, tlsCfg)
relayconn.ListenRelay(ctx, addr)        // returns (*RelayListener, token, error)
relayconn.ListenRelayWSS(ctx, addr, tlsCfg) // returns (*RelayListener, token, error)
```

### Raw TCP (`[tcp]`)

A bare TCP listener with length-prefixed framing. No TLS, no HTTP — just
2-byte big-endian length + payload over a plain TCP stream. Suitable for
trusted LANs, VPN backends, and development.

```toml
[tcp]
enabled = true
address = "127.0.0.1:8889"
```

Client API:

```go
relayconn.DialRelayTCP(ctx, addr, token)
relayconn.ListenRelayTCP(ctx, addr)  // returns (*RelayListener, token, error)
```

### TLS (`[tls]`)

A TLS-encrypted TCP listener using the same length-prefixed framing, but
wrapped in a TLS 1.3 connection. To passive DPI this is indistinguishable
from any other TLS service on port 443 — no HTTP upgrade, no opcodes, no
protocol fingerprint.

```toml
[tls]
enabled = true
address = "0.0.0.0:443"
cert_file = "/path/to/cert.pem"
key_file  = "/path/to/key.pem"
```

**Auto-generated certificate.** When `cert_file` and `key_file` are specified
but the files don't exist, the relay generates a self-signed TLS certificate.
This certificate is valid for 10 years and contains no identifying metadata.
If `cert_file` or `key_file` is empty, defaults to `assets/cert/server.crt`
and `assets/certs/server.key` and auto-generates if missing.

Client API:

```go
tlsCfg := &tls.Config{}
relayconn.DialRelayTLS(ctx, addr, token, tlsCfg)
relayconn.ListenRelayTLS(ctx, addr, tlsCfg)  // returns (*RelayListener, token, error)
```

### Comparison

| Transport | Wire fingerprint             | DPI evasion               | Use case                     |
| --------- | ---------------------------- | ------------------------- | ---------------------------- |
| WebSocket | HTTP upgrade + `0x82` frames | Weak                      | Permissive nets, dev, CDN    |
| Raw TCP   | Plain TCP, no TLS            | None (visible as raw TCP) | Trusted LAN, VPN             |
| TLS       | Standard TLS 1.3             | Excellent                 | Production, hostile networks |

### PSK auth

All transport functions accept an optional password via `relayconn.WithPassword`:

```go
relayconn.DialRelay(ctx, addr, token, relayconn.WithPassword("secret"))
relayconn.ListenRelay(ctx, addr, relayconn.WithPassword("secret"))
```

### Config example: stealth deployment

```toml
[tcp]
enabled = false

[tls]
enabled = true
address = "0.0.0.0:443"
# cert_file and key_file will be auto-generated on first run
cert_file = "server.crt"
key_file  = "server.key"

[ws]
enabled = false

[server]
password = ""
expose_health = false
expose_ip = false
```

On the wire: TLS 1.3 handshake followed by length-prefixed ciphertext. No
HTTP requests, no protocol fingerprint beyond "unknown TLS application".

## Deploying Behind a CDN

A CDN proxies traffic between clients and your relay, shielding the relay's
IP address and providing free TLS termination. This is the recommended
deployment model for hostile networks.

### How WSS works

`wss://` is the WebSocket equivalent of `https://` — a WebSocket connection
inside a TLS tunnel. The client performs a standard TLS handshake first,
then sends the WebSocket upgrade inside the encrypted tunnel. Passive DPI
sees only the initial TLS handshake.

### CDN deployment flow

```
                  TLS (CDN cert)         plain WS (private network)
Client ──wss://relay.cdn.com/ws──► CDN ──ws://relay:8080/ws──► Relay
  │                                │
  │‑ Client sees CDN's valid cert  │‑ CDN terminates TLS
  │‑ Client never sees relay IP    │‑ Forwards upgrade as-is
  │‑ Blends with millions of       │‑ Connection to origin is
  │  other CDN sites               │  plain WS on private network
```

The relay operator does not need a TLS certificate. The CDN provides one.
The relay listens on `[server] address = "127.0.0.1:8080"` with `[ws] enabled = true`
— plain WebSocket behind the CDN is perfectly safe.

Use `DialRelayWSS` / `ListenRelayWSS` on the client side with a TLS config
pointed at the CDN hostname.

### Cloudflare Tunnel (recommended)

[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
lets the relay make a single outbound connection to Cloudflare, eliminating
the need for a public IP or open firewall ports entirely:

```
Client ──wss://relay.cdn.com/ws──► Cloudflare edge
                                       ▲
                                       │ outbound tunnel (no open ports)
                                       │
                                   Relay (cloudflared on localhost:8080)
```

- No public IP required — works behind CGNAT, residential ISPs, or firewalls
- No open ports — only outbound connections
- Free tier handles unlimited traffic
- DPI sees traffic to Cloudflare IPs, not the relay

The relay itself needs no changes — it listens on localhost as usual.

### Config for CDN-backed relay

```toml
[ws]
enabled = true

[tcp]
enabled = false

[tls]
enabled = false

[server]
address = "127.0.0.1:8080"   # localhost only — CDN connects via tunnel
password = ""
expose_health = false
expose_ip = false
```

### CDN vs direct TLS comparison

|                     | Direct TLS listener | CDN (Cloudflare)                   | Cloudflare Tunnel         |
| ------------------- | ------------------- | ---------------------------------- | ------------------------- |
| Relay IP hidden     | No                  | Yes (CDN IP shown)                 | Yes (no public IP at all) |
| TLS cert            | Self-signed (auto)  | CDN's valid cert                   | CDN's valid cert          |
| DPI evasion         | Good (raw TLS)      | Excellent (blends with CF traffic) | Excellent                 |
| Cost                | Free                | Free                               | Free                      |
| Open ports required | Yes (port 443)      | Yes (port 443 on origin)           | No (outbound only)        |
| Setup complexity    | None (auto-cert)    | DNS + proxy toggle                 | Install cloudflared       |

### Cloudflare Workers

[Workers](https://workers.cloudflare.com/) can act as a WebSocket proxy
between clients and the relay, optionally adding auth, logging, or IP
filtering at the edge:

```js
// worker.js — WebSocket proxy (~20 lines)
export default {
  async fetch(req) {
    const url = new URL(req.url);
    const origin = new URL("wss://relay-origin.example.com");
    origin.pathname = url.pathname;
    return fetch(new Request(origin, req));
  },
};
```

The Worker forwards the WebSocket upgrade transparently. All subsequent WS
frames pass through. The relay sees the Worker's IP, not the client's.

## Access Control

The relay supports restricting which peers can create sessions. Enforcement
happens inside the HPKE-encrypted channel, before a token is issued.

| Mode | Config                    | Behaviour                                          |
| ---- | ------------------------- | -------------------------------------------------- |
| Open | `password = ""` (default) | Any peer can create sessions and receive tokens    |
| PSK  | `password = "<secret>"`   | Peer must send `Frame.Auth{psk}` before `Register` |

### Open mode (default)

```toml
[server]
password = ""
```

No restrictions. The relay accepts any peer.

### PSK mode

```toml
[server]
password = "aB3dF5gH8jK2lQ4wE6rT9yU1iO7pZ0x"
```

After the HPKE exchange, the peer must send a `Frame.Auth{psk: "..."}`
frame before `Frame.Register`. The relay verifies the PSK using
constant-time comparison and closes the connection if incorrect.

On the client side, pass the password via `relayconn.WithPassword`:

```go
rc, err := relayconn.DialRelay(ctx, addr, token, relayconn.WithPassword(password))
```

## Rate Limiting

The relay supports optional rate limiting per connection to prevent abuse.

```toml
[rate_limit]
enabled = true
time_window = "1m"
quota = 20
```

When enabled, each connection is limited to `quota` registrations per
`time_window`. Exceeding the quota closes the connection.

## Config Reference

```toml
[server]
address = "127.0.0.1:8888"    # HTTP/WS listen address
password = ""                 # PSK password, empty = open mode
expose_health = true          # expose /health endpoint
expose_ip = true              # expose /ip endpoint

[ws]
enabled = true                # WebSocket listener (shares server address)

[tcp]
enabled = false               # Raw TCP listener
address = "127.0.0.1:8889"

[tls]
enabled = false               # TLS listener
address = "0.0.0.0:443"
# cert_file = "server.crt"    # required (auto-generated if files missing)
# key_file  = "server.key"    # required (auto-generated if files missing)

[session]
token_ttl = "5m"              # Token time-to-live (default: 5 minutes)
# session_ttl = "30m"         # Max lifetime for paired sessions (0 = no limit)
# handshake_timeout = "10s"   # Max time for HPKE + registration (0 = no limit)
max_concurrent_sessions = 10000  # Maximum active sessions
max_message_size = 65536      # Maximum message payload size (bytes)

[rate_limit]
enabled = true                # Enable rate limiting
time_window = "1m"            # Rate limit window
quota = 20                    # Max registrations per window
```

## Security Considerations

The relay is a blind session switch — it makes no trust decisions about who
can create or join sessions (beyond optional PSK auth). This section documents
known attack vectors and the current level of protection.

### Attack vectors

#### Token exhaustion (resource exhaustion)

An attacker can create tokens in rapid succession by opening many HPKE
connections and sending `Register{token: nil}`. Each unpaired token occupies
a slot in the in-memory session map until its TTL expires (default: 5 min).
If the attacker fills all `max_concurrent_sessions` slots, legitimate users
cannot create sessions until expired tokens are purged.

**Current defenses:**

| Defense                               | Status                                                       |
| ------------------------------------- | ------------------------------------------------------------ |
| `max_concurrent_sessions` cap         | ✅ Enforced — `Create()` rejects at capacity                 |
| Token TTL + `purgeExpired()` 30s loop | ✅ Enforced — expired tokens freed every 30s                 |
| Rate limiting (`[rate_limit]`)        | ✅ Enforced — sliding window counter per IP, reject at quota |
| Per-IP rate limiting                  | ✅ Enforced — each IP tracked independently                  |

Rate limiting is checked after connection accept but before HPKE key
exchange, so rate-limited clients are rejected without wasting asymmetric
crypto. See [Rate limiting implementation](#rate-limiting-implementation)
below for details.

#### Session hoarding

An attacker who controls both ends of a session (listener + dialer) can hold
a session open until its TTL expires. The TTL serves double duty:

1. **Token offer window** — how long the receiver has to scan a QR and join
2. **Session max lifetime** — how long a paired session lives before forced
   disconnect

This means:

- Raising TTL for share card usability (longer offer window) also gives
  attackers longer-lived sessions
- A paired session at rest (no messages) still consumes a slot until TTL

**Current defenses:**

| #   | Mitigation                                                                                                                                                    | Prevents                                               | Status                                                        |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------- |
| 1   | **Rate limiting** — sliding window counter per IP, enforced before registration                                                                               | Rapid token fill                                       | ✅ Implemented                                                 |
| 2   | **Session TTL** — `session_ttl` controls max lifetime after pairing, separate from `token_ttl` (offer window)                                                 | Session hoarding, flexibility for share cards          | ✅ Implemented — configurable, 0 = no limit                   |
| 3   | **Handshake timeout** — `handshake_timeout` limits time between accept and registration complete; enforced via `net.Conn.SetDeadline` (TCP) or context (WS)   | Slow client DoS holding connection + goroutine slots   | ✅ Implemented — configurable, default 10s                    |
| 4   | **Per-IP concurrent session cap** — optional limit below the global `max_concurrent_sessions`                                                                 | Single IP exhausting all slots                         | ❌ Not implemented                                            |

### Status summary

| Protection                                     | Status                                                       |
| ---------------------------------------------- | ------------------------------------------------------------ |
| Token TTL                                      | ✅ Enforced (configurable, default 5 min)                    |
| Session TTL (paired max lifetime)              | ✅ Enforced (configurable, default 0 = no limit)             |
| Max concurrent sessions                        | ✅ Enforced (configurable, default 10K)                      |
| Max message size                               | ✅ Enforced (configurable, default 64 KB)                    |
| PSK auth                                       | ✅ Enforced (constant-time compare)                          |
| Rate limiting (global + per-IP)                | ✅ Enforced — sliding window, `hashicorp/golang-lru`         |
| Handshake timeout (HPKE + registration)        | ✅ Enforced (configurable, default 10s)                      |
| Per-IP session cap                             | ❌                                                           |

Mitigations 1–3 are implemented. Per-IP session cap remains as
defensive hardening for public relay deployments.

### Rate limiting implementation

Rate limiting lives in `internal/ratelimit/` and is the first line of defense
against token exhaustion (rapid `RegisterListener` calls).

**Algorithm:** Sliding window counter with sub-window buckets. The time window
(e.g. 1 minute) is divided into 10 equal buckets (e.g. 6 s each). On each
registration attempt:

1. Advance the cursor by elapsed time / bucket duration, zeroing stale buckets
2. Sum all 10 bucket counters
3. If sum ≥ quota → deny; else increment current bucket → allow

This avoids the O(n) timestamp iteration of a pure sliding window log while
providing sub-window precision (worst case: 1 bucket's worth of overcount).

**Storage:** `hashicorp/golang-lru/v2/expirable` — a bounded, TTL-aware LRU.
Each IP maps to a `*entry` struct holding the sliding window state. Entries
auto-evict after `2 × time_window` of inactivity. The LRU size is capped at
`max_concurrent_sessions` to prevent memory exhaustion under IP spoofing.

**Concurrency:** A single `sync.Mutex` guards the RateLimiter. Every `Allow()`
call mutates state (sub-window counters, timestamp), so `RWMutex` would promote
to write on every path anyway. The lock is per-connection-attempt (held for
~100 ns), well before any asymmetric crypto, so contention is negligible.

**Placement in the connection lifecycle:**

```
TCP/TLS accept / WS upgrade
        ↓
Extract client IP (proxy-aware for WS)
        ↓
    ┌─────────────────-┐
    │ Rate limit check │ ← reject with close + log warning
    └────────────────-─┘
        ↓
HPKE key exchange (expensive — attacker burns CPU per attempt)
        ↓
Authentication (if PSK configured)
        ↓
Registration (listener: token create / dialer: token join)
        ↓
Read pump (message forwarding)
```

**Keying:** By IP address. For WebSocket connections, IP is extracted via
proxy headers (`X-Real-IP`, `X-Forwarded-For`, `True-Client-IP`, etc.)
through `clientIP()`. For TCP/TLS, the raw `RemoteAddr` is used, with the
port stripped.

**Tests:** `ratelimit_test.go` runs under `go test -race` and covers:

- Single IP stays within quota
- Single IP blocked after exceeding quota
- Counter resets after window elapses
- Multiple IPs are independent
- Concurrent goroutines for same IP maintain correct count

```

```
