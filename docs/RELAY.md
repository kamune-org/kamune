# Relay Protocol

Kamune includes a relay server for NAT traversal. The relay is a **blind
token-based session switch**: a listener connects, receives a random token,
shares it out of band, and the dialer connects with that token. The relay
bridges encrypted frames between the two and learns nothing about their
identities or message content.

The relay makes no trust decisions beyond an optional pre-shared key. End-to-end
authentication and encryption are established directly between the two peers;
the relay is a low-trust message forwarder.

## Design Goals

- **Blind**: the relay never sees public keys, identities, or message content.
- **Stateless**: no persistent storage, no queues, no offline messages. Tokens,
  sessions, and rate-limit counters are ephemeral, scoped to the relay process
  lifetime.
- **Zero metadata**: no social graph, no presence tracking, no persistent
  identifiers across connections.
- **Out-of-band rendezvous**: the only thing peers exchange is a short random
  token — no key material, no addresses.
- **Transport-agnostic**: same protocol over WebSocket, raw TCP, or TLS.

## Threat Model

The relay is a **low-trust relay**. Callers must assume:

- A **network attacker** on the path between client and relay can observe
  connection metadata (timing, sizes, IP pairs) but not message contents.
- The **relay operator** can deny service, log connection metadata, and observe
  which connection pairs share a session. They cannot read message contents,
  identify peers, or persist identity across sessions.
- A **malicious relay** cannot impersonate either peer: authentication and
  end-to-end encryption are established directly between the two peers using the
  rendezvous token alone.

### What the Relay Observes

| The relay observes               | The relay does NOT observe                                |
| -------------------------------- | --------------------------------------------------------- |
| Session `S` has 2 connections    | Public keys of either peer                                |
| Connection `A` is in session `S` | Identity of any peer                                      |
| Session `S` received a message   | Persistent identifier (token is ephemeral and single-use) |
|                                  | Message content (E2E encrypted)                           |
|                                  | Social graph (each token is unique per rendezvous)        |

The relay never learns who any peer is — only that two connections share a
token, nothing more.

### What a Compromised Relay Can and Cannot Do

If the relay is fully compromised (operator is malicious or the host is
breached), the attacker can:

- **Deny service** by refusing connections or dropping messages.
- **Observe metadata** — which IPs connect, when, how much they exchange, which
  connections share a session.
- **Inject or reorder messages** _between_ sessions, but never within a session
  it cannot see (and it can see all of them, by design).
- **Replay or forge** messages it has previously observed, but the end-to-end
  cryptographic layer rejects any frame the recipient cannot authenticate, so
  the only effect is to drop traffic or cause disconnects.

The attacker **cannot**:

- Read message contents (end-to-end encryption is established peer-to-peer via
  the HPKE exchange).
- Impersonate a peer (no long-term keys are exchanged with the relay; peers
  authenticate each other after rendezvous).
- Decrypt past sessions retroactively (ephemeral keys per session; see
  [Forward Secrecy](#forward-secrecy)).
- Persist a peer's identity across separate sessions (tokens are single-use; the
  relay does not know the same client is back).

## Protocol

### Wire Format

For TCP and TLS transports, every frame is a length-prefixed payload: two
big-endian bytes of length followed by exactly that many bytes of payload. The
length is a `uint16`, so the maximum frame size is 64 KB. Both ends of a
connection MUST agree on the maximum; if they differ, the stricter end will
reject frames the other would have accepted.

For WebSocket transport, frames are sent as binary WebSocket messages; the
WebSocket layer's framing replaces the length prefix.

**Design decision:** length-prefixed framing was chosen over delimiter-based
framing because it allows zero-byte payloads, avoids escaping problems, and
makes the byte stream resumable. The 64 KB ceiling is a deliberate small-frame
choice that limits blast radius from a malicious peer; larger messages are split
by the application layer above the relay.

### Frame Schema

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
    bytes  token               = 1;  // The 16-byte session token
    uint32 ttl_seconds         = 2;  // Token validity (offer window)
    uint32 session_ttl_seconds = 3;  // Max lifetime of paired session (0 = no limit)
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

### Connection Flow

#### Listener (creates session)

1. Establish a transport connection (WebSocket, TCP, or TLS).
2. Perform an HPKE key exchange.
3. If the relay is in PSK mode, send `Frame.Auth{psk}` before registering.
4. Send `Frame.Register{token: nil}` to request a new session.
5. Receive `Frame.Registered{token: T, ttl_seconds, session_ttl_seconds}`. `T`
   is a random 16-byte token.
6. Share `T` with the dialer out of band (QR code, text message, NFC, etc.).
7. Enter read loop. The first incoming `Frame.Message{data}` establishes the
   session — the dialer has arrived.

#### Dialer (joins session)

1. Establish a transport connection.
2. Perform an HPKE key exchange.
3. If the relay is in PSK mode, send `Frame.Auth{psk}` before registering.
4. Send `Frame.Register{token: T}` with the token received from the listener.
5. The relay validates `T`, joins the dialer to the session, and sends the
   dialer a `Frame.Registered{token: T, ttl_seconds, session_ttl_seconds}` to
   confirm.
6. Enter read loop. Messages are now bridged.

```
Listener                                    Relay
   │                                          │
   ├── Connect ──────────────────────────────►│
   ├── HPKE Initiate ────────────────────────►│
   ├── (Auth if PSK) ────────────────────────►│
   ├── Register{token: nil} ─────────────────►│
   │◄─ Registered{token: T, ttl, session_ttl} ┤
   │                                          │
   │  (share T with dialer OOB)               │
   │                                          │
   │                 Dialer                   │
   │                    │                     │
   │                    ├── Connect ─────────►│
   │                    ├── HPKE Initiate ───►│
   │                    ├── (Auth if PSK) ───►│
   │                    ├── Register{T} ─────►│
   │◄══════ Message{data} ═══════════════════╝│
   │══════ Message{data} ════════════════════►│
```

### Token Lifecycle

1. **Issued**: the relay generates `T = crypto/rand` 16 bytes and creates a
   session. The session has one participant: the listener.
2. **Consumed**: when a dialer sends `Register{token: T}`, the relay joins the
   dialer's connection to the session. The token is now consumed — no further
   peer can join with the same `T`.
3. **Expired**: if the listener disconnects before a dialer joins, the token is
   discarded and cannot be used.
4. **TTL**: tokens have a configurable time-to-live (`token_ttl`, default 5
   minutes). If no dialer joins within the TTL, the session is cleaned up.

**Design decision: 16-byte tokens.** A 16-byte (128-bit) token provides 128 bits
of entropy, which is more than enough to make guessing infeasible. 16 bytes also
fits comfortably in a QR code without the dialer needing to scan anything more
elaborate. Shorter tokens would be QR-friendly but reduce entropy; longer tokens
buy nothing practical.

Tokens are:

- **Single-use**: one dialer per token.
- **Time-bound**: TTL enforced server-side.
- **Opaque**: the relay does not embed any peer information in the token.
- **Unpredictable**: generated by `crypto/rand`.

### Session Lifetime

A paired session is bounded by `session_ttl` (default 30 minutes;
`0 = no limit`). After this duration, the relay closes both peers regardless of
activity. This is independent of `token_ttl`, which controls the offer window
before pairing.

**Design decision: two-tier TTL.** The token offer window and the session max
lifetime are conceptually different:

- `token_ttl` is a UX concern: how long a share card (QR code) stays valid. It
  should be short (5 minutes) to minimize the cost of abandoned offers.
- `session_ttl` is a resource concern: how long a paired session can hold a slot
  in the relay's session map. It should be long enough for the use case (30
  minutes is generous) or unlimited (0).

A single TTL would force a compromise that hurts one of these.

### Backpressure and Message Drops

The relay applies **no back-pressure, no queuing, no retry**. If the recipient
is absent or slow, the message is silently dropped. The end-to-end Kamune
protocol layer above the relay is responsible for reliability, ordering, and
retransmission.

**Design decision: drop, not queue.** Queuing would require:

- Persistent storage (violates the stateless goal).
- A notion of "session mailbox" (introduces replay windows).
- Per-recipient ordering state (CPU and memory cost per session).

The chosen design is simpler, more predictable, and has bounded resource cost
per session. The cost is that messages sent before both peers are connected — or
while the recipient is processing — are lost. Callers above the relay handle
this.

### Forward Secrecy

Each session uses fresh HPKE ephemeral keys. A compromised relay — or a future
compromise of any long-term key — cannot decrypt past sessions, because the keys
never existed outside that session's lifetime and are destroyed when the session
ends.

**Design decision: ephemeral per-session keys.** Long-term keys would allow the
relay to persist identity across sessions (violating zero-metadata) and would
mean a single key compromise decrypts all sessions ever routed through that
relay. Ephemeral keys buy both better privacy and better security at the cost of
slightly more work per handshake.

### Replay Protection

Replay protection is **explicitly out of scope** at the relay layer. The relay
does not track, deduplicate, or sequence messages. Replay defense is the
responsibility of the end-to-end Kamune protocol layer, which uses the
rendezvous token and ML-KEM-768 handshake to establish a fresh session secret
per rendezvous.

**Design decision: no replay state at the relay.** Replay tracking would require
keeping per-message state for the entire session lifetime and across sessions
for the same peer. With ephemeral per-session keys already providing
session-scoped authentication, the caller can cheaply reject replays above the
relay.

### Authentication Modes

| Mode | Config                    | Behaviour                                          |
| ---- | ------------------------- | -------------------------------------------------- |
| Open | `password = ""` (default) | Any peer can create sessions and receive tokens    |
| PSK  | `password = "<secret>"`   | Peer must send `Frame.Auth{psk}` before `Register` |

**Design decision: PSK as a deployment-level gate, not per-peer identity.** The
PSK identifies the _deployment_, not the peer. It prevents drive-by token
harvesting from a public relay, but it does not authenticate individual peers to
each other. Peer-to-peer authentication is established end-to-end after the
rendezvous, using the shared token as a starting point for a key agreement.

In PSK mode, the password is transmitted inside the HPKE-encrypted channel and
verified with a constant-time comparison. A wrong password closes the connection.

### Rate Limiting

Rate limiting applies per source IP, before the key exchange, so abusive clients
are rejected without burning the relay's CPU on asymmetric crypto.

| Aspect      | Behavior                                                     |
| ----------- | ------------------------------------------------------------ |
| Algorithm   | Sliding window log                                           |
| Window      | Configurable (default 1 minute)                              |
| Quota       | Configurable (default 20 registrations per window)           |
| Keying      | Source IP (proxy-aware for WebSocket)                        |
| Boundedness | Bounded; defaults to `max_concurrent_sessions`               |
| TTL         | Per-IP state forgotten after `2 × time_window` of inactivity |

**Design decision: rate-limit by IP, not by token.** Tokens are opaque to the
rate limiter (a client may not have a token yet — that's the listener case). IP
is the only stable identity available at connection time.

**Design decision: rate-limit before HPKE.** The whole point of rate limiting is
to prevent abuse. Putting it after the HPKE handshake would let attackers force
the relay to do expensive asymmetric crypto on every connection attempt. The
check is a simple, fast lookup that costs the relay nothing to reject.

**Design decision: sliding window log, not token bucket.** A sliding window log
gives exact "N events in the last T seconds" semantics with no edge cases at
window boundaries. The cost is O(N) memory per IP where N is the quota. Since
the quota is small (default 20), this is fine.

## Transports

The relay supports three independent transports, each configured via its own
section in the TOML config. Any combination can be active at once.

The client API takes the relay address and an optional password (for PSK mode).
No peer key or identity key is needed — the dialer discovers the session via the
token, and the HPKE exchange generates ephemeral keys per connection.

### WebSocket (`[ws]`)

A WebSocket listener. Shares the HTTP server address from `[server].address`.
Suitable for permissive networks, local development, and deployments behind a
CDN.

For WebSocket over TLS (`wss://`), the client uses a configured TLS context
against the relay's certificate.

### Raw TCP (`[tcp]`)

A bare TCP listener with length-prefixed framing. No TLS, no HTTP — just 2-byte
big-endian length + payload over a plain TCP stream. Suitable for trusted LANs,
VPN backends, and development.

### TLS (`[tls]`)

A TLS-encrypted TCP listener using the same length-prefixed framing, but wrapped
in a TLS 1.3 connection. To passive DPI this is indistinguishable from any other
TLS service on port 443 — no HTTP upgrade, no opcodes, no protocol fingerprint.

**Auto-generated certificate.** When `cert_file` and `key_file` are specified
but the files don't exist, the relay generates a self-signed TLS certificate.
This certificate is valid for 10 years and contains no identifying metadata.

### Comparison

| Transport | Wire fingerprint             | DPI evasion               | Use case                     |
| --------- | ---------------------------- | ------------------------- | ---------------------------- |
| WebSocket | HTTP upgrade + `0x82` frames | Weak                      | Permissive nets, dev, CDN    |
| Raw TCP   | Plain TCP, no TLS            | None (visible as raw TCP) | Trusted LAN, VPN             |
| TLS       | Standard TLS 1.3             | Excellent                 | Production, hostile networks |

**Design decision: WebSocket, TCP, and TLS only.** The chosen set covers the
three main deployment scenarios:

- **WebSocket** for CDN-fronted and permissive networks.
- **TLS** for stealth on hostile networks.
- **Raw TCP** for trusted internal deployments.

Other transports (QUIC, HTTP/2, gRPC) were considered. QUIC would give better
NAT-traversal and multiplexing but is visible as QUIC to DPI; gRPC has the same
problem. Plain TCP is the lowest common denominator for trusted networks.

### Handshake Timeout

A configurable `handshake_timeout` (default 30 s) bounds the time between
connection accept and successful registration. Slow clients that hold a
connection open without registering are dropped, freeing the slot the relay had
reserved for them.

**Design decision: separate from token_ttl.** Token TTL applies _after_
successful registration (offer window for the dialer). The handshake timeout
applies _before_ registration (how long the relay is willing to wait for the
client to finish HPKE + auth). A client that opens a connection and stalls is a
different problem from a client that registers successfully but never gets a
peer to join.

## Configuration Reference

```toml
[server]
address = "127.0.0.1:8888"    # HTTP/WS listen address
password = ""                 # PSK password, empty = open mode
expose_health = true          # expose /health endpoint
expose_ip = true              # expose /ip endpoint

[ws]
enabled = true                # WebSocket listener (shares server address)

[tcp]
enabled = true                # Raw TCP listener
address = "127.0.0.1:8889"

[tls]
enabled = true                # TLS listener
address = "0.0.0.0:443"
# cert_file = "assets/cert/server.crt"   # auto-generated if missing
# key_file  = "assets/cert/server.key"   # auto-generated if missing

[session]
token_ttl = "5m"              # Token time-to-live (unpaired sessions)
session_ttl = "30m"           # Max lifetime of paired sessions (0 = no limit)
handshake_timeout = "30s"     # Max time for HPKE + registration (0 = default 30s)
max_concurrent_sessions = 10000  # Maximum active sessions (>0 required)
max_message_size = 65536      # Maximum frame payload in bytes (0 = no limit)

[rate_limit]
enabled = true                # Enable per-IP rate limiting
time_window = "1m"            # Sliding window duration
quota = 20                    # Max registrations per window per IP
# max_entries = 100000        # Max unique IPs tracked (default: max_concurrent_sessions)
```

### Field Semantics

| Field                     | Default | Range  | Behavior on `0`          |
| ------------------------- | ------- | ------ | ------------------------ |
| `token_ttl`               | `5m`    | `> 0`  | (rejected)               |
| `session_ttl`             | `30m`   | `>= 0` | no limit                 |
| `handshake_timeout`       | `30s`   | `>= 0` | treated as default (30s) |
| `max_concurrent_sessions` | `10000` | `> 0`  | (rejected)               |
| `max_message_size`        | `65536` | `>= 0` | no limit                 |
| `time_window`             | `1m`    | `> 0`  | (rejected)               |
| `quota`                   | `20`    | `> 0`  | (rejected)               |

### Diagnostics Endpoints

When `expose_health = true`, `GET /health` returns:

```json
{ "status": "ok", "uptime": "1h2m3s", "sessionCount": 12 }
```

When `expose_ip = true`, `GET /ip` returns the client's IP as seen by the relay
(proxy-aware for WebSocket):

```json
{ "ip": "203.0.113.42" }
```

**Design decision: opt-in diagnostics.** Both endpoints leak information (relay
uptime, current load, perceived client IP) that is useful for debugging but is
metadata a public relay should not expose. Both are off-by-default-friendly in
the sense that the operator is expected to set them to `false` on public
deployments.

## Deployment Patterns

### Direct TLS (single host)

A single host runs the relay bound to a public IP on port 443, with self-signed
(auto-generated) certificates. Simple, no infrastructure dependencies, but the
relay's IP is exposed.

```toml
[server]
address = "127.0.0.1:8888"
password = ""
expose_health = false
expose_ip = false

[ws]
enabled = false

[tcp]
enabled = false

[tls]
enabled = true
address = "0.0.0.0:443"
```

On the wire: TLS 1.3 handshake followed by length-prefixed ciphertext. No HTTP
requests, no protocol fingerprint beyond "unknown TLS application".

For deployments that need to hide the relay's IP, see the
[CDN-backed footnote](#cdn-backed-deployments) at the end of this document.

## Known Limits

The relay is designed to be cheap, simple, and predictable. The following are
known limits, not bugs:

- **Token exhaustion** — an attacker can open many connections and send
  `Register{token: nil}` to fill the relay's session table until tokens expire.
  Defenses: `max_concurrent_sessions` cap, automatic cleanup of expired tokens,
  and the per-IP rate limiter (which runs before HPKE, so attackers do not burn
  asymmetric crypto).
- **Session hoarding** — an attacker controlling both ends of a session can hold
  it open for the full `session_ttl`. `session_ttl` bounds the cost of a hoarded
  session independently of `token_ttl`.
- **Handshake stalls** — slow clients can hold connection slots open. The
  `handshake_timeout` drops them so the slot is freed.
- **No offline messages, no replay protection** — by design, see
  [Backpressure and Message Drops](#backpressure-and-message-drops) and
  [Replay Protection](#replay-protection).

## Operator Responsibilities

The relay operator is responsible for:

- Running behind a CDN or tunnel for IP-hiding in hostile networks.
- Setting `[server] password` to enable PSK mode if the relay is exposed.
- Tuning `max_concurrent_sessions`, `token_ttl`, and `session_ttl` to match
  expected load.
- Disabling `expose_health` and `expose_ip` on public deployments to avoid
  leaking connection metadata.

## Footnotes

### CDN-Backed Deployments

A CDN proxies traffic between clients and the relay, shielding the relay's IP
address and providing free TLS termination. This is the recommended deployment
model for hostile networks.

#### How WSS Works

`wss://` is the WebSocket equivalent of `https://`: a WebSocket connection
inside a TLS tunnel. The client performs a standard TLS handshake first, then
sends the WebSocket upgrade inside the encrypted tunnel. Passive DPI sees only
the initial TLS handshake.

#### CDN Deployment Flow

```
                  TLS (CDN cert)         plain WS (private network)
Client ──wss://relay.cdn.com/ws──► CDN ──ws://relay:8080/ws──► Relay
  │                                │
  │‑ Client sees CDN's valid cert  │‑ CDN terminates TLS
  │‑ Client never sees relay IP    │‑ Forwards upgrade as-is
  │‑ Blends with millions of       │‑ Connection to origin is
  │  other CDN sites               │  plain WS on private network
```

The relay operator does not need a TLS certificate. The CDN provides one. The
relay listens on `[server] address = "127.0.0.1:8080"` with
`[ws] enabled = true` — plain WebSocket behind the CDN is perfectly safe.
Clients use the WebSocket-over-TLS client API against the CDN hostname.

#### Cloudflare Tunnel (recommended)

[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
lets the relay make a single outbound connection to Cloudflare, eliminating the
need for a public IP or open firewall ports entirely:

```
Client ──wss://relay.cdn.com/ws──► Cloudflare edge
                                       ▲
                                       │ outbound tunnel (no open ports)
                                       │
                                   Relay (cloudflared on localhost:8080)
```

- No public IP required — works behind CGNAT, residential ISPs, or firewalls.
- No open ports — only outbound connections.
- Free tier handles unlimited traffic.
- DPI sees traffic to Cloudflare IPs, not the relay.

The relay itself needs no changes — it listens on localhost as usual.

#### CDN Config

```toml
[server]
address = "127.0.0.1:8080"   # localhost only — CDN connects via tunnel
password = ""
expose_health = false
expose_ip = false

[ws]
enabled = true

[tcp]
enabled = false

[tls]
enabled = false
```

#### Comparison: Direct TLS vs CDN vs Cloudflare Tunnel

|                     | Direct TLS listener | CDN (Cloudflare)                   | Cloudflare Tunnel         |
| ------------------- | ------------------- | ---------------------------------- | ------------------------- |
| Relay IP hidden     | No                  | Yes (CDN IP shown)                 | Yes (no public IP at all) |
| TLS cert            | Self-signed (auto)  | CDN's valid cert                   | CDN's valid cert          |
| DPI evasion         | Good (raw TLS)      | Excellent (blends with CF traffic) | Excellent                 |
| Cost                | Free                | Free                               | Free                      |
| Open ports required | Yes (port 443)      | Yes (port 443 on origin)           | No (outbound only)        |
| Setup complexity    | None (auto-cert)    | DNS + proxy toggle                 | Install cloudflared       |

#### Cloudflare Workers

[Cloudflare Workers](https://workers.cloudflare.com/) can act as a WebSocket
proxy between clients and the relay, optionally adding auth, logging, or IP
filtering at the edge. The Worker forwards the WebSocket upgrade transparently;
the relay sees the Worker's IP, not the client's.
