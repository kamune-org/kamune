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

### Cross-Transport Sessions

Sessions are **transport-agnostic**. Any two peers that share a token can be
bridged regardless of which transport each uses (WebSocket, WSS, raw TCP, or
TLS). The relay forwards bytes between the two `exchange.Channel`s without
inspecting the underlying connection.

A practical use: a peer behind a restrictive NAT that only allows raw TCP can
hand its token to a peer in a browser using WSS, and the relay will bridge them
transparently. Each side only needs to know the relay address for its own
transport and the shared token.

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

## Static Tokens

By default the listener receives a random 16-byte token from the relay and
shares it with the dialer out of band (QR code, link, text message). The
static-tokens mode lets both peers compute the same token independently from
each other's long-term public keys, so the listener never has to publish a fresh
token to the dialer when reconnecting after an IP change.

### Motivation

When a peer's public IP changes (DHCP renewal, NAT rebinding, network switch),
the existing relay session is gone. Both peers must redo the full dance:

1. Listener connects to relay, gets a new random token
2. Listener communicates the new token to the dialer out of band
3. Dialer connects to the relay with that token

Step 2 is the friction. The peers already know each other's long-term public
keys (the same mechanism used for identity verification). They can derive a
session identifier deterministically from those keys.

### Token Derivation

Both peers compute the same token via:

```
token = SHA256(min(A, B) || max(A, B))[:16]
```

where `min` and `max` are the lex-smallest and lex-largest of the two peers'
public keys (as raw 32 bytes). This is order-independent: neither peer needs
to know which one is "A" — both compute the same token. Both peers must
use ed25519 public keys of the standard 32-byte size to compute the same
token.

### Wire Protocol

The `Register` message gains a `Mode` field to make "create" vs "join"
explicit:

```protobuf
message Register {
  bytes token = 1;  // 16 bytes in MODE_JOIN; empty or 16 bytes in MODE_CREATE
  Mode  mode  = 2;  // required: MODE_CREATE or MODE_JOIN

  enum Mode {
    MODE_UNSPECIFIED = 0;  // reserved, will be rejected
    MODE_CREATE      = 1;  // create new session
    MODE_JOIN        = 2;  // join existing session
  }
}
```

The pre-static-token protocol distinguished "create" vs "join" by the token
field alone (empty vs non-empty). Making it explicit via `Mode` is the
breaking change. Old clients that send `Mode = MODE_UNSPECIFIED` are
rejected.

Server behavior by `mode`:

| `mode`             | `token`   | Action                                                                        |
| ------------------ | --------- | ----------------------------------------------------------------------------- |
| `MODE_UNSPECIFIED` | any       | Reject. Close connection, log "unsupported register mode".                    |
| `MODE_CREATE`      | empty     | Generate random 16-byte token. Register session. (Default listener behavior.) |
| `MODE_CREATE`      | non-empty | Register session under provided token. Reject on duplicate (no preemption).   |
| `MODE_JOIN`        | empty     | Reject. Close connection, log "join requires token".                          |
| `MODE_JOIN`        | non-empty | Look up session. Pair dialer with listener if found.                          |

The relay's behavior is the same regardless of whether the token is
precomputed or randomly generated — both are 16-byte opaque strings from
the relay's perspective. The choice is the peers', not the operator's.

**Design decision: static mode is not a config flag.** The relay operator
does not have a say in how peers connect to each other. Static tokens are
always available; listeners that want to use them just pass the
precomputed token. There is no operator opt-in.

### Client Behaviour

Listeners that want to use static tokens pass the precomputed 16-byte
token when opening the connection. The dialer passes the same token
(which it computed independently). Both peers need the same ed25519
public keys (typically exchanged out of band at first contact).

The wire protocol and behaviour described in this section are
independent of any client library. Clients in any language that
implement the `Register{Mode, Token}` flow described above will work
with any conformant relay. The kamune Go library is one such
implementation; the function names and option types in that library
are an implementation detail of the Go ecosystem.

### Properties

- **Both peers compute the same token independently.** Given the two
  contacts' long-term public keys, each peer derives the same 16-byte
  session token via `SHA256(min(A, B) || max(A, B))[:16]`. Neither peer
  needs the other to send them a token.
- **Coexists with the existing random-token system.** Listeners can ask
  the relay to generate a random token (the default); static tokens are
  opt-in per registration.
- **Same TTL semantics.** Static tokens use the existing `token_ttl`
  config (default 5 minutes). The listener re-registers periodically to
  keep the session alive.
- **Forward secrecy is unaffected.** The static token is a routing
  identifier for the relay only; end-to-end authentication and encryption
  are established directly between the two peers after rendezvous, using
  the kamune protocol layer.

### Reconnection on IP Change

When a peer's public IP changes (DHCP renewal, NAT rebinding), the existing
relay session is gone. Both peers re-derive the same token from the same
public keys and re-register — the listener sends
`Register{Mode: MODE_CREATE, Token: T}` again, the dialer sends
`Register{Mode: MODE_JOIN, Token: T}`. Neither peer needs to communicate
the token out of band again.

This works for any IP change: NAT rebinding (same IP, new port), network
switch (new IP), or even a completely different device, as long as both
peers have access to the same long-term public keys.

## Broker: STUN-Echo and Signal Introduction

The relay's transports are useful for any peer that can connect outbound, but
peers behind restrictive NATs benefit from a direct UDP path between them when
possible. The broker is a separate UDP service that combines two functions
needed for P2P hole-punching:

1. **STUN-like IP echo** — a peer sends a packet; the broker responds with the
   peer's perceived public IP:port.
2. **Signal introduction** — two peers register with a shared token; when both
   are present, the broker notifies each with the other's claimed IP:port so
   they can hole-punch directly.

The broker is optional. If the operator enables it, peers can use the
kamune broker client (or implement the on-the-wire protocol directly) to
discover each other and try a direct connection. The relay continues to
function as a fallback when hole-punching fails.

**Design decision: UDP, not TCP.** TCP-based signaling (HTTP, WebSocket) is
fingerprintable and easy to block. UDP is the right primitive for STUN-echo
and for one-shot introducer packets. The broker uses a single UDP listener
on a configurable port (default `127.0.0.1:4788`).

**Design decision: two functions, one wire format.** The broker combines STUN
and signaling into a single wire format with a fixed 4-byte magic (`"KBRK"`)
and a 1-byte opcode. This keeps the implementation small and the fingerprint
narrow (4 bytes of fixed header for the active protocol).

### Wire Format

All packets share a common 6-byte header:

```
offset  size  field
0       4     MAGIC    "KBRK"     (0x4B 0x42 0x52 0x4B)
4       1     VER      0x01
5       1     OPCODE   0x01 = STUN_ECHO
                  0x02 = REGISTER
                  0x03 = NOTIFY
```

#### `STUN_ECHO` (peer → broker)

```
MAGIC | VER | OPCODE=0x01
```

6 bytes. The broker responds with ASCII `ip:port\0` to the sender's UDP
address — the IP/port are derived from the packet's source address, not from
any field in the packet itself. Example: `192.0.2.1:54321\x00`.

#### `REGISTER` (peer → broker)

```
MAGIC (4) | VER=0x01 (1) | OPCODE=0x02 (1) | TOKEN (16) | PEER_EPH_PUB (32) | IP (4) | PORT (2)
```

60 bytes. Fields:

- `TOKEN` — 16 bytes, may be all zero (random mode) or precomputed (static
  mode, see [Static Tokens](#static-tokens)).
- `PEER_EPH_PUB` — the peer's stable X25519 public key (raw 32 bytes). The
  broker uses this both for encryption (per-NOTIFY ECDH) and to identify
  the same peer across re-registrations.
- `IP`, `PORT` — the peer's claimed public IPv4 + port. The broker echoes
  these to a matched peer in `NOTIFY(PEER_MATCHED)`.

#### `NOTIFY` (broker → peer, encrypted)

```
MAGIC (4) | VER=0x01 (1) | OPCODE=0x03 (1) | BROKER_EPH_PUB (32) | NONCE (24) | SEALED (N)
```

- `BROKER_EPH_PUB` — the broker's fresh ephemeral X25519 public key,
  generated per-NOTIFY for forward secrecy.
- `NONCE` — 24 bytes, random, for XChaCha20-Poly1305.
- `SEALED` — `Seal(plaintext)` output: ciphertext followed by 16-byte tag.
  Sizes:
  - `PEER_MATCHED`: 6 + 32 + 24 + 55 + 16 = **133 bytes**
  - `TOKEN_ASSIGNED`: 6 + 32 + 24 + 21 + 16 = **99 bytes**

Encrypted payload layout (depends on `TYPE`):

- `TYPE = 0x01` (`PEER_MATCHED`): `TYPE (1) | TOKEN (16) | OTHER_PEER_EPH_PUB (32) | IP (4) | PORT (2)` — 55 bytes plaintext.
- `TYPE = 0x02` (`TOKEN_ASSIGNED`): `TYPE (1) | TOKEN (16) | TTL_SECONDS (4)` — 21 bytes plaintext.

The peer derives the AEAD key and decrypts:

```
shared_secret = X25519(peer_ephemeral_private, broker_ephemeral_public)
aead_key     = SHA256(shared_secret)[:32]
AAD          = MAGIC || VER || OPCODE || BROKER_EPH_PUB
```

and decrypts `SEALED` with XChaCha20-Poly1305 (24-byte nonce, 16-byte tag).
The AAD binds the ciphertext to the broker's ephemeral key so a captured
NOTIFY cannot be re-targeted to a different broker key.

NOTIFY is sent by the broker only; peers that send NOTIFY are ignored.

### Static Tokens

The same static-token mechanism that the relay's transports support
(see [Static Tokens](#static-tokens) above) applies to the broker:

- Both peers compute `token = SHA256(min(A, B) || max(A, B))[:16]` from each
  other's long-term public keys.
- Peer A registers as listener with the static token; peer B joins with the
  same token. The broker matches them.
- When peer A's IP changes (NAT rebinding, DHCP renewal), both peers
  re-derive the same token from the same public keys — no OOB exchange
  needed.

**Design decision: peer identity = `PEER_EPH_PUB`, not source address.** The
broker identifies the same peer by the X25519 public key it sends in
REGISTER, not by the source UDP address. This handles NAT rebinding (the
peer's source port changes but the key stays the same) and treats two
distinct processes from the same IP as different peers (their keys
differ). The peer must use a stable key across re-registrations; the
client library holds one key for its lifetime.

**Design decision: hybrid token model.** Static tokens (above) and
broker-assigned random tokens share the same wire format. A peer
registering with an empty `TOKEN` field gets a 16-byte random token via
`NOTIFY(TOKEN_ASSIGNED)` and shares it with the dialer out of band. Both
modes go through the same registry and the same match logic.

### Server Behavior

For every received UDP datagram, the broker:

1. Rejects packets shorter than 6 bytes.
2. Verifies the 4-byte magic and 1-byte version.
3. Dispatches by opcode.

**`STUN_ECHO`** (opcode 0x01): responds with `ip:port\0` from the packet's
source address. No state, no encryption, no registry interaction.

**`REGISTER`** (opcode 0x02): validates the packet, generates a fresh broker
ephemeral X25519 key, and branches on the token:

| `TOKEN`   | Registry state                                               | Action                                                                                                           |
| --------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| empty     | n/a                                                          | Generate a random 16-byte token. Store `T → peer` (TTL). Send `NOTIFY(TOKEN_ASSIGNED)` to peer.                  |
| non-empty | empty                                                        | Store `TOKEN → peer` (TTL). No NOTIFY — the peer already knows the token.                                        |
| non-empty | held by a different peer (different `PEER_EPH_PUB`)          | Match. Send `NOTIFY(PEER_MATCHED)` to BOTH peers, each with its own fresh broker ephemeral key. Clear the entry. |
| non-empty | held by the same peer (same `PEER_EPH_PUB`, re-registration) | Refresh TTL. No NOTIFY.                                                                                          |

The broker generates a **fresh** X25519 key pair for **every** NOTIFY it
sends. A match produces two NOTIFYs, each with its own broker ephemeral
public key in the header. Forward secrecy is per-NOTIFY, not per-REGISTER.
After the NOTIFY is sent, the broker's ephemeral private key is discarded.

**`NOTIFY`** (opcode 0x03): ignored. Peers should not send NOTIFY.

**Unknown opcode**: ignored. Random UDP that happens to start with `"KBRK"` and
some random opcode is silently dropped.

### Anti-Fingerprint

| Packet type                                    | Recognizable?               | Notes                                                                |
| ---------------------------------------------- | --------------------------- | -------------------------------------------------------------------- |
| `STUN_ECHO`                                    | Yes (peer opts in)          | Response is plaintext `ip:port\0` from source address                |
| `REGISTER`                                     | Yes (peer opts in)          | Plaintext header; not sensitive (token + claimed IP + ephemeral pub) |
| `NOTIFY`                                       | Encrypted                   | Server-only; AEAD-sealed payload; header has fixed fingerprint       |
| Random UDP                                     | No response                 | Ignored                                                              |
| Random UDP that happens to start with `"KBRK"` | Falls into "unknown opcode" | Ignored                                                              |

A passive observer sees the 4-byte magic, the 1-byte version, the 1-byte
opcode, and (for NOTIFY) the broker's ephemeral public key and the nonce.
They cannot read the payload or tag without the peer's ephemeral private
key. Packet sizes and timing metadata are visible, as on any UDP service.

This is better stealth than a design that echoes every packet: random
UDP scanners see no response and cannot tell if the broker is up. A more
elaborate stealth design (variable packet sizes, padding, timing
obfuscation) is out of scope for v1.

### Threat Model

The broker is **lower-trust** than the relay's transports:

- The broker **sees** the matched peers' claimed IP:port and ephemeral
  public keys (passed through in NOTIFY plaintext).
- The broker **does not see** message content (the broker hands off and is
  out of the picture; subsequent traffic is end-to-end between peers).
- A malicious broker can disrupt rendezvous (drop REGISTERs, refuse
  matches) but cannot read application traffic.
- The broker does not pin a long-term identity; every broker ephemeral
  key is fresh per NOTIFY. A compromised broker cannot decrypt past
  NOTIFYs (forward secrecy per NOTIFY).

**Design decision: no long-term broker identity.** This removes the
operational burden of key distribution and gives forward secrecy
automatically. Peers do not need to pin anything.

### Replay Considerations

The v1 broker does not implement anti-replay. The shared secret prevents
forgery; only valid packets can be replayed. The threat model:

- **Replayed `REGISTER`**: an attacker can disrupt legitimate registrations
  or refresh a held entry's TTL. Mitigation: per-IP rate limiter (shared
  with the relay).
- **Replayed `NOTIFY`**: the peer receives a duplicate. AEAD verification
  still applies; if the broker's ephemeral key has changed (which it does
  on every re-registration, since the broker generates a fresh key per
  NOTIFY), the replayed ciphertext fails verification. Captured NOTIFYs
  are mostly self-healing.
- **Replayed `STUN_ECHO`**: a known STUN protocol property; v1's response
  does not include a request nonce. Peers should cross-check STUN_ECHO
  responses against a parallel connection attempt, or use a different
  STUN source. The broker is not the only STUN source a peer should trust.

Adding full anti-replay (sequence numbers, nonce tracking, per-peer
session-expiry state) would significantly complicate the implementation
for limited benefit at v1's threat model. The shared AEAD already prevents
forgery; the per-IP rate limiter caps the most relevant attack (replayed
REGISTER).

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

[broker]
enabled = false               # UDP signaling (STUN-echo + signal intro); off by default
address = "127.0.0.1:4788"    # IPv4 only in v1
# registration_ttl = "60s"    # How long a held registration lives before eviction

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

| Field                     | Default          | Range  | Behavior on `0`                                                 |
| ------------------------- | ---------------- | ------ | --------------------------------------------------------------- |
| `token_ttl`               | `5m`             | `> 0`  | (rejected)                                                      |
| `session_ttl`             | `30m`            | `>= 0` | no limit                                                        |
| `handshake_timeout`       | `30s`            | `>= 0` | treated as default (30s)                                        |
| `max_concurrent_sessions` | `10000`          | `> 0`  | (rejected)                                                      |
| `max_message_size`        | `65536`          | `>= 0` | no limit                                                        |
| `time_window`             | `1m`             | `> 0`  | (rejected)                                                      |
| `quota`                   | `20`             | `> 0`  | (rejected)                                                      |
| `broker.enabled`          | `false`          | bool   | broker goroutine not started                                    |
| `broker.address`          | `127.0.0.1:4788` | string | (no default when `enabled = true`; must be a valid `host:port`) |
| `broker.registration_ttl` | `60s`            | `> 0`  | (rejected)                                                      |

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

### Direct UDP Broker (single host)

To enable P2P hole-punching for peers behind permissive NATs, enable the
broker on the same host. The broker is a single UDP listener on the
configured port; peers discover each other and try to connect directly. If
hole-punching fails, they fall back to the relay as before.

```toml
[server]
address = "127.0.0.1:8888"
password = ""
expose_health = false
expose_ip = false

[ws]
enabled = true           # WebSocket still available as the relay fallback

[broker]
enabled = true
address = "0.0.0.0:4788"  # public, so peers behind NATs can reach it
# registration_ttl = "60s"
```

The broker and the relay's transports run in the same process but on
different ports. The broker shares the relay's per-IP rate limiter. Peers
talk to the broker first to discover each other's IP:port; if direct UDP
fails, they fall back to the relay over WS/WSS/TCP/TLS as usual.

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
- **Broker registry growth** (when broker is enabled) — entries are held
  in an in-memory map and evicted on `registration_ttl` (default 60s). The
  per-IP rate limiter caps registrations per IP. Map size is bounded by
  the number of active registrations; TTL evicts stale entries.

## Operator Responsibilities

The relay operator is responsible for:

- Running behind a CDN or tunnel for IP-hiding in hostile networks.
- Setting `[server] password` to enable PSK mode if the relay is exposed.
- Tuning `max_concurrent_sessions`, `token_ttl`, and `session_ttl` to match
  expected load.
- Disabling `expose_health` and `expose_ip` on public deployments to avoid
  leaking connection metadata.
- When the broker is enabled, opening UDP `4788` (or the configured port)
  in the host firewall. The broker has no TLS layer; if the deployment
  hides the relay's IP behind a CDN, the broker cannot be CDN-fronted
  and is exposed directly. Operators in hostile networks should leave
  the broker disabled and rely on the relay.

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
