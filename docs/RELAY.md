# Relay Protocol

Kamune includes a relay server for NAT traversal. The relay is a **blind
token-based session switch**: a listener connects, receives a random token,
shares it out of band, and the dialer connects with that token. The relay
bridges encrypted frames between the two. A relay that forwards those frames
unchanged learns nothing about the peers' identities or message content; what an
active relay can learn is set out in the [Threat Model](#threat-model).

The relay makes no trust decisions beyond an optional pre-shared key. End-to-end
authentication and encryption are established directly between the two peers;
the relay is a low-trust message forwarder.

## Design Goals

- **Blind**: a relay that forwards frames unchanged never sees public keys,
  identities, or message content. An active relay can read the peers' public
  keys and names, but not their messages (see [Threat Model](#threat-model)).
- **Stateless**: no queues, no offline messages. Tokens, sessions, and
  rate-limit counters are ephemeral, scoped to the relay process lifetime. The
  relay writes to disk only the self-signed TLS certificate and key it keeps in
  `server.data_dir` for a `[tls]` or `[wss]` listener without a certificate of
  its own (see [TLS](#tls-tls)).
- **Zero metadata**: no social graph, no presence tracking, no persistent
  identifiers across connections.
- **Out-of-band rendezvous**: the only thing peers exchange is a short random
  token — no key material, no addresses.
- **Transport-agnostic**: same protocol over WebSocket, raw TCP, or TLS.

## Threat Model

The relay is a **low-trust relay**. Callers must assume:

- A **passive network attacker** on the path between client and relay can
  observe connection metadata (timing, sizes, IP pairs) but not message
  contents.
- An **active network attacker** on that path can pose as the relay unless the
  client checks the relay's TLS certificate. The HPKE exchange between a client
  and the relay does not authenticate the relay, so over `ws`, `tcp`, or TLS
  without a verified or pinned certificate, such an attacker receives the PSK
  and the session token and can do anything a malicious relay can.
- The **relay operator** can deny service, log connection metadata, and observe
  which connection pairs share a session. They cannot read message contents.
- A **malicious relay** cannot read the messages of an established session or
  impersonate a peer whose identity key the other peer checks: the kamune
  handshake is signed with the peers' identity keys. It can read what the peers
  send before that handshake completes, their identity keys included (see
  below).

### What the Relay Observes

This table holds for a relay that forwards frames unchanged.

| The relay observes               | The relay does NOT observe                                |
| -------------------------------- | --------------------------------------------------------- |
| Session `S` has 2 connections    | Public keys of either peer                                |
| Connection `A` is in session `S` | Identity of any peer                                      |
| Session `S` received a message   | Persistent identifier (random tokens are single-use)      |
|                                  | Message content (E2E encrypted)                           |
|                                  | Social graph (each random token is unique per rendezvous) |

Such a relay never learns who any peer is, only that two connections share a
token. Static tokens are the exception to the "Persistent identifier" and
"Social graph" rows: a pair's static token is the same in every session, so the
relay can link those sessions (see [Static Tokens](#security-considerations)).

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
- **Read the PSK and tokens** that clients send: the HPKE channel between a
  client and the relay ends at the relay.
- **Read the peers' introductions** by running the kamune Exchange separately
  with each peer and re-encrypting the frames between them. That Exchange is
  unauthenticated HPKE and nothing later in the kamune handshake binds it, so
  neither peer notices. The relay then reads both Introduce messages (name,
  identity public key, app version), the session ID, and, when a peer resumes a
  session, its resumption token. With the two public keys it can compute the
  pair's static token and link the pair's sessions over time.

The attacker **cannot**:

- Read message contents. The session keys come from the kamune handshake
  (ML-KEM-768), whose messages each peer signs with its identity key, so a
  relay that splits the Exchange still cannot learn them, provided each peer
  checks the other's identity key.
- Impersonate a peer to a user who checks that peer's identity key (no
  long-term keys are exchanged with the relay; peers authenticate each other
  after rendezvous).
- Decrypt past sessions retroactively (ephemeral keys per session; see
  [Forward Secrecy](#forward-secrecy)).

## Protocol

### Wire Format

For TCP and TLS transports, every frame is a length-prefixed payload: two
big-endian bytes of length followed by exactly that many bytes of payload. The
length is a `uint16`, so a frame carries at most 65,535 bytes. Both ends of a
connection MUST agree on the maximum; if they differ, the stricter end will
reject frames the other would have accepted.

For WebSocket transport, frames are sent as binary WebSocket messages; the
WebSocket layer's framing replaces the length prefix. The relay reads WebSocket
messages of up to `max_message_size` bytes (65,536 by default, at most
131,072), and the Go client reads up to 131,072 bytes. A frame the relay
forwards to a peer on TCP or TLS must still fit the 65,535-byte limit, or the
write fails and the relay closes both peers.

These sizes count the whole relay frame: the payload wrapped in a `Message`
frame and sealed for the HPKE channel. Kamune keeps its own frames to 65,471
bytes (SPEC 4.1), and the relay's wrapping adds 24 bytes to a frame of that
size, so every kamune frame fits on every transport.

**Design decision:** length-prefixed framing was chosen over delimiter-based
framing because it allows zero-byte payloads, avoids escaping problems, and
makes the byte stream resumable. The 64 KiB ceiling is a deliberate small-frame
choice that limits blast radius from a malicious peer. The protocol above the
relay has to keep its frames under it; kamune does not split frames.

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
    bytes token = 1;  // MODE_CREATE: empty asks the relay for a random
                      // 16-byte token, or a 32-byte token the listener chose.
                      // MODE_JOIN: the session's token, 16 bytes if the relay
                      // generated it, 32 bytes if the listener chose it
    Mode  mode  = 2;  // Required: MODE_CREATE (listener) or MODE_JOIN (dialer)

    enum Mode {
        MODE_UNSPECIFIED = 0;  // Rejected
        MODE_CREATE      = 1;  // Create a session
        MODE_JOIN        = 2;  // Join an existing session
    }
}

message Registered {
    bytes  token               = 1;  // The token from Register, or the
                                     // relay-generated 16-byte token
    uint32 ttl_seconds         = 2;  // Token validity (offer window); 0 in
                                     // the reply to MODE_JOIN
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
3. If the relay is in PSK mode, send `Frame.Auth{psk}` and wait for the relay's
   empty `Frame.Auth` before registering.
4. Send `Frame.Register{mode: MODE_CREATE}` with an empty token to request a
   new session, or with a 32-byte token of the listener's choosing (see
   [Static Tokens](#static-tokens)).
5. Receive `Frame.Registered{token: T, ttl_seconds, session_ttl_seconds}`. `T`
   is a random 16-byte token, or the token the listener sent.
6. Share `T` with the dialer out of band (QR code, text message, NFC, etc.).
7. Enter read loop. The first incoming `Frame.Message{data}` establishes the
   session — the dialer has arrived.

#### Dialer (joins session)

1. Establish a transport connection.
2. Perform an HPKE key exchange.
3. If the relay is in PSK mode, send `Frame.Auth{psk}` and wait for the relay's
   empty `Frame.Auth` before registering.
4. Send `Frame.Register{mode: MODE_JOIN, token: T}` with the token received
   from the listener.
5. The relay validates `T`, joins the dialer to the session, and sends the
   dialer a `Frame.Registered{token: T, ttl_seconds: 0, session_ttl_seconds}`
   to confirm.
6. Enter read loop. Messages are now bridged.

The relay sends no error frame. When it cannot register a client (unknown,
taken or expired token, a token that fails the checks, a full session table)
it closes the connection.

```
Listener                                    Relay
   │                                          │
   ├── Connect ──────────────────────────────►│
   ├── HPKE Initiate ────────────────────────►│
   ├── (Auth if PSK) ────────────────────────►│
   ├── Register{CREATE} ─────────────────────►│
   │◄─ Registered{token: T, ttl, session_ttl} ┤
   │                                          │
   │  (share T with dialer OOB)               │
   │                                          │
   │                 Dialer                   │
   │                    │                     │
   │                    ├── Connect ─────────►│
   │                    ├── HPKE Initiate ───►│
   │                    ├── (Auth if PSK) ───►│
   │                    ├── Register{JOIN, T}►│
   │                    │◄─ Registered{T} ────┤
   │◄══════ Message{data} ═══════════════════╝│
   │══════ Message{data} ════════════════════►│
```

### Token Lifecycle

1. **Issued**: the relay generates `T = crypto/rand` 16 bytes, or takes the
   32-byte token the listener sent, and creates a session. The session has one
   participant: the listener.
2. **Consumed**: when a dialer sends `Register{mode: MODE_JOIN, token: T}`, the
   relay joins the dialer's connection to the session. The token is now
   consumed: no further peer can join with the same `T`.
3. **Expired**: if the listener disconnects before a dialer joins, the token is
   discarded and cannot be used. Once paired, the session ends when either
   peer's connection closes: the relay removes it and closes the other peer.
4. **TTL**: tokens have a configurable time-to-live (`token_ttl`, which every
   config must set; the shipped config uses 10 minutes). If no dialer joins
   within the TTL, the session is cleaned up.

**Design decision: 16-byte tokens.** A 16-byte (128-bit) token provides 128 bits
of entropy, which is more than enough to make guessing infeasible. 16 bytes also
fits comfortably in a QR code without the dialer needing to scan anything more
elaborate. Shorter tokens would be QR-friendly but reduce entropy; longer tokens
buy nothing practical.

Relay-generated tokens are:

- **Single-use**: one dialer per token.
- **Time-bound**: TTL enforced server-side.
- **Opaque**: the relay does not embed any peer information in the token.
- **Unpredictable**: generated by `crypto/rand`.

### Session Lifetime

A paired session is bounded by `session_ttl` (`0` or unset = no limit; the
shipped config uses 60 minutes). After this duration, the relay closes both
peers regardless of activity. This is independent of `token_ttl`, which
controls the offer window before pairing.

**Design decision: two-tier TTL.** The token offer window and the session max
lifetime are conceptually different:

- `token_ttl` is a UX concern: how long a share card (QR code) stays valid. It
  should be short (5 minutes) to minimize the cost of abandoned offers.
- `session_ttl` is a resource concern: how long a paired session can hold a slot
  in the relay's session map. It should be long enough for the use case (30
  minutes is generous) or unlimited (0).

A single TTL would force a compromise that hurts one of these.

### Backpressure and Message Drops

The relay keeps **no queue and does not retry**. It forwards each `Message`
frame from the sender's read loop: it reads a frame, writes it to the other
peer, and only then reads the sender's next frame.

- **Absent recipient.** A frame sent before the other peer has joined is
  dropped.
- **Slow recipient.** The relay waits up to 15 seconds for each write to the
  recipient. Meanwhile it reads nothing more from the sender, its pings
  included, so a slow recipient holds the sender back through the transport's
  flow control. When a write does not complete within 15 seconds, the relay
  closes both peers. A frame is never dropped because the recipient is slow.

Kamune does not retransmit, and a missing frame ends a kamune session (SPEC 8.2
and 9.4). A dropped frame would therefore end the session too, only later and
less clearly than closing both connections does.

**Design decision: no queue.** Queuing would require:

- Persistent storage (violates the stateless goal).
- A notion of "session mailbox" (introduces replay windows).
- Per-recipient ordering state (CPU and memory cost per session).

The chosen design is simpler, more predictable, and has bounded resource cost
per session. The costs are that messages sent before both peers are connected
are lost, and that a slow peer holds up the other one and can end the session.
Callers above the relay handle this.

### Forward Secrecy

Each connection to the relay runs its own HPKE exchange with fresh ephemeral
keys. The relay holds its end of that channel and decrypts every frame on it by
design, so the forward secrecy that protects message content comes from the
kamune session the peers run inside `Message` frames. Its keys come from an
ephemeral ML-KEM-768 key pair per session (SPEC 12.4), so a relay that records
the traffic, or a later compromise of a long-term identity key, does not reveal
the keys of a past session.

**Design decision: ephemeral per-session keys.** Long-term keys would allow the
relay to persist identity across sessions (violating zero-metadata) and would
mean a single key compromise decrypts all sessions ever routed through that
relay. Ephemeral keys buy both better privacy and better security at the cost of
slightly more work per handshake.

### Replay Protection

Replay protection is **explicitly out of scope** at the relay layer. The relay
does not track, deduplicate, or sequence messages. Replay defense is the
responsibility of the end-to-end Kamune protocol layer, which numbers every
frame of a session (SPEC 8.2) and derives fresh session keys from an ML-KEM-768
handshake for each session. The rendezvous token plays no part in it.

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
each other. The peers authenticate each other end-to-end after the rendezvous,
in the kamune handshake, with their identity keys; the token plays no part in
it.

In PSK mode, the password is sent inside the HPKE channel to the relay and
verified with a constant-time comparison. A wrong or missing password closes
the connection, and so does an `Auth` frame sent to a relay without a password.
The relay answers a correct password with an empty `Frame.Auth`.

That HPKE channel ends at the relay and does not authenticate it, so it hides
the password from passive observers only. An active attacker that poses as the
relay receives the password, and the client accepts any `Auth` reply, so the
reply does not prove that the relay knows the password. Send a password only
over `wss` or `tls` with a certificate the client verifies or pins (see
[TLS](#tls-tls)).

### Rate Limiting

Rate limiting applies per client address before the key exchange, and for a
client that connects directly also before any TLS handshake, so abusive clients
are rejected without burning the relay's CPU on asymmetric crypto.

| Aspect      | Behavior                                                                 |
| ----------- | ------------------------------------------------------------------------ |
| Algorithm   | Sliding window log                                                       |
| Window      | `time_window` (default 1 minute)                                         |
| Quota       | `quota` (default 20 per window)                                          |
| Keying      | IPv4 address, or the /64 of an IPv6 address                              |
| Boundedness | `max_entries` addresses per limiter (default 100,000; `0` = no cap)      |
| Eviction    | Least recently used address when a limiter is full                       |
| TTL         | Dropped by a sweep, once per window, after its requests leave the window |

What counts against the quota:

- **TCP and TLS**: every accepted connection, keyed by the TCP peer's address.
  A TLS connection is charged before its TLS handshake.
- **WebSocket** (`ws` and `wss`): every request to `/ws`, keyed by the client
  address. A connection from a peer outside `trusted_proxies` also spends a
  separate connection quota, with the same settings, as it is accepted and
  before TLS. A peer over the connection quota has its connection closed
  without a response; one over the request quota gets HTTP 429. TCP health
  checks against these ports count as well, so point a load balancer's checks
  at the `[diagnose]` listener instead.

TCP and TLS connections and WebSocket requests share one limiter. The UDP
broker has limiters of its own (see
[Rate Limits and Registry Size](#rate-limits-and-registry-size)).
`disabled = true` in `[rate_limit]` turns every limiter off.

**Client address behind a proxy.** The relay reads a forwarded client address
only for a WebSocket request whose TCP peer is in `server.trusted_proxies`, and
only from the one header named by `server.client_ip_header` (default
`X-Forwarded-For`). `X-Forwarded-For` is read from the right, across all its
header lines, skipping trusted hops and stopping at an entry that does not
parse. Any other header must hold a single address on a single line, as a proxy
that sets it writes it. No other header is read, so behind a proxy that sets
only `X-Real-IP` or `CF-Connecting-IP`, set `client_ip_header` to that name.
Without a usable address in the header, the request is keyed by the proxy's
address, and the relay logs a warning the first time this happens. A trusted
proxy's connections are not charged at accept; its requests are limited by
client address.

With `trusted_proxies` empty, every client of a proxy or tunnel in front of the
relay shares the proxy's quota. The relay warns at startup for each enabled
`ws` or `wss` listener on a loopback, private or link-local address while the
limiter is on and `trusted_proxies` is empty, and once at run time when it
refuses a `ws` or `wss` peer on such an address. See
[CDN-Backed Deployments](#cdn-backed-deployments).

**Design decision: rate-limit by IP, not by token.** Tokens are opaque to the
rate limiter (a client may not have a token yet — that's the listener case). IP
is the only stable identity available at connection time.

**Design decision: rate-limit before HPKE.** The whole point of rate limiting is
to prevent abuse. Putting it after the HPKE handshake would let attackers force
the relay to do expensive asymmetric crypto on every connection attempt. The
check is a simple, fast lookup that costs the relay nothing to reject.

**Design decision: sliding window log, not token bucket.** A sliding window log
gives exact "N events in the last T seconds" semantics with no edge cases at
window boundaries. The cost is up to N timestamps per address, where N is the
quota, and an address starts with none. Since the quota is small (default 20),
this is fine.

## Transports

The relay supports three transports, served by four independent listeners,
each configured via its own section in the TOML config: `[ws]` and `[wss]`
(WebSocket), `[tcp]` and `[tls]`. Any combination can be active at once.

The client API takes the relay address, an optional password (for PSK mode)
and, for `wss` and `tls`, a TLS client configuration. No peer key or identity
key is needed: the dialer discovers the session via the token, and the HPKE
exchange generates ephemeral keys per connection.

### WebSocket (`[ws]` and `[wss]`)

A WebSocket listener on its own address, serving the relay protocol at `/ws`.
`[ws]` speaks plain HTTP; `[wss]` is the same listener over TLS, with the
certificate handling described under [TLS](#tls-tls). Suitable for permissive
networks, local development, and deployments behind a CDN.

Both listeners take one request per connection: HTTP/1.1 only (no HTTP/2 on
`wss`), keep-alives off, and the connection closed after any response other
than an upgrade. Reading the request and writing such a response may take 30
seconds each, and request headers are capped at 32 KiB. An upgraded connection
is free of these limits; the handshake timeout then bounds its registration.

`/ws` answers any request that carries an `Origin` header with HTTP 403. Native
clients send none and browsers always send one, so a browser-based client
cannot use the relay, and a web page cannot have its visitors' browsers open
sessions on it.

### Raw TCP (`[tcp]`)

A bare TCP listener with length-prefixed framing. No TLS, no HTTP — just 2-byte
big-endian length + payload over a plain TCP stream. Suitable for trusted LANs,
VPN backends, and development.

### TLS (`[tls]`)

A TLS-encrypted TCP listener using the same length-prefixed framing, but wrapped
in a TLS 1.3 connection. To passive DPI this is indistinguishable from any other
TLS service on port 443 — no HTTP upgrade, no opcodes, no protocol fingerprint.
The `[tls]` and `[wss]` listeners accept TLS 1.3 only.

**Certificates.** `[tls]` and `[wss]` each take a `cert_file` and a `key_file`
in PEM, set together or not at all. A configured file that is missing or does
not load stops the relay at startup. When both are empty, the listener uses the
relay's self-signed certificate, which `[tls]` and `[wss]` share:

- The relay creates it on first use in `server.data_dir` (default
  `kamune-relay` in the user's configuration directory, such as
  `~/.config/kamune-relay`) as `relay-cert.pem` and `relay-key.pem`, and loads
  the same files on later starts. It never replaces them; if only one of the
  two is there, or one does not load, startup fails.
- It is an RSA-2048 certificate for `CN=localhost`, with the names `localhost`,
  `127.0.0.1` and `::1`, valid for 10 years. Nothing in it names the relay or
  kamune.
- Removing both files makes the relay create a new certificate at the next
  start.

**Pinning.** At startup the relay logs each listener's certificate fingerprint,
a SHA-256 over the certificate in 64 lowercase hex digits:

```
INFO tls certificate listener=tls sha256=<fingerprint>
```

A self-signed certificate cannot pass normal certificate checks, so clients
authenticate the relay by pinning that fingerprint. The Go client builds such a
TLS configuration with `relayconn.PinnedTLSConfig`, from a fingerprint that
`relayconn.ParseCertFingerprint` reads in this form or in the colon-separated
form `openssl x509 -noout -fingerprint -sha256` prints. A pin covers the whole
certificate, so when the certificate changes every client must pin the new
fingerprint. A client that turns certificate checks off instead hands an active
attacker the PSK and the session token (see [Threat Model](#threat-model)).

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
hand its token to a peer that reaches the relay only over WSS, for example
through a CDN, and the relay will bridge them transparently. Each side only
needs to know the relay address for its own transport and the shared token.

**Design decision: WebSocket, TCP, and TLS only.** The chosen set covers the
three main deployment scenarios:

- **WebSocket** for CDN-fronted and permissive networks.
- **TLS** for stealth on hostile networks.
- **Raw TCP** for trusted internal deployments.

Other transports (QUIC, HTTP/2, gRPC) were considered. QUIC would give better
NAT-traversal and multiplexing but is visible as QUIC to DPI; gRPC has the same
problem. Plain TCP is the lowest common denominator for trusted networks.

### Handshake Timeout

A configurable `handshake_timeout` (30 s when unset or `0`; it cannot be turned
off) bounds the time between connection accept and successful registration.
Slow clients that hold a connection open without registering are dropped,
freeing the slot the relay had reserved for them.

**Design decision: separate from token_ttl.** Token TTL applies _after_
successful registration (offer window for the dialer). The handshake timeout
applies _before_ registration (how long the relay is willing to wait for the
client to finish HPKE + auth). A client that opens a connection and stalls is a
different problem from a client that registers successfully but never gets a
peer to join.

### Go Client

The Go client in `pkg/relayconn` (`ListenRelay*` and `DialRelay*`, one pair per
transport) adds these limits on its side:

- **Handshake bound.** Connecting, TLS, the HPKE exchange, PSK auth and the
  relay's `Registered` reply share one deadline: `WithHandshakeTimeout`, 30
  seconds by default (`DefaultHandshakeTimeout`), or the context's deadline if
  that comes first. The context bounds only the handshake; cancelling it later
  does not close the connection.
- **Token check.** The token in `Registered` must equal the token the client
  sent (`ErrRelayTokenMismatch`), or, when the relay generated it, be 16 or 32
  bytes long (`ErrInvalidRelayToken`).
- **One connection per listener.** The relay pairs a listener with one dialer,
  so a `RelayListener` yields one connection, when the peer's first frame
  arrives. Closing that connection ends the relay session, and `Accept` then
  returns `net.ErrClosed`; listen again for a new session. `Stop` releases the
  session at once when no connection is active.
- **Frame sizes.** The client reads WebSocket messages of up to 131,072 bytes.
  `RelayConn.MaxFrameSize` reports the largest payload a write may carry,
  65,511 bytes (a 65,535-byte relay frame less its wrapping); a larger write
  fails with `exchange.ErrFrameTooLarge` and the session stays usable.
- **Receive buffer.** A `RelayConn` holds at most 1,024 frames or 4 MiB that
  have not been read yet. While it is full the client stops reading from the
  relay, so a fast sender is held back through the relay instead of growing
  the client's memory.
- **Close and deadlines.** `RelayConn.Close` may be called more than once, and
  `WriteBytes` returns `net.ErrClosed` after it. A new deadline set with
  `SetDeadline` also applies to a read that is already waiting.

## Static Tokens

By default the listener receives a random 16-byte token from the relay and
shares it with the dialer out of band (QR code, link, text message). The
static-tokens mode lets both peers compute the same 32-byte token independently
from each other's long-term public keys, so the listener never has to publish a
fresh token to the dialer when reconnecting after an IP change.

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
token = SHA256(min(A, B) || max(A, B))
```

where `min` and `max` are the lex-smallest and lex-largest of the two peers'
public keys (as raw 32 bytes). This is order-independent: neither peer needs
to know which one is "A" — both compute the same 32-byte token. Both peers
must use ed25519 public keys of the standard 32-byte size to compute the same
token.

### Wire Protocol

The `Register` message gains a `Mode` field to make "create" vs "join" explicit:

```protobuf
message Register {
  bytes token = 1;  // MODE_CREATE: empty or 32 bytes; MODE_JOIN: the
                    // session's token (16 bytes if relay-generated, else 32)
  Mode  mode  = 2;  // required: MODE_CREATE or MODE_JOIN

  enum Mode {
    MODE_UNSPECIFIED = 0;  // reserved, will be rejected
    MODE_CREATE      = 1;  // create new session
    MODE_JOIN        = 2;  // join existing session
  }
}
```

The pre-static-token protocol distinguished "create" vs "join" by the token
field alone (empty vs non-empty).

Server behavior by `mode`:

| `mode`             | `token`   | Action                                                                        |
| ------------------ | --------- | ----------------------------------------------------------------------------- |
| `MODE_UNSPECIFIED` | any       | Reject. Close connection (logged at debug).                                   |
| `MODE_CREATE`      | empty     | Generate random 16-byte token. Register session. (Default listener behavior.) |
| `MODE_CREATE`      | non-empty | Check the token, then register the session under it. Reject a duplicate.      |
| `MODE_JOIN`        | empty     | Reject. Close connection (logged at debug).                                   |
| `MODE_JOIN`        | non-empty | Look up session. Pair dialer with listener if found.                          |

The relay's behavior is the same regardless of whether the token is precomputed
or randomly generated — both are opaque strings from the relay's perspective.
The choice is the peers', not the operator's.

**Design decision: static mode is not a config flag.** The relay operator does
not have a say in how peers connect to each other. Static tokens are always
available; listeners that want to use them just pass the precomputed token.
There is no operator opt-in.

### Client Behaviour

Listeners that want to use static tokens pass the precomputed 32-byte token when
opening the connection. The dialer passes the same token (which it computed
independently). Both peers need the same ed25519 public keys (typically
exchanged out of band at first contact).

The wire protocol and behaviour described in this section are independent of any
client library. Clients in any language that implement the `Register{Mode, Token}`
flow described above will work with any conformant relay. The kamune Go library
is one such implementation; the function names and option types in that library
are an implementation detail of the Go ecosystem.

### Properties

- **Both peers compute the same token independently.** Given the two contacts'
  long-term public keys, each peer derives the same 32-byte session token via
  `SHA256(min(A, B) || max(A, B))`. Neither peer needs the other to send them a
  token.
- **Coexists with the existing random-token system.** Listeners can ask the
  relay to generate a random token (the default); static tokens are opt-in per
  registration.
- **Same TTL semantics.** Static tokens use the existing `token_ttl` config.
  An unpaired session ends when it passes, so a listener that wants to stay
  reachable registers again.
- **Forward secrecy is unaffected.** The static token is a routing identifier
  for the relay only; end-to-end authentication and encryption are established
  directly between the two peers after rendezvous, using the kamune protocol
  layer.
- **Token validation.** The relay checks a token the listener chooses before it
  registers the session: exactly 32 bytes, not all zeros, not all the same
  byte, and a byte-frequency Shannon entropy above 3 bits per byte. This is a
  sanity filter against broken tokens, not a measure of how hard a token is to
  guess: a counter such as `0x00, 0x01, ..., 0x1f` passes, and so does the
  SHA-256 of any guessable input, static tokens included. A token is only as
  secret as its inputs; derive it from a secret with a KDF or take it from a
  cryptographic random source.

### Security Considerations

Static tokens trade privacy for convenience. The token is a SHA-256 of the two
public keys, with no secret input and no key agreement, so it is **not a
secret**: it is a routing identifier that anyone who knows both public keys can
compute. Public keys are not secret either: peers hand them out to be verified,
and an active relay reads them from the kamune introductions (see
[Threat Model](#threat-model)).

- **Session probing.** Anyone who knows both peers' public keys can compute the
  same token and send `Register{MODE_JOIN, token: T}` to the relay. If the relay
  answers with `Registered`, a session exists; if it closes the connection, no
  session is waiting for a dialer. This leaks whether two specific peers are
  communicating via this relay.
- **Taking or blocking the session.** A probe is not passive. A successful
  `MODE_JOIN` pairs the prober with the waiting listener, so the real dialer is
  refused; when the prober disconnects, the relay ends the session and closes
  the listener. Registering `MODE_CREATE` with the token first makes the real
  listener's registration fail, and pairs the real dialer with the squatter.
  The kamune handshake still stops the squatter from posing as a peer whose
  identity key is checked, but the pair cannot meet on that relay while it
  keeps this up.
- **Broker matching.** The broker carries the same token cut to 16 bytes (see
  the broker's [Static Tokens](#static-tokens-1)). Anyone who computes it can
  register with it and is sent the waiting peer's public IP address and port.
- **Relay correlation.** Because the token is stable across reconnections (by
  design), a relay operator can observe that the same token appears over time,
  even as source IPs change. Random tokens are single-use and unlinkable — each
  new session gets a fresh token that cannot be correlated to a previous one.
- **Key exposure scope.** Whoever obtains both peers' public keys (from a
  compromised device, a leaked key bundle, a public key directory, or the
  introductions an active relay reads) can probe, take or block every session
  the pair opens with static tokens, on any relay and broker, for as long as
  the pair keeps those keys.

**When to use static tokens:** in trusted deployments where both peers' public
keys are already known to each other and session existence is not sensitive. For
example, friends, family, or business partners who communicate regularly and are
not concerned about a relay operator learning that they talk to each other.

**When to prefer random tokens:** when the fact that two specific peers are
communicating is itself sensitive, or when the relay is untrusted and the
operator may be adversarial. Random tokens provide no correlation surface across
sessions.

### Reconnection on IP Change

When a peer's public IP changes (DHCP renewal, NAT rebinding), the existing
relay session is gone. Both peers re-derive the same token from the same public
keys and re-register — the listener sends `Register{Mode: MODE_CREATE, Token: T}`
again, the dialer sends `Register{Mode: MODE_JOIN, Token: T}`. Neither peer
needs to communicate the token out of band again.

This works for any IP change: NAT rebinding (same IP, new port), network switch
(new IP), or even a completely different device, as long as both peers have
access to the same long-term public keys.

## ECDH-Derived Relay Tokens

Static tokens are a SHA-256 of the two public keys, so anyone who knows both
keys can compute them and then probe, take or block the pair's relay session
(see [Security Considerations](#security-considerations)). ECDH-derived tokens
solve this by deriving tokens from an ephemeral key exchange performed _after_
the kamune handshake completes. The tokens are not computable from public keys
alone, and the ephemeral keys travel inside the established kamune session, so
a relay that splits the kamune Exchange still cannot read them, provided each
peer checks the other's identity key.

### Derivation

After the kamune handshake completes and the encrypted transport is available,
both peers independently derive a pool of 3 reconnect tokens:

1. Each peer generates an ephemeral X25519 key pair.
2. Each peer sends its ephemeral public key to the other over the existing
   encrypted transport, as a `SessionData` message on `RouteSessionData` whose
   `ecdh_pubkey` field holds the key.
3. Both peers compute the X25519 shared secret.
4. Both peers derive 3 tokens via HKDF-SHA512:

```
shared_secret = X25519(local_ephemeral_private, peer_ephemeral_public)
token_i = HKDF-Expand(shared_secret, "kamune/relay-reconnect/v1/" || uint32_be(i), 32)
```

Where `i` ranges from 0 to 2. Each token is 32 bytes. Both peers derive
identical tokens because ECDH is commutative — `A.B == B.A`.

In Go, `relayconn.BeginRelayTokenExchange` sends the key, and
`relayconn.CompleteRelayTokenPayload` derives the pool from the peer's
`SessionData` payload, which the caller's receive loop hands to it.
`DeriveRelayTokens` is deprecated: it takes the next frame itself, so a frame
the peer sends first, such as a chat message, is lost.

### Token Pool

The 3 tokens form an ordered pool. On reconnection after session TTL expiry, the
protocol is asymmetric:

- **Listener** (server side): picks the first unconsumed token from the pool and
  registers with the relay using `MODE_CREATE(token_i)`.
- **Dialer** (client side): searches the pool sequentially with
  `MODE_JOIN(token_0)`, `MODE_JOIN(token_1)`, `MODE_JOIN(token_2)` until it
  finds the matching session.

```
Listener: MODE_CREATE(tokens[1]) → session created     (tokens[0] consumed earlier)
Dialer:   MODE_JOIN(tokens[0])   → connection closed (no such session)
          MODE_JOIN(tokens[1])   → matched → connected
```

The relay answers a missed `MODE_JOIN` by closing the connection, so each try
costs the dialer a new connection and an HPKE exchange and counts against its
rate limit (see [Rate Limiting](#rate-limiting)); the search takes at most 3
tries. This eliminates the coordination problem: the listener picks one token,
the dialer searches all of them. No shared counter or index agreement is needed.

**Why 3 tokens (not 1 or 10):** A single token offers no retry margin — if the
first reconnection attempt fails (network error, timing race), the session must
cold-start. A pool of 10 wastes entropy and storage. Three tokens give the peers
3 attempts to reconnect before pool exhaustion, with the relay's per-address
rate limiter (20 connections a minute by default) limiting how fast an attacker
could probe tokens during the rare cold-start recovery path.

### Lifecycle

- **Single-use.** Each token may be consumed exactly once for relay
  registration. Any-order, mark-on-use.
- **Forward secrecy.** On successful resumption (new handshake, new encrypted
  transport), both peers perform a fresh ECDH exchange. Tokens from session _k_
  are worthless after session _k+1_'s handshake.
- **Pool exhaustion.** When all 3 tokens are consumed, no fallback is used. The
  session enters a cold start — the user must re-initiate the connection. After
  a new handshake, a fresh ECDH exchange derives 3 new tokens.
- **Expiration.** Relay tokens are valid for 7 days, longer than the 24-hour
  resumption window because relay reconnection is less time-sensitive.

### Security

- **Not computable from public keys.** Unlike static tokens, ECDH-derived tokens
  require the ephemeral private keys from both peers. An adversary who knows
  both long-term public keys cannot derive the token.
- **Forward-secret.** Compromise of a later session's keys does not expose
  tokens from earlier sessions.
- **Limited blast radius.** The pool is only 3 tokens; after exhaustion, a fresh
  ECDH exchange with new ephemeral keys is required. This limits the number of
  sessions an attacker could establish with a compromised token.

## Relay Listener Reconnection

### Problem

When `purgeExpired()` closes both channels (session TTL expiry), or when the
relay server restarts, the server-side relay listener is permanently lost. The
`multiListener` goroutine for that listener exits, but no new listener is
registered. The server continues running with fewer listeners.

The dialer side already handles disconnects via `reconnectSession()`, which
retries with exponential backoff using a pre-captured closure.

### Solution

A goroutine (`relayReconnectLoop`) monitors the relay listener for death and
re-registers it automatically using ECDH-derived tokens:

1. Monitor the relay listener for death (the `tokenTracker` reports the listener
   is dead via a `Dead()` channel).
2. Wait a short backoff (1–5 seconds, jittered).
3. Pop the next unconsumed token from the stored token pool.
4. Re-create a `RelayListener` with that token.
5. Add the new listener to the `multiListener`.
6. Loop back to step 1.

### Termination

The loop exits when:

- The server's context is cancelled (`StopServer` / `shutdown`).
- The token pool is exhausted (all 3 tokens consumed without a successful
  reconnection + new handshake). Pool exhaustion triggers a cold start — the
  user must re-initiate.

## Broker: STUN-Echo and Signal Introduction

The relay's transports are useful for any peer that can connect outbound, but
peers behind restrictive NATs benefit from a direct UDP path between them when
possible. The broker is a separate UDP service that combines two functions
needed for P2P hole-punching:

1. **STUN-like IP echo** — a peer sends a packet; the broker responds with the
   peer's perceived public IP:port.
2. **Signal introduction** — two peers register with a shared token; when both
   are present, the broker notifies each with the other's public IP:port, as
   the broker saw it, so they can hole-punch directly.

The broker is optional. If the operator enables it, peers can use the
kamune broker client (or implement the on-the-wire protocol directly) to
discover each other and try a direct connection. The relay continues to
function as a fallback when hole-punching fails.

**Design decision: UDP, not TCP.** TCP-based signaling (HTTP, WebSocket) is
fingerprintable and easy to block. UDP is the right primitive for STUN-echo
and for one-shot introducer packets. The broker uses a single UDP listener
on a configurable IPv4 address. It is off unless `[broker] enabled = true`;
the shipped config leaves it off and gives it `0.0.0.0:4788`, since the broker
only works on an address that peers can reach directly.

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

6 bytes. The broker responds with ASCII `ip:port\0` to the sender's UDP address
— the IP/port are derived from the packet's source address, not from any field
in the packet itself. Example: `192.0.2.1:54321\x00`.

#### `REGISTER` (peer → broker)

```
MAGIC (4) | VER=0x01 (1) | OPCODE=0x02 (1) | TOKEN (16) | PEER_EPH_PUB (32) | IP (4) | PORT (2)
```

60 bytes. Fields:

- `TOKEN` — 16 bytes, may be all zero (random mode) or precomputed (static mode,
  see [Static Tokens](#static-tokens-1)). A longer token travels as its first
  16 bytes, so a 32-byte static token is cut to 16.
- `PEER_EPH_PUB` — the peer's stable X25519 public key (raw 32 bytes). The
  broker uses this both for encryption (per-NOTIFY ECDH) and to identify the
  same peer across re-registrations.
- `IP`, `PORT`: a non-zero IPv4 address and a non-zero port, or the broker
  drops the packet. They are not used otherwise.

The broker records the REGISTER's source address, not `IP` and `PORT`. It sends
its NOTIFYs to that address and gives it to the matched peer as the address to
punch to. A peer must therefore send REGISTER from the UDP socket it will
hole-punch from, and read NOTIFYs on it; in the Go client that is
`Client.RegisterOn` and `Client.ReadNotify` on a socket the caller owns (the
older `Client.Register` uses a socket it closes on return and is deprecated).
A `STUN_ECHO` from the same socket (`Client.EchoOn`) reports the address the
broker will record. In static mode `RegisterOn` returns right after it sends
the REGISTER, and the `PEER_MATCHED` is read with `ReadNotify`. The calls that
read the socket (`EchoOn`, `RegisterOn` in random mode, and `ReadNotify`) drop
packets from any address other than the broker's, read into a 64 KiB buffer,
and skip a read that fails. They fail when the context ends, when the
socket is closed, or after 16 failed reads in a row; with no context deadline,
`EchoOn` and `RegisterOn` also fail after 2 seconds (`DefaultEchoTimeout` and
`DefaultRegisterTimeout`).

#### `NOTIFY` (broker → peer, encrypted)

```
MAGIC (4) | VER=0x01 (1) | OPCODE=0x03 (1) | BROKER_EPH_PUB (32) | NONCE (24) | SEALED (N)
```

- `BROKER_EPH_PUB` — the broker's fresh ephemeral X25519 public key, generated
  per-NOTIFY for forward secrecy.
- `NONCE` — 24 bytes, random, for XChaCha20-Poly1305.
- `SEALED` — `Seal(plaintext)` output: ciphertext followed by 16-byte tag.
  Sizes:
  - `PEER_MATCHED`: 6 + 32 + 24 + 55 + 16 = **133 bytes**
  - `TOKEN_ASSIGNED`: 6 + 32 + 24 + 21 + 16 = **99 bytes**

Encrypted payload layout (depends on `TYPE`):

- `TYPE = 0x01` (`PEER_MATCHED`): `TYPE (1) | TOKEN (16) | OTHER_PEER_EPH_PUB (32) | IP (4) | PORT (2)` — 55 bytes plaintext.
  `IP` and `PORT` are the source address of the other peer's REGISTER, and
  `TOKEN` is the token as the REGISTERs carried it (16 bytes).
- `TYPE = 0x02` (`TOKEN_ASSIGNED`): `TYPE (1) | TOKEN (16) | TTL_SECONDS (4)` — 21 bytes plaintext.

The peer derives the AEAD key and decrypts:

```
shared_secret = X25519(peer_ephemeral_private, broker_ephemeral_public)
aead_key     = SHA256(shared_secret)[:32]
AAD          = MAGIC || VER || OPCODE || BROKER_EPH_PUB
```

and decrypts `SEALED` with XChaCha20-Poly1305 (24-byte nonce, 16-byte tag). The
AAD binds the ciphertext to the broker's ephemeral key so a captured NOTIFY
cannot be re-targeted to a different broker key.

NOTIFY is sent by the broker only; peers that send NOTIFY are ignored.

### Static Tokens

The same static-token mechanism that the relay's transports support (see
[Static Tokens](#static-tokens) above) applies to the broker:

- Both peers compute `token = SHA256(min(A, B) || max(A, B))[:16]` from each
  other's long-term public keys.
- Peer A registers as listener with the static token; peer B joins with the same
  token. The broker matches them.
- When peer A's IP changes (NAT rebinding, DHCP renewal), both peers re-derive
  the same token from the same public keys — no OOB exchange needed.
- `NOTIFY` carries the 16-byte form, so a client compares the token in a
  `PEER_MATCHED` with the first 16 bytes of its own token, not with the whole
  32-byte token. The Go client provides `broker.WireToken` and
  `broker.TokenMatches` for this.

**Design decision: peer identity = `PEER_EPH_PUB`, not source address.** The
broker identifies the same peer by the X25519 public key it sends in REGISTER,
not by the source UDP address, and treats two distinct processes from the same
IP as different peers (their keys differ). The peer must use a stable key across
re-registrations; the client library holds one key for its lifetime.

The key travels in clear, so repeating it proves nothing about the sender. Every
REGISTER with the held token and key, from any address, pushes the entry's
expiry a full `registration_ttl` ahead, but it moves the entry to its source
address only in two cases:

- **Same IP, another port** (a client restart, a dial retry from a new socket,
  most NAT port changes): the entry moves at once.
- **Another IP**: the entry moves only once the held address has gone 35
  seconds without sending a REGISTER for it (a 30-second client refresh
  interval plus slack), whatever `registration_ttl` is.

While the owner refreshes on schedule, a replayed REGISTER from another IP
therefore cannot move its entry. The cost falls on a peer whose IP really
changes: its first refresh from the new IP only keeps the entry alive, and its
second, about two refresh intervals after the change, moves it. A peer that
matches in between is sent the old address. That match consumes the entry: the
matched peer's hole punch fails, and the owner, whose NOTIFY went to the old
address, holds a new entry only from its next REGISTER.

**Design decision: hybrid token model.** Static tokens (above) and
broker-assigned random tokens share the same wire format. A peer registering
with an empty `TOKEN` field gets a 16-byte random token via
`NOTIFY(TOKEN_ASSIGNED)` and shares it with the dialer out of band. Both modes
go through the same registry and the same match logic.

### Server Behavior

For every received UDP datagram, the broker:

1. Rejects packets shorter than 6 bytes.
2. Verifies the 4-byte magic and 1-byte version.
3. Dispatches by opcode.

**`STUN_ECHO`** (opcode 0x01): responds with `ip:port\0` from the packet's
source address. No encryption and no registry interaction; only the echo rate
limiter keeps state (see
[Rate Limits and Registry Size](#rate-limits-and-registry-size)).

**`REGISTER`** (opcode 0x02): validates the packet and branches on the token.
"Peer" in the table is the REGISTER's `PEER_EPH_PUB` together with its source
address:

| `TOKEN`   | Registry state                                               | Action                                                                                                           |
| --------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| empty     | n/a                                                          | Generate a random 16-byte token. Store `T → peer` (TTL). Send `NOTIFY(TOKEN_ASSIGNED)` to peer.                  |
| non-empty | empty, or held entry expired                                 | Store `TOKEN → peer` (TTL). No NOTIFY: the peer already knows the token.                                         |
| non-empty | held by a different peer (different `PEER_EPH_PUB`)          | Match. Send `NOTIFY(PEER_MATCHED)` to BOTH peers, each with its own fresh broker ephemeral key. Clear the entry. |
| non-empty | held by the same peer (same `PEER_EPH_PUB`, re-registration) | Refresh TTL. Move the entry to the source address under the rules above. No NOTIFY.                              |

The broker generates a **fresh** X25519 key pair for **every** NOTIFY it sends.
A match produces two NOTIFYs, each with its own broker ephemeral public key in
the header. Forward secrecy is per-NOTIFY, not per-REGISTER. After the NOTIFY is
sent, the broker's ephemeral private key is discarded.

**`NOTIFY`** (opcode 0x03): ignored. Peers should not send NOTIFY.

**Unknown opcode**: ignored. Random UDP that happens to start with `"KBRK"` and
some random opcode is silently dropped.

### Rate Limits and Registry Size

The broker has two rate limiters of its own, built from the `[rate_limit]`
settings: one for `STUN_ECHO` and one for `REGISTER`, each keyed by the source
IPv4 address and tracking up to `max_entries` addresses. A REGISTER is charged
only once it has parsed and passed the field checks. A packet over its limit is
dropped without a reply. `rate_limit.disabled = true` turns both off.

The two are separate from the TCP, TLS and WebSocket limiter, and from each
other, because UDP source addresses are not verified: a spoofed packet spends
the budget of the address it names, and a spray of forged sources evicts real
addresses from a limiter. Spoofed packets can still spend or evict an address's
broker budget, but not its budget on the relay's other listeners, and spoofed
echoes cannot evict REGISTER histories. Each forged source also gets a fresh
budget, so the limiters do not stop a spoofing sender from making the broker
work: every NOTIFY costs an X25519 key generation and exchange.

The registry holds at most 100,000 entries; a REGISTER that would add one to a
full registry is dropped. Expired entries are removed every 500 ms, so a
registry full of expired entries frees up within that time, and a REGISTER
never scans the registry. Spoofed REGISTERs, in random mode or with made-up
tokens, can still fill it. Stopping that needs a return-routability check, a
wire format change.

The broker reads into a 64 KiB buffer, which holds the largest IPv4 UDP
payload. A failed read is logged at debug level and skipped; after 16 failed
reads in a row the broker logs a warning and waits 100 ms before each further
read until one succeeds or times out. A broker error after startup is logged at
error level and does not stop the relay's other listeners.

### Anti-Fingerprint

| Packet type                                    | Recognizable?               | Notes                                                                |
| ---------------------------------------------- | --------------------------- | -------------------------------------------------------------------- |
| `STUN_ECHO`                                    | Yes (peer opts in)          | Response is plaintext `ip:port\0` from source address                |
| `REGISTER`                                     | Yes (peer opts in)          | Plaintext; token, X25519 public key and IP/PORT fields in clear      |
| `NOTIFY`                                       | Encrypted                   | Server-only; AEAD-sealed payload; header has fixed fingerprint       |
| Random UDP                                     | No response                 | Ignored                                                              |
| Random UDP that happens to start with `"KBRK"` | Falls into "unknown opcode" | Ignored                                                              |

A passive observer sees the 4-byte magic, the 1-byte version, the 1-byte opcode,
and (for NOTIFY) the broker's ephemeral public key and the nonce. They cannot
read the payload or tag without the peer's ephemeral private key. Packet sizes
and timing metadata are visible, as on any UDP service.

This is better stealth than a design that echoes every packet: random UDP
scanners see no response and cannot tell if the broker is up. A more elaborate
stealth design (variable packet sizes, padding, timing obfuscation) is out of
scope for v1.

### Threat Model

The broker is **lower-trust** than the relay's transports:

- The broker **sees** each peer's public IP:port (the source address of its
  REGISTER) and X25519 public key, and passes them to the matched peer inside
  the NOTIFY.
- The broker **does not see** message content (the broker hands off and is out
  of the picture; subsequent traffic is end-to-end between peers).
- A malicious broker can disrupt rendezvous (drop REGISTERs, refuse matches) but
  cannot read application traffic.
- The broker does not pin a long-term identity; every broker ephemeral key is
  fresh per NOTIFY. A compromised broker cannot decrypt past NOTIFYs (forward
  secrecy per NOTIFY).

**Design decision: no long-term broker identity.** This removes the operational
burden of key distribution and gives forward secrecy automatically. Peers do not
need to pin anything. The cost is that a peer cannot tell a NOTIFY from the
broker from one that someone else sealed (see
[Replay Considerations](#replay-considerations)).

### Replay Considerations

The v1 broker does not implement anti-replay, and nothing in a REGISTER or a
NOTIFY proves who sent it. REGISTER is plaintext. NOTIFY is sealed to the
peer's X25519 public key under a broker key made for that NOTIFY alone, so the
AEAD hides the payload but does not show that the broker sealed it. The threat
model:

- **Replayed `REGISTER`**: anyone who has seen a peer's REGISTER has its token
  and public key and can send the same packet from elsewhere. The rebind rules
  above stop a replay from another IP from moving the entry while its owner
  refreshes on schedule. A replay can still:
  - come from the owner's IP with another source port, by sharing the owner's
    NAT or forging its source address, and move the entry to that port until
    the owner's next refresh moves it back;
  - keep the entry alive after its owner has stopped refreshing, or take it
    once the owner misses a refresh;
  - match the other peer of a static token while that peer holds the entry,
    which is then sent the replayer's address as the key owner's;
  - evict the entry by matching it with a key of its own, which sends the owner
    a spurious NOTIFY, and then hold the token from its own address for as long
    as it refreshes within 35 seconds. The owner's refreshes from another IP
    only keep the squat alive.

  Closing these needs proof of possession of the private key in REGISTER, a
  wire format change.
- **Forged or replayed `NOTIFY`**: a peer derives the AEAD key from the
  `BROKER_EPH_PUB` in the packet itself, so anyone who knows the peer's X25519
  public key (from any of its REGISTERs, or from a match) can seal a NOTIFY the
  peer accepts, with any address in it, and a captured NOTIFY decrypts again
  when replayed. A peer should accept NOTIFYs only from the broker's address, as
  the Go client's `ReadNotify` does, but an on-path attacker, or one that can
  forge the broker's source address, passes that check. The AEAD gives
  confidentiality, not origin authentication. The kamune handshake that follows
  the hole punch still authenticates the peer.
- **Replayed `STUN_ECHO`**: a known STUN protocol property; v1's response does
  not include a request nonce. Peers should cross-check STUN_ECHO responses
  against a parallel connection attempt, or use a different STUN source. The
  broker is not the only STUN source a peer should trust.

Authenticating NOTIFY would need a long-term broker key that clients pin, and
binding REGISTER to its sender a proof of possession; both change the wire
format, and v1 has neither.

## Configuration Reference

The relay reads its configuration from the TOML file given with `-c`, or,
without `-c`, from the TOML text in the `KAMUNE_RELAY_CONFIG` environment
variable. A key the relay does not know, or one in the wrong table, stops it at
startup with `unknown config key`, so a misspelt `password` cannot start the
relay in open mode.

The sample lists every key. Its values are those of the shipped
`cmd/relay/assets/config.toml`; the commented keys are not set there.

```toml
[server]
password = ""                 # PSK password, empty = open mode
trusted_proxies = []          # CIDRs whose forwarded client address is read
# client_ip_header = "X-Forwarded-For"  # The one header read from them
# data_dir = "/var/lib/kamune-relay"    # Keeps the self-signed certificate
# log_level = "info"          # debug, info, warn or error

[session]
token_ttl = "10m"             # Offer window of an unpaired session (required)
session_ttl = "60m"           # Max lifetime of paired sessions (0 = no limit)
handshake_timeout = "30s"     # Max time for HPKE + registration (0 = 30s)
max_concurrent_sessions = 10_000  # Maximum sessions (required, > 0)
max_message_size = 65536      # Largest relay frame read, 65536 to 131072

[rate_limit]
# disabled = false            # true turns every rate limiter off
time_window = "1m"            # Sliding window duration
quota = 20                    # Connections or requests per window per address
max_entries = 100_000         # Addresses tracked per limiter (0 = no cap)

[diagnose]
enabled = false               # Plain HTTP server for GET /health
address = "127.0.0.1:9090"

[ws]
enabled = false               # Plain WebSocket listener (/ws)
address = "127.0.0.1:8888"

[tcp]
enabled = true                # Raw TCP listener
address = "127.0.0.1:8889"

[tls]
enabled = true                # TLS listener
address = "0.0.0.0:8890"
# cert_file = "assets/cert/server.crt"   # both empty = self-signed
# key_file  = "assets/cert/server.key"   # certificate in data_dir

[wss]
enabled = true                # WebSocket over TLS listener (/ws)
address = "0.0.0.0:8891"
# cert_file = "assets/cert/server.crt"   # both empty = self-signed
# key_file  = "assets/cert/server.key"   # certificate in data_dir

[broker]
enabled = false               # UDP signaling (STUN-echo + signal intro)
address = "0.0.0.0:4788"      # IPv4 only in v1
# registration_ttl = "60s"    # Life of a registration after its last REGISTER
```

At least one of `diagnose`, `ws`, `tcp`, `tls`, `wss` or `broker` must be
enabled, and an enabled one needs an `address`.

### Field Semantics

"Default" is the value the relay uses when the key is left out.

| Field                                   | Default                             | Range                                | Behavior on `0` or empty                     |
| --------------------------------------- | ----------------------------------- | ------------------------------------ | -------------------------------------------- |
| `server.password`                       | empty                               | string                               | open mode, no PSK                            |
| `server.trusted_proxies`                | empty                               | CIDRs                                | no forwarded client address is read          |
| `server.client_ip_header`               | `X-Forwarded-For`                   | HTTP header name                     | `X-Forwarded-For`                            |
| `server.data_dir`                       | `kamune-relay` in user's config dir | path                                 | the default                                  |
| `server.log_level`                      | `info`                              | `debug`, `info`, `warn`, `error`     | `info`                                       |
| `session.token_ttl`                     | none                                | `> 0`                                | (rejected; must be set)                      |
| `session.session_ttl`                   | `0`                                 | `>= 0`                               | no limit                                     |
| `session.handshake_timeout`             | `30s`                               | `>= 0`                               | `30s`; the timeout cannot be turned off      |
| `session.max_concurrent_sessions`       | none                                | `> 0`                                | (rejected; must be set)                      |
| `session.max_message_size`              | `65536`                             | `0`, or `65536` to `131072`          | `65536`                                      |
| `rate_limit.disabled`                   | `false`                             | bool                                 | rate limiting on                             |
| `rate_limit.time_window`                | `1m`                                | `> 0`                                | (rejected unless `disabled = true`)          |
| `rate_limit.quota`                      | `20`                                | `> 0`                                | (rejected unless `disabled = true`)          |
| `rate_limit.max_entries`                | `100000`                            | `>= 0`                               | no cap on tracked addresses                  |
| `<listener>.enabled`                    | `false`                             | bool                                 | listener not started                         |
| `<listener>.address`                    | none                                | `host:port`                          | (rejected when `enabled = true`)             |
| `tls` and `wss` `cert_file`, `key_file` | empty                               | both set or both empty               | self-signed certificate kept in `data_dir`   |
| `broker.registration_ttl`               | `60s`                               | duration                             | `60s` (a negative value too)                 |

`max_message_size` bounds WebSocket messages; a TCP or TLS frame cannot exceed
65,535 bytes whatever it is set to (see [Wire Format](#wire-format)).

### Diagnostics Endpoint

The `[diagnose]` listener is a separate plain HTTP server with one route.
`GET /health` returns:

```json
{ "status": "ok", "uptime": "1h2m3s", "sessionCount": 12 }
```

The relay has no other diagnostics route, and none that tells a client its own
address.

**Design decision: a separate, opt-in listener.** `/health` reveals uptime and
current load, which is useful for monitoring but is metadata a public relay
should not expose. It is served only when `[diagnose]` is enabled, on its own
address, so it can stay on loopback or a private network while the relay's
other listeners are public.

## Deployment Patterns

### Direct TLS (single host)

A single host runs the relay bound to a public IP on port 443, with the relay's
self-signed certificate (see [TLS](#tls-tls)). Simple, no infrastructure
dependencies, but the relay's IP is exposed, and clients pin the certificate's
fingerprint. A listener whose section is left out stays off.

```toml
[server]
password = ""

[session]
token_ttl = "10m"
max_concurrent_sessions = 10_000

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
password = ""

[session]
token_ttl = "10m"
max_concurrent_sessions = 10_000

[wss]
enabled = true            # WSS still available as the relay fallback
address = "0.0.0.0:8891"

[broker]
enabled = true
address = "0.0.0.0:4788"  # public, so peers behind NATs can reach it
# registration_ttl = "60s"
```

The broker and the relay's transports run in the same process but on
different ports. The broker has rate limiters of its own, apart from those of
the TCP, TLS and WebSocket listeners (see
[Rate Limits and Registry Size](#rate-limits-and-registry-size)). Peers talk to
the broker first to discover each other's IP:port; if direct UDP fails, they
fall back to the relay over WS/WSS/TCP/TLS as usual.

## Known Limits

The relay is designed to be cheap, simple, and predictable. The following are
known limits, not bugs:

- **Token exhaustion** — an attacker can open many connections and send
  `Register{mode: MODE_CREATE}` to fill the relay's session table until tokens
  expire. Defenses: `max_concurrent_sessions` cap, automatic cleanup of expired
  tokens, and the per-address rate limiter (which runs before HPKE, so attackers
  do not burn asymmetric crypto).
- **Session hoarding** — an attacker controlling both ends of a session can hold
  it open for the full `session_ttl`. `session_ttl` bounds the cost of a hoarded
  session independently of `token_ttl`.
- **Handshake stalls** — slow clients can hold connection slots open. The
  `handshake_timeout` drops them so the slot is freed.
- **No offline messages, no replay protection** — by design, see
  [Backpressure and Message Drops](#backpressure-and-message-drops) and
  [Replay Protection](#replay-protection).
- **Broker registry growth** (when broker is enabled): entries are held in an
  in-memory map of at most 100,000 entries and expire `registration_ttl`
  (default 60s) after their last REGISTER. The broker's limiter caps REGISTERs
  per source address, but UDP sources are not verified, so REGISTERs from many
  forged addresses can fill the map and make the broker seal NOTIFYs, each
  costing X25519 work (see
  [Rate Limits and Registry Size](#rate-limits-and-registry-size)).

## Operator Responsibilities

The relay operator is responsible for:

- Running behind a CDN or tunnel for IP-hiding in hostile networks.
- Behind a reverse proxy, CDN or tunnel, listing the addresses it connects
  from in `server.trusted_proxies` and naming its client address header in
  `server.client_ip_header`; otherwise all clients share the proxy's rate
  limit (see [CDN-Backed Deployments](#cdn-backed-deployments)).
- Setting `[server] password` to enable PSK mode if the relay is exposed.
- Tuning `max_concurrent_sessions`, `token_ttl`, and `session_ttl` to match
  expected load.
- Keeping the `[diagnose]` listener, if enabled, on loopback or a private
  network: `/health` reveals uptime and the current session count.
- Leaving `server.log_level` at `info` or above outside debugging. At `debug`
  the relay logs client addresses and registrations, which pair the two peers
  of a session.
- When `[tls]` or `[wss]` uses the self-signed certificate, giving clients its
  fingerprint to pin, and keeping `server.data_dir` across restarts and
  redeployments so that the pin stays valid.
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

With the relay on a private network or behind a tunnel, the relay operator does
not need a TLS certificate: the CDN provides the one clients see. The relay runs
a `[ws]` listener and clients use the WebSocket-over-TLS client API against the
CDN hostname. The leg from the CDN to the relay is plain WebSocket, which
carries the relay's own HPKE channel but does not authenticate the relay, so
keep it on a private network or a tunnel and let only the CDN reach the
listener. A CDN that reaches the relay over the internet needs a `[wss]`
listener instead (see [CDN Config](#cdn-config)).

**Rate limiting behind a CDN.** Every connection reaches the relay from a CDN
address. With `server.trusted_proxies` empty, all clients share that address's
quota (20 per minute by default), and a few requests from anyone lock everyone
else out. List the CDN's published address ranges in `trusted_proxies` and set
`server.client_ip_header` to the header that carries the client address
(`CF-Connecting-IP` for Cloudflare); the relay then limits each client by its
own address (see [Rate Limiting](#rate-limiting)). The relay warns about a
shared quota only when the proxy connects from a loopback, private or
link-local address, so it says nothing about a CDN that connects over the
internet.

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

The relay listens on localhost, where cloudflared connects from `127.0.0.1`.
List that address in `server.trusted_proxies` (or the address cloudflared
connects from, such as a sidecar's) and set
`client_ip_header = "CF-Connecting-IP"`, or every client shares cloudflared's
quota. While the limiter is on and `trusted_proxies` is empty, the relay warns
about this at startup for a `ws` or `wss` listener on a loopback, private or
link-local address, and once when it refuses a peer on such an address (see
[Rate Limiting](#rate-limiting)).

#### CDN Config

For Cloudflare Tunnel, with cloudflared on the same host:

```toml
[server]
password = ""
trusted_proxies = ["127.0.0.1/32", "::1/128"]  # cloudflared on this host
client_ip_header = "CF-Connecting-IP"

[session]
token_ttl = "10m"
max_concurrent_sessions = 10_000

[ws]
enabled = true
address = "127.0.0.1:8080"   # localhost only, reached through the tunnel
```

For a CDN that reaches the origin over the internet, enable `[wss]` in place of
`[ws]`, with a `cert_file` and `key_file` that hold a certificate the CDN
verifies. Over plain `[ws]`, an attacker on the path between the CDN and the
relay can pose as the relay and receive the PSK and the session tokens. The
`[wss]` listener accepts TLS 1.3 only, so the CDN must connect to the origin
with TLS 1.3. Bind `[wss]` to an address the CDN can reach, let only the CDN's
ranges through the firewall, and list those ranges in `trusted_proxies` in
place of the loopback addresses.

#### Comparison: Direct TLS vs CDN vs Cloudflare Tunnel

|                     | Direct TLS listener | CDN (Cloudflare)                   | Cloudflare Tunnel         |
| ------------------- | ------------------- | ---------------------------------- | ------------------------- |
| Relay IP hidden     | No                  | Yes (CDN IP shown)                 | Yes (no public IP at all) |
| TLS cert            | Self-signed (auto)  | CDN's valid cert                   | CDN's valid cert          |
| DPI evasion         | Good (raw TLS)      | Excellent (blends with CF traffic) | Excellent                 |
| Cost                | Free                | Free                               | Free                      |
| Open ports required | Yes (port 443)      | Yes (port 443 on origin)           | No (outbound only)        |
| Setup complexity    | Clients pin cert    | DNS + proxy toggle                 | Install cloudflared       |

#### Cloudflare Workers

[Cloudflare Workers](https://workers.cloudflare.com/) can act as a WebSocket
proxy between clients and the relay, optionally adding auth, logging, or IP
filtering at the edge. The Worker forwards the WebSocket upgrade transparently;
the relay sees the Worker's IP, not the client's. All clients then share one
rate-limit quota, unless the Worker passes the client address in the header
named by `client_ip_header` and the addresses it connects from are listed in
`trusted_proxies`.
