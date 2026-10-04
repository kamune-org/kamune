# RFC: Rendezvous Tokens Derived from the Peer Pair

**Status:** Draft

**Target:** Kamune Protocol Specification before v1.0 (not scheduled)

**Relates to:** §5.2 (Session Data), §6 (Protocol Flow), §7 (Encryption and
Key Derivation), §9.3 (Relay), §11.3 (Stored Entities), §13 (Constants and
Limits), §14 (Error Conditions); RELAY.md "Threat Model", "Frame Schema",
"Connection Flow", "Token Lifecycle", "Session Lifetime", "Go Client",
"Static Tokens", "ECDH-Derived Relay Tokens", "Relay Listener Reconnection"
and the broker "Static Tokens"; RFC006 (overview), RFC007 (handshake), RFC008
(UDP path), RFC009 (relay leg), RFC011 (broker)

---

## 1. Summary

Replace the public static relay and broker tokens, today the SHA-256 of the
two Ed25519 identity keys, with tokens that only the two peers can compute:
HKDF-SHA512 over the X25519 Diffie-Hellman of the two identity keys, bound to
the authenticated key of the relay or broker the token is used at, and to the
direction of the rendezvous. Reconnect tokens stop using a separate ephemeral
X25519 exchange over `SessionData` and come from RFC007's session exporter.
Every token is 32 bytes on every wire.

A connection that arrives on a pair token, or that a client dials with one,
completes only with the pair's peer key. The library checks this before the
`RemoteVerifier` runs, on both sides. The relay gains a `Refused` record, so a
client can tell a missing session from a token in use, and a dialer that joins
and stays silent can no longer hold or tear down a listener. The Go `Token`
type prints, logs and marshals as a 12-hex-character handle.

This RFC is the token part of the pre-v1.0 rework described in RFC006,
which is not implemented now. It ships as a wire-incompatible hard cut, as
RFC004 does: the token formats, the relay `Register` contract, the broker
token input, the on-disk token store, the daemon JSON API and the exported
Go API all change. No backward compatibility is kept, so
older clients and relays must upgrade, together with RFC007, RFC009 and
RFC011.

Findings closed: RC-04 and RC-07 jointly with RFC011, RC-18, DOC-01; the
token parts of BUS-21 and DMN-11 (partly closed). Section 20 has the detail.

## 2. Current Behavior

The statements below describe the current code.

### 2.1 Static tokens

`relayconn.TokenFromKeys` (`pkg/relayconn/token.go`) returns
`SHA-256(lo ‖ hi)`, where `lo` and `hi` are the two raw Ed25519 public keys
sorted bytewise. It has no secret input and no label. Anyone who knows both
public keys (share cards, or one handshake with each peer) computes it, and
the value is the same for both directions and at every relay and broker. The
bus and the daemon call it through `deriveP2PToken` (`cmd/bus/p2p.go`,
`cmd/daemon/p2p.go`) for static relay listeners and dials and for static
broker registrations.

The broker codec (`pkg/relayconn/broker/codec.go`) carries 16-byte tokens.
`WireToken` cuts the 32-byte static token to its first 16 bytes, and the
clients compare the token in `NOTIFY(PEER_MATCHED)` with
`broker.TokenMatches`.

### 2.2 Random tokens

`SessionManager.Create` (`cmd/relay/internal/services/session.go`) draws 16
bytes from `crypto/rand`. `CreateWith`, for a token the listener supplies,
calls `relayconn.ValidateUserToken`: exactly 32 bytes, not all zero, not one
repeated byte, and a byte-frequency Shannon entropy above 3 bits per byte. On
the client, `checkRegisteredToken` accepts a relay-assigned token of 16 or 32
bytes. A p2p listener started without a token gets one from the broker in
`NOTIFY(TOKEN_ASSIGNED)`; tokens from `generate_p2p_token` are 16 random
bytes drawn by the client.

### 2.3 Reconnect tokens

On every established session that is not incognito, both clients call
`deriveAndStoreRelayTokens` (daemon: `dial`, `serverHandler`,
`makeReconnectFn`; bus: `ConnectToServer`, `serverHandler`). It calls
`relayconn.BeginRelayTokenExchange`, which sends an ephemeral X25519 public
key in a `SessionData` frame under the field `ecdh_pubkey`. The receive loop
hands the peer's frame to `finishRelayToken`, which calls
`relayconn.CompleteRelayTokenPayload`. `RelayTokenPending.Complete` uses the
raw X25519 output as the HKDF-SHA512 PRK and expands three 32-byte tokens with
info `"kamune/relay-reconnect/v1/" ‖ u32be(i)`. The tokens are stored as the
session meta `relay_tokens` (`storage.RelayTokensKey`).

The listener side (`awaitRelayResume` in both clients, with
`registerResumeToken` in the bus) registers the stored tokens one at a time
and removes each from the stored list once the relay has seen it. The dialer
side (daemon `makeReconnectFn`, and the reconnect function built in bus
`ConnectToServer`) tries the stored list with `dialRelayFuncMultiToken`. The
TUI takes no part; its `receiveLoop` drops `SessionData` frames.

### 2.4 Binding a rendezvous to a peer

`RemoteVerifier` receives the storage and the remote peer, nothing else.
`verifyPeer` (`handshake.go`) runs on both sides (`dial.go`, `server.go`) and
has no expected key. Nothing in the library ties a connection that arrived on
a static token to the peer the token was computed for.

The bus adds two application-level checks. On a dial to a selected peer it
wraps the verifier with `pinPeer`, which rejects any other key before the
verifier sees it. On its static relay and broker listeners it records the
peer key (`peerKeySet` in `peergate.go`, `pinRelayListener`,
`p2pListener.admitsPeer`), and `serverHandler` closes a session with another
key through `admittedBy`. That check runs after the handshake, so the
verifier has already run. The daemon has neither check.

### 2.5 Relay registration

`handleRelayConn` (`cmd/relay/internal/handlers/ws_handler.go`, used by the
WebSocket and the TCP listeners) closes the channel without a reply when
`Create`, `CreateWith` or `Join` fails, when `MODE_JOIN` carries no token, and
when the mode is `MODE_UNSPECIFIED`. The three `SessionManager` failures are
logged with `slog.Error`. A client cannot tell a missing session from a token
in use.

`Join` on a session that already has a dialer returns `ErrTokenConsumed`.
`Leave` for either side deletes the session and closes the other side's
channel, so a dialer that joins and leaves tears the listener down, and a
dialer that joins and sends nothing holds the session until `session_ttl`. A
`RelayListener` (`pkg/relayconn/listener.go`) creates its connection only
when the dialer's first frame arrives, so the listener never learns of such a
dialer.

### 2.6 Display and logging

Token entries in both clients are keyed by the token string:
`tokenTracker.token`, `markRelayTokenConsumed`, bus `RemoveRelayToken` and
daemon `handleRemoveRelayToken`. Log lines print the first eight hex
characters (`logToken` in the bus, `shortToken` in the daemon). The full token
goes into events and the UI: the daemon `relay_token` and `relay_tokens`
events, the bus `relay-token` event, and the return value of bus
`StartServer`, which in static mode is the static token.

DAEMON.md says that with `peer_pub_b64` set, `generate_relay_token` and
`generate_p2p_token` derive the token "via ECDH" so that only that peer can
connect.

## 3. Problems

- **Squatting and address disclosure (RC-04).** Anyone who knows both public
  keys can register a pair's static relay token first, after which the real
  listener's `CreateWith` returns `ErrTokenInUse`. The same party can join
  the token and hold the session, or leave and close the listener, or
  register the token at the broker, which matches the listener and returns
  its IP and port.
- **No direction.** "A listens for B" and "B listens for A" share one token.
  When both peers listen for each other on one relay, the second `CreateWith`
  fails; when the first then dials, its `MODE_JOIN` reaches its own listener.
  At the broker the two listeners' registrations match each other, so each
  is sent the other's address and neither dials; under RFC011's slot rule
  they would instead evict each other.
- **Truncation on the broker wire (RC-07).** Static tokens lose half their
  bytes on the broker wire, and clients need a special compare.
- **Reconnect derivation (RC-18).** The raw X25519 output is used as an HKDF
  PRK, and the info binds no session or identity. The exchange also costs a
  `SessionData` round that the TUI has to drop.
- **No identity binding (DOC-01).** With the Quick or Auto-Accept verifier, a
  relay operator or a squatter can put another identity behind a static
  rendezvous, while DAEMON.md presents static tokens as exclusive to the
  peer.
- **Tokens in logs and events (BUS-21, DMN-11).** Full tokens and token
  prefixes reach log buffers, exported log files and UI events.
- **Weak check (RC-19).** `ValidateUserToken` measures byte frequency, which
  says nothing about how hard a token is to guess.

## 4. Decisions

### 4.1 Design decisions

1. **Static pair secret: X25519 between the two Ed25519 identity keys**,
   converted to Montgomery form (RFC 7748 section 4.1 birational map; the
   private scalar is the Ed25519 secret scalar `SHA-512(seed)[0:32]`, clamped
   by X25519). No new key, no change to the handshake's identity, and a
   contact card that carries only the Ed25519 key is enough. libsodium ships
   the same conversion (`crypto_sign_ed25519_pk_to_curve25519`,
   `crypto_sign_ed25519_sk_to_curve25519`) and age uses it for `ssh-ed25519`
   recipients; Thormarker (IACR ePrint 2021/509) proves joint security for
   this reuse when the DH output is hashed. The raw DH value never leaves
   `pkg/attest`.
2. **HKDF-SHA512 Extract-then-Expand.** Extract with a protocol salt over the
   DH and both identity keys (the X3DH and Noise practice of hashing public
   keys into the key derivation); Expand with an injective fixed-layout
   `info` that names purpose, service, direction and a reserved counter.
3. **Tokens are bound to the authenticated service key**: the relay static
   key of RFC009, or the broker key the client pins in the broker address
   (RFC011). A token for relay R1 is useless at R2, and a man in the middle
   with its own key gets a token that does not exist at the real service.
4. **Static tokens are directional.** "A listens for B" and "B listens for A"
   are different tokens, so both peers can listen for each other on one relay
   or broker, and no dial reaches its own listener.
5. **A pair rendezvous is bound to the peer's identity.** A connection that
   arrives on a pair token, or that a client dials with one, completes only
   if the authenticated remote key is the pair's peer key. The library
   enforces this before the `RemoteVerifier` runs (section 7.7). Tokens stay
   routing secrets; authentication stays with the kamune handshake (RFC007).
6. **Reconnect tokens come from RFC007's session exporter**
   (`Transport.ExportKeyingMaterial`, modelled on RFC 8446 section 7.5). The
   `SessionData` `ecdh_pubkey` exchange is deleted.
7. **Every token is 32 bytes on every wire.** The relay checks only length
   and non-zero. `ValidateUserToken` and its entropy heuristic are deleted.
   No API turns a human-chosen string into a token: `ParseToken` takes 64 hex
   characters.
8. **Tokens are secrets by default in code.** `rendezvous.Token` prints, logs
   and marshals as a 12-hex-character handle. Only a random (bearer) token
   can be revealed in full, for sharing.

### 4.2 Maintainer decisions

- The rework is not implemented now. This RFC is a Draft that targets the
  specification before v1.0, with no release scheduled.
- No backward compatibility: the change is a wire-incompatible hard cut, as
  in RFC004. There is no version negotiation, no migration of stored
  `relay_tokens`, and no acceptance of 16-byte tokens.
- Listener identity exposure to anyone who can reach a listener, including
  the relay operator, is accepted for now (RFC007, where KAM-10 is listed as
  partly closed); contact-only listeners are left for a future RFC. This RFC
  does not change what a responder reveals in the handshake. What it changes
  depends on where the static listener waits:
  - **Relay static listener.** The relay routes to the listener only by the
    pair token, and only the peer and that relay's operator hold the token
    (the operator learns it from `Register`). Before this RFC anyone who
    knew both public keys could reach it.
  - **Broker static listener.** The token keeps third parties from matching
    the listener at the broker, but it does not guard the listener's
    socket. That socket is a UDP socket with no knock key (section 9.4,
    RFC008), and anyone who learns its UDP address can deliver an RFC007
    ClientHello and learn the listener's identity: the broker operator,
    which sees the address of every registrant without knowing the token
    (RFC011 sends only `RID`), a peer that matched it earlier, or an
    on-path observer. Today both clients pass packets on a broker punch
    socket only from IPs that a `PEER_MATCHED` named (bus
    `punchFilter.expect`, daemon `p2pListener.admitPeer`). Whether the new
    listener keeps such a filter, fed from RFC011's `Match.Peer`, is RFC008
    open question 1; how far matched-address filtering limits this
    exposure depends on that answer.
  - Random tokens and direct listeners stay reachable by whoever holds the
    token or the address.

  A future contact-only-listener RFC would call `attest.PairSecret` with its
  own salt.

### 4.3 Agreements with other RFCs

- RFC007 runs the `PeerConstraint` check of section 7.7 in both roles (the
  initiator before it sends its identity, the responder before its
  verifier), sets `VerifyRequest.Pinned` for a responder whose check ran and
  passed, and adds `ErrSelfConnection` for a remote key equal to the local
  key. The direction byte already prevents reflection on pair tokens;
  `ErrSelfConnection` covers random tokens.
- RFC009 accepts `Refused` as an alternative to `Registered` for the relay's
  record 0 (field 7 of `Frame`), gives `Dial` no positional token, and types
  `WithToken` and `WithTokenFunc` with `pkg/rendezvous` from the start.
- RFC011's `Endpoint.Register` takes a `rendezvous.Token`. The p2p listener
  records the expected peer per match, and this RFC's client commits add the
  `ExpectPeer` wrapping (section 7.7).

### 4.4 Proposed defaults

These are the design's recommendations. They stand unless the maintainer
changes them.

| Item | Proposed default | Reason |
| --- | --- | --- |
| Static token rotation | None in v1: one token per (pair, direction, service); `n = 0` kept in `info` so rotation can return without a layout change | Rotation only kept the service operator from linking one pair's registrations over days, which source IP and timing already allow, and it cost a clock dependency (section 21) |
| Relay `dialerGrace` | 10 s | RFC007's initiator sends its first frame as soon as the relay pairs it, so 10 s leaves room for a slow link (section 13) |
| Reconnect pool size | 3 | Index 0 is the normal case; index 1 covers a stale registration of our own at index 0; index 2 covers a second quick network change |
| Reconnect first-frame watchdog | 10 s | Bounds a dial that a stale index-0 session swallows (section 12.4) |
| Static listener retry | backoff 2, 4, 8, 16, 30, 30, ... s; after a session ends, 1 s plus a uniform draw in [0, 4 s) | Gives the relay time to run `Leave` for the old session; the wait after a session ends is the one the clients use today after an unused resume listener |

## 5. Token Types, Before and After

| Token | Today | After this RFC |
| --- | --- | --- |
| Relay random | relay `crypto/rand`, 16 B, shared out of band | relay `crypto/rand`, 32 B, shared out of band (bearer) |
| Relay static | `SHA256(lo‖hi)`, 32 B, public, undirected | `HKDF(pair, "relay-static", relay_id, dir, 0)`, 32 B, secret to the pair, directional |
| Broker random | broker `TOKEN_ASSIGNED` or client `crypto/rand`, 16 B | client `crypto/rand`, 32 B (RFC011 removes `TOKEN_ASSIGNED`) |
| Broker static | `SHA256(lo‖hi)` cut to 16 B on the wire | `HKDF(pair, "broker-static", broker_id, dir, 0)`, 32 B; RFC011 derives `RID` from it and the token never leaves the client |
| Relay reconnect pool | 3 × `HKDF-Expand(raw X25519 ss, "kamune/relay-reconnect/v1/" ‖ u32be(i))` after a `SessionData` exchange | 3 × `HKDF-Expand(exporter root, info("relay-reconnect", relay_id, 0x00, i))` |

## 6. Threat Model

Goals:

- **G1.** Nobody but the two peers can compute a static token, given both
  public keys, the pair's tokens for other services or for the other
  direction, and the tokens of other pairs. The relay a token is bound to
  learns it when a peer presents it in `Register`; the broker never sees it
  (RFC011 sends `RID`).
- **G2.** Without the pair secret, a pair's tokens for two services, or for
  the two directions, are unlinkable. A token is stable over time at one
  service, so that service links the registrations of one direction of one
  pair over time. It can do that by source IP and timing anyway.
- **G3.** A token leaves the client only after the relay proved possession of
  the relay static key the token is bound to (RFC009's `finished_r`). Broker
  tokens never leave the client.
- **G4.** Reconnect tokens are fresh per established session (cold or
  resumed) and are replaced after the next one.
- **G5.** A session over a pair rendezvous (static or reconnect) completes
  only with the pair's peer key, whatever the verifier mode. Anyone who
  learns the token (the relay operator, a first-contact impostor, a reader of
  relay logs) can at most deny service and, by dialing the listener, learn
  its identity key as RFC007 section 8.3 allows (section 4.2); it cannot put
  another identity behind the token.

Non-goals and residual risks:

- A random token shared out of band stays a bearer token. The verifier is the
  only access control on a random-token listener.
- The relay operator can refuse, drop, reorder, or squat a token it has seen,
  and the broker operator the same for a `RID` (denial of service). Tokens do
  not authenticate peers.
- A static broker listener is a UDP socket with no knock key. The token keeps
  third parties from matching it at the broker, but anyone who learns the
  socket's address (the broker operator, an earlier peer, an on-path
  observer) can reach it without the token and learn its identity, unless
  the matched-address filter of RFC008 open question 1 is kept, which
  narrows who can reach it (section 4.2).
- Static tokens are classical. An adversary with a cryptographically relevant
  quantum computer and both public keys computes `PRK_pair`, then every
  static token and broker `RID` of the pair, past and future. Combined with
  relay or broker logs this reveals the pair's rendezvous history and,
  through the broker, its addresses. Today anyone can do this without a
  quantum computer, so it is no regression. Message confidentiality stays
  hybrid (RFC007), and the relay leg that carries the token is hybrid
  (RFC009). A post-quantum pair secret is deferred (section 21).
- Compromise of A's identity key reveals `PRK_AX` for every contact X. The
  attacker can then dial any X that listens for A on a broker and learn X's
  address. It can impersonate A anyway; the point is that a contact's
  location privacy depends on the other side's key too.

## 7. Cryptographic Construction

`‖` is concatenation and `u64be(n)` is 8-byte big-endian. ASCII strings carry
no terminator unless `0x00` is written. HKDF is HKDF-SHA512; identifiers use
SHA-256.

### 7.1 Ed25519 to X25519

Inside `pkg/attest`, unexported:

```
x_priv(sk) = SHA-512(seed(sk))[0:32]              passed to crypto/ecdh, which clamps
x_pub(pk)  = u = (1 + y) / (1 - y) mod 2^255-19   y from pk with bit 255 cleared,
                                                  32 bytes little-endian
```

`x_pub` runs only on keys that `attest.IsValidPublicKey` accepts (canonical,
on the curve, not of small order). `checkPoint` already excludes y in {1,
p − 1, 0, y8, p − y8}, where y8 is the y-coordinate of the points of order 8
(`smallOrderY` in `pkg/attest/attest.go`), so `1 − y ≠ 0` and `u ≠ 0`.
Inputs to `x_pub` are public, so the `math/big` arithmetic `attest` already
uses is acceptable (`filippo.io/edwards25519` is not in the module graph).
The secret scalar is handled only by `ecdh.X25519().NewPrivateKey`, never by
`math/big`. A torsion component on the peer's point does not matter: the
clamped scalar is a multiple of 8.

### 7.2 Pair secret

```
dh       = X25519(x_priv(self), x_pub(peer))      crypto/ecdh rejects all-zero
lo, hi   = the two raw 32-byte Ed25519 keys, sorted bytewise ascending
PRK_pair = HKDF-Extract(SHA-512, salt = "kamune/pair/v1", IKM = dh ‖ lo ‖ hi)   64 B
```

`self == peer` is rejected (`ErrSamePeer`). With both raw keys in the IKM, a
torsion-shifted or sign-flipped key that maps to the same `u` gives a
different PRK. `PRK_pair` is held only in memory and recomputed on demand (one
X25519, one HMAC). `dh` is a local variable in `attest` and is never
returned.

### 7.3 Expand info layout

```
info(purpose, svc, dir, n) =
    "kamune/rendezvous/v1" ‖ 0x00 ‖ purpose ‖ 0x00 ‖ svc[32] ‖ dir[1] ‖ u64be(n)
```

`purpose` is one of the fixed ASCII strings below (none contains `0x00`),
`svc` is always 32 bytes, `dir` one byte and `n` eight bytes, so the encoding
is injective. The info for a relay static token is 75 bytes.

| purpose | key | svc | dir | n | length |
| --- | --- | --- | --- | --- | --- |
| `relay-static` | `PRK_pair` | relay_id | 0x01 or 0x02 (7.5) | 0 | 32 |
| `broker-static` | `PRK_pair` | broker_id | 0x01 or 0x02 (7.5) | 0 | 32 |
| `relay-reconnect` | `reconnect_root` | relay_id | 0x00 | index 0..2 | 32 |
| `p2p-punch` | `PRK_pair` | 32 zero bytes | 0x00 | 0 | 32 |

`n` is fixed at 0 for static tokens; it is reserved for a later rotation or
re-key counter. `p2p-punch` is RFC008's knock key for direct P2P
(`PairKey.PunchKey()`). A direct path has no service key, so `svc` is 32
zero bytes, and both ends need the same key, so `dir` is `0x00`. It is a MAC
key, never a token, and never leaves the client. `dir = 0x00` means that
something other than the pair fixes the roles (the session, for reconnect).

### 7.4 Service identifier

```
service_id(pub[32]) = SHA-256("kamune/service-id/v1" ‖ 0x00 ‖ pub)
```

- `relay_id`: `pub` is RFC009's `relayleg.PublicKey` (32 raw bytes) as
  authenticated by `finished_r`.
- `broker_id`: `pub` is the broker X25519 public key carried in the broker
  address (`udp://host:port?rk=rk1-...`, RFC011), which is the static key of
  the relay that runs the broker.

When the broker uses the relay's key, `relay_id == broker_id`; the purpose
strings keep relay and broker tokens apart. When a service changes its key,
both peers see the new key and derive new tokens together.

Binding broker tokens to `broker_id` repeats what RFC011's `RID` salt already
does. It costs nothing, since every broker address carries `rk=`; it keeps
the relay and broker rules identical, and it keeps a pair's tokens at two
brokers unlinkable even if a later broker version stops salting `RID` with
its key.

### 7.5 Direction

```
dir(listener) = 0x01 if the listener's raw Ed25519 key is lo
                0x02 if it is hi
ListenToken(purpose, svc) = Expand(PRK_pair, info(purpose, svc, dir(self), 0), 32)
DialToken(purpose, svc)   = Expand(PRK_pair, info(purpose, svc, dir(peer), 0), 32)
```

`ListenToken` of (A, B) equals `DialToken` of (B, A) and differs from
`ListenToken` of (B, A). The listener is the side that sends `MODE_CREATE` to
the relay or registers `RoleListen` at the broker, whatever the kamune server
and dialer roles are (they coincide in all clients).

### 7.6 Reconnect root

```
reconnect_root = t.ExportKeyingMaterial("kamune/relay-reconnect", nil, 32)
token_i        = HKDF-Expand(reconnect_root,
                             info("relay-reconnect", relay_id, 0x00, i), 32)
                 for i in 0, 1, 2
```

The exporter output is a uniform key (RFC007), so Expand alone is the correct
RFC 5869 use; the RC-18 defect (raw X25519 output used as a PRK, no context)
disappears with the code that had it. The root depends on RFC007's full
transcript and hybrid (X-Wing) key schedule. Both peers compute it when the
transport is established, cold or resumed, with no message exchange. `dir` is
`0x00` because the previous session fixes the roles: its responder
re-listens and its initiator re-dials. No code path listens and dials on the
same pool, and `DialWithResume` pins the stored peer key, so a client that
reached itself on a reconnect token would fail G5 anyway; a role byte would
encode a constant.

Pool size 3: index 0 is the normal case; the listener moves to index 1 when
the relay still holds a stale registration of its own at index 0 (the TCP
close not yet seen), and to index 2 after a second quick network change. More
indices only add relay connections on a miss.

### 7.7 Expected peer rule

This rule implements G5. A pair rendezvous connection carries the pair's peer
key. The handshake checks it, on both sides, once the remote identity is
authenticated and before the `RemoteVerifier` runs:

```go
// package kamune

// PeerConstraint is implemented by a Conn that may carry a session only
// with particular peers. The handshake calls AllowPeer with the remote
// PKIX key after the remote has proved possession of it. false aborts
// with ErrPeerKeyMismatch before the RemoteVerifier runs.
type PeerConstraint interface {
	AllowPeer(pkix []byte) bool
}

// ExpectPeer wraps c so that only one of keys is accepted. With no keys
// it returns c unchanged.
func ExpectPeer(c Conn, keys ...[]byte) Conn
```

- **Relay.** `relayconn` conns created with `WithExpectedPeer` or `WithPair`
  implement `AllowPeer` (byte equality on PKIX). Conns without it return
  true.
- **Broker and UDP.** The p2p listener records, per authenticated `Match`,
  the expected key of the registration that matched (none for a random
  token) under `Match.Peer` for 120 s, and wraps each conn from that address
  with `ExpectPeer(conn, keys...)`. If any registration that matched that
  address in the window was random, the conn is not constrained. The dialer
  wraps its conn with `ExpectPeer(conn, peer)`. This RFC's client commits own
  the wrapping code in `p2plistener.go`, `broker.go` and the p2p dial path.
  They land on top of RFC011's client rewrite, and RFC008's later client
  commit keeps the wrappers when it replaces kcp-go with
  `ListenUDP`/`DialUDP`.
- **Direct P2P.** When the peer key is known, the direct P2P conn
  (`directp2p.go`) is wrapped with `ExpectPeer(conn, peer)`.
- **Dialers** also pass RFC007's `DialWithPeerKey(peer)` whenever the peer
  key is known. That option does not exist before RFC007's root switch, so
  RFC007's client commit adds it on these paths; until then the conn's
  `PeerConstraint` gives the check. On the responder side, where RFC007 has
  no pin, `PeerConstraint` is the only check.

### 7.8 Random tokens and handles

```
random token = 32 bytes from crypto/rand, not all zero
               (relay Create; clients for broker random mode)
handle(t)    = hex(SHA-256("kamune/token-handle/v1" ‖ 0x00 ‖ t)[0:6])   12 hex chars
```

The handle is the only token-derived string that may be logged or shown for a
derived token.

### 7.9 Test vectors

Computed with Go 1.26.6 (`crypto/ed25519`, `crypto/ecdh`, `crypto/hkdf`,
`math/big`); `relay-static, A listens` and `p2p-punch` were also reproduced
with Python `hmac` and `hashlib`. The implementation's known-answer test must
reproduce all of them.

```
seed_A = 01 × 32           seed_B = 02 × 32
edA     8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
edB     8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394
xA      1b1b58dd50ea14b60da17b790cd02754d970c9bab864ebb3c0f3016fe51d3f57
xB      60346e7c911a5f6ba154129174cafe75b294ac3bbd5549632f48cec6266f8410
dh      4181d7302557342bdb6d061c4b1eebea828ecb625c3368b7111680793307220b
PRK     d9e99e7737ca7f04493966f553aac678a99b9f034159d8afed13d60c51296165
        af3d6afdb61cf34af0efa7c439e27b0825ccab7bf1fb7f8e504b36b05347b5a2
lo = edB (0x81 < 0x8a), so dir(A listens) = 0x02, dir(B listens) = 0x01

relay static pub  = aa × 32
svc(relay)  a1e8be00254100a1c26e98beae6453c6e70e27da57e7c7ab4268608abe197629
broker pub        = bb × 32
svc(broker) c6fffd6ded35d244a71c26931a15bbbdcaa067c96d6238dc753b3dd6587b3eba

info(relay-static, svc(relay), 0x02, 0) =
  6b616d756e652f72656e64657a766f75732f76310072656c61792d737461746963
  00a1e8be00254100a1c26e98beae6453c6e70e27da57e7c7ab4268608abe197629
  020000000000000000                                      (75 bytes)

relay-static,  A listens  06092b9ce253d28857c1a7757a69ce3efc2a12ae9712ffef3aaca89f559c1a4a
relay-static,  B listens  94014bc8d792d201aa674348c3735d0ffe8f189672ab8286103e2b7275de36d1
broker-static, A listens  06fb7ac8f6aab7183c93cdd39a379abfef98ead6519d8ccb97a3c0e58b4de63d
broker-static, B listens  6109e9bbce69faf6b6cfcef585e3fc709c35ad1374b2375033983d484858f0cc

reconnect_root = 33 × 32, svc(relay)
reconnect[0]  e753d2bc11b59e2a304a06b0bbf6c6420b3732aec3a174b8645cee37b3f45197
reconnect[1]  edffdb7af9a324711b376ce65e65f3e9a63318a50b12020adef6b1aac64c84bf
reconnect[2]  eff23211bd4a5558a981be9073bb1ebf5a4c52941ec77c9889d10232e05e3925

handle(relay-static, A listens)  d4577ee27751

p2p-punch (either side)  54367d7f800f4c3cf6360583b206a416d79aa17fe72e6ca696f0ecbf6577c72e
  (info is 72 bytes: purpose "p2p-punch", svc 32 zero bytes, dir 0x00, n 0)
```

### 7.10 Patterns reused

- Static-static DH as a shared rendezvous secret: the `ss` term of Noise KK
  and the identity DH of X3DH; XEdDSA is the same key conversion in the other
  direction.
- Extract with a protocol salt, Expand with structured `info`: RFC 5869 and
  TLS 1.3 `HKDF-Expand-Label` (RFC 8446 section 7.1).
- Exporter: RFC 8446 section 7.5 and RFC 5705.
- Binding a credential to a server identity: TLS 1.3 session tickets and PSK
  identities are valid only with the server that issued them.
- Directional keys from one shared secret: the per-direction traffic secrets
  of TLS 1.3 and the initiator and responder keys of Noise `Split()`.
- Expected peer: TLS client certificate pinning on the server side; SSH
  `authorized_keys` restricted to one key per forwarded port.

## 8. Wire Changes

### 8.1 Relay protobuf

In `pkg/relayconn/pb/relay.proto`, the field numbers of `Register` and
`Registered` stay; the contract changes:

```protobuf
message Register {
  bytes token = 1;  // MODE_CREATE: empty (relay picks a random 32-byte
                    // token) or exactly 32 bytes. MODE_JOIN: exactly 32
                    // bytes. Any other length, or 32 zero bytes: Refused
                    // TOKEN_INVALID.
  Mode  mode  = 2;
  ...
}
message Registered {
  bytes token = 1;  // always 32 bytes
  ...
}
```

A new record lets a client tell a missing session from a taken token:

```protobuf
message Frame {
  oneof kind {
    ...                       // fields 1 to 5 as today; 6 reserved by RFC009
    Refused refused = 7;
  }
}

message Refused {
  Reason reason = 1;
  enum Reason {
    REASON_UNSPECIFIED = 0;
    TOKEN_NOT_FOUND    = 1;   // MODE_JOIN: no waiting session
    TOKEN_IN_USE       = 2;   // MODE_CREATE: token already registered;
                              // MODE_JOIN: session already has a dialer
    TOKEN_INVALID      = 3;   // CheckWire failed, or MODE_JOIN with no token
    SESSION_FULL       = 4;   // max_conns reached
    SESSION_EXPIRED    = 5;
    BAD_REGISTER       = 6;   // MODE_UNSPECIFIED or unknown mode
  }
}
```

Field 6 is `auth` today; RFC009 deletes `Auth` and reserves the number.

Rules:

- `Refused` is valid only as the relay's record 0, in place of `Registered`
  (RFC009: the relay's first record is `Registered`). The relay closes the
  channel right after writing it. RFC009's alerts are sent before its
  ServerHello; `Refused` is an authenticated record after it, so only the
  relay that holds the relay key can send it.
- A client that receives `Refused` after `Registered`, or a second record 0,
  closes with RFC009's `ErrBadMessage`.
- A `Refused` with `REASON_UNSPECIFIED`, or with a value the client does not
  know (proto3 keeps unknown enum values as integers), maps to `ErrRefused`.

The record tells the sender nothing new: a `MODE_JOIN` that gets
`Registered`, or a closed channel, already showed whether a session existed.

### 8.2 Broker contract with RFC011

RFC011 owns the broker wire, and this RFC needs nothing on it. The contract is
on RFC011's client API:

- The client never sends a token. RFC011 derives
  `RID = ExpandLabel(HKDF-Extract(salt = "kamune broker v2 rid " ‖ S_pub,
  ikm = token), "rendezvous", "", 32)` from this RFC's 32-byte token, where
  `ExpandLabel` uses RFC011's prefix `kamune broker v2 ` and the salt string
  ends with a space.
- Static P2P tokens: `pk.ListenToken(rendezvous.Broker, broker_id)` for
  `RoleListen`, `pk.DialToken(rendezvous.Broker, broker_id)` for `RoleDial`.
  Directional tokens put A-listens-for-B and B-listens-for-A in different
  `RID`s, so two listeners of one pair no longer evict each other under
  RFC011's slot rule ("same role, newer cookie: the slot moves"), and a
  client's own `DIAL` never meets its own `LISTEN`.
- Random P2P tokens: `rendezvous.NewRandomToken()` in the client.
- `Endpoint.Register(ctx, tok rendezvous.Token, role)` takes this RFC's type,
  not `[]byte`. A zero token returns `rendezvous.ErrTokenZero`; RFC011 has
  no `ErrBadToken` and no reference to `relayconn.ValidateUserToken`.
- No epoch overlap, so one registration per (pair, role) and no match
  dedupe. The dialer registers once and calls `Wait` with a 30 s context
  (RFC011).
- `Match` carries no token or key; the client knows which registration
  matched from the `Registration` it reads. No client compares a notified
  token, so `broker.TokenMatches` goes with RFC011's removal of the v1 codec.

## 9. Interfaces with Other RFCs

### 9.1 RFC007: handshake

- `func (t *Transport) ExportKeyingMaterial(label string, context []byte,
  length int) ([]byte, error)`. This RFC uses label `kamune/relay-reconnect`
  (RFC007 reserves the `kamune/` prefix), context nil, length 32. With these
  arguments the call fails only after the transport is closed, and the
  clients call it right after establishment.
- `DialWithPeerKey(pub []byte)`, `DialWithResume(sessionID)` (which pins the
  stored key), `Transport.Resumed()`, `Transport.SessionID()`.
- The `PeerConstraint` check of section 7.7, in RFC007's checks on receipt.
  Initiator: after the responder's signature and Finished verify, next to
  the pin check, before it sends anything, so SIGMA-I identity protection
  holds (the initiator never sends its identity to a key the conn forbids).
  Responder: right after the initiator's signature and Finished verify,
  before the version check and the verifier; on failure it closes without a
  Confirm. Failure: `ErrPeerKeyMismatch`. When the check ran and passed,
  `VerifyRequest.Pinned` is true on either side, so the Quick and
  Auto-Accept modes behave as for a pinned initiator.
- **Interim check.** Until RFC007's root switch lands, this RFC adds the same
  check to today's `verifyPeer`, which already receives `cn` and `peer`:
  `if pc, ok := cn.(PeerConstraint); ok && !pc.AllowPeer(peer.PublicKey)
  { return ErrPeerKeyMismatch }`, before `opts.remoteVerifier`.
  `verifyPeer` runs on both sides today, so this covers dialer and listener.
  `ErrPeerKeyMismatch` is defined in the root `errors.go` by this RFC;
  RFC007 keeps that definition and moves the check into its handshake.
  Static modes do not ship in a release without one of the two.
- Identity stays a single Ed25519 key. If RFC007 ever adds a separate X25519
  identity key, only `attest.PairSecret` changes, and share cards must carry
  that key.

### 9.2 RFC009: relay leg

- `relayleg.PublicKey [32]byte`, text form `rk1-...`. The client sends
  `Register` only as record 0, after `finished_r` verified. A failed
  handshake, `ErrRelayKeyUnknown` or `ErrRelayKeyChanged` returns before any
  `TokenFunc` runs.
- `ListenResult.RelayKey` and `(*RelayConn).RelayKey()` as RFC009 defines
  them.
- `Dial` has no positional token; the token is an option (section 10.4).
  `checkRegisteredToken` keeps its role with one length,
  `rendezvous.TokenSize`; its "sent empty" branch stays for relay-assigned
  random tokens.
- Record 0 from the relay is `Registered` or `Refused` (section 8.1). This
  RFC's commits that touch `relayHandshake`, `listenHandshake` and the
  relay's record-0 handling merge after RFC009's `Dial`/`Listen` commit and
  after RFC009's commit that moves the relay to the new relay leg.
- RFC009's first-contact policy is unchanged. A token derived during a first
  contact with an impostor is bound to the impostor's key, is useless at the
  real relay, and the impostor cannot pass G5. Waiting at an impostor is the
  same loss any on-path attacker causes.

### 9.3 RFC011: broker

- Section 8.2.
- `NewClient(a broker.Address)`, where `a.Key` is the broker's
  `relayleg.PublicKey` from the address's `rk=`. `broker_id` is
  `rendezvous.NewServiceID(a.Key)`; RFC011's `Client.ServiceID()` returns
  the same value and either may be used.
- The p2p listener and dialer apply the expected-peer rule of section 7.7.
  `RemoveP2PToken` calling `Registration.Close`, and the dial-side `Wait`
  with 30 s, belong to RFC011.

### 9.4 RFC008: UDP path

This RFC provides `PairKey.PunchKey() [32]byte` (purpose `p2p-punch`,
section 7.3), which RFC008 uses as the direct-P2P knock key
(`UDPWithKnockKey`). Broker P2P listeners have no knock key. This RFC's client
commits wrap the UDP conns with `kamune.ExpectPeer` (section 7.7); RFC008
keeps the wrappers.

## 10. Go API

### 10.1 `pkg/attest`

New file `pairsecret.go`; commit prefix `kamune:`.

```go
// PairSecret returns HKDF-Extract(SHA-512, salt, X25519(self, peer) ‖ lo ‖ hi)
// for this identity and peerPKIX (section 7.2). The raw DH is not exposed.
// salt must start with "kamune/". Errors: ErrInvalidKey (peer fails
// IsValidPublicKey or bad PKIX), ErrSameKey, an empty or unprefixed salt.
func (a *Attest) PairSecret(peerPKIX []byte, salt string) ([64]byte, error)

var ErrSameKey = errors.New("attest: peer key equals own key")
```

Unexported: `edToX25519Public(pub ed25519.PublicKey) ([]byte, error)` with
`math/big` on the public point, and `x25519Private(seed []byte)
(*ecdh.PrivateKey, error)` through `crypto/ecdh`. Any later static DH calls
`PairSecret` with its own salt.

### 10.2 New package `pkg/rendezvous`

Commit prefix `kamune:`. The package imports `attest` only. `relayconn`,
`relayconn/broker`, `cmd/relay` and the clients import it.

```go
package rendezvous

const (
	TokenSize         = 32
	ReconnectPoolSize = 3
	ReconnectLabel    = "kamune/relay-reconnect"
)

var (
	ErrTokenSize    = errors.New("rendezvous: token must be 32 bytes")
	ErrTokenZero    = errors.New("rendezvous: token is all zero")
	ErrTokenFormat  = errors.New("rendezvous: token must be 64 hex characters")
	ErrDerivedToken = errors.New("rendezvous: a derived token cannot be revealed")
	ErrSamePeer     = errors.New("rendezvous: peer key equals own key")
)

// Token is a 32-byte rendezvous token. Its zero value is invalid.
// It formats, logs and marshals as "tok:" + Handle().
type Token struct {
	b       [TokenSize]byte
	derived bool
}

func NewRandomToken() (Token, error)
// ParseToken trims leading and trailing ASCII whitespace, then requires
// exactly 64 hex digits (either case, no "0x"). Zero: ErrTokenZero.
func ParseToken(s string) (Token, error)
// TokenFromWire takes a relay-assigned token (bearer). ErrTokenSize,
// ErrTokenZero.
func TokenFromWire(b []byte) (Token, error)
// CheckWire is the relay's only token check.
func CheckWire(b []byte) error

func (t Token) Reveal() (string, error)  // lowercase hex; ErrDerivedToken
func (t Token) Bytes() []byte            // copy, for relayconn and broker only
func (t Token) Handle() string           // section 7.8
func (t Token) Derived() bool
func (t Token) IsZero() bool
func (t Token) Equal(u Token) bool       // constant time on the bytes
func (t Token) String() string           // "tok:" + Handle()
func (t Token) Format(f fmt.State, verb rune)   // every verb: String()
func (t Token) LogValue() slog.Value     // String()
func (t Token) MarshalText() ([]byte, error)    // String()

type ServiceID [32]byte
func NewServiceID(pub [32]byte) ServiceID        // section 7.4

// TokenFunc derives a token once the relay key is authenticated.
type TokenFunc func(svc ServiceID) (Token, error)

type Purpose uint8
const (
	Relay  Purpose = iota + 1 // "relay-static"
	Broker                    // "broker-static"
)

type PairKey struct{ /* prk [64]byte; peer []byte; dirSelf, dirPeer byte */ }

func NewPairKey(self *attest.Attest, peerPKIX []byte) (*PairKey, error)
func (k *PairKey) Peer() []byte                              // PKIX copy
func (k *PairKey) ListenToken(p Purpose, svc ServiceID) Token // self listens
func (k *PairKey) DialToken(p Purpose, svc ServiceID) Token   // peer listens
func (k *PairKey) RelayListen() TokenFunc  // ListenToken(Relay, svc)
func (k *PairKey) RelayDial() TokenFunc    // DialToken(Relay, svc)
func (k *PairKey) PunchKey() [32]byte      // 7.3 p2p-punch, RFC008's knock key

type Exporter interface {
	ExportKeyingMaterial(label string, context []byte, n int) ([]byte, error)
}

type ReconnectRoot [32]byte

func NewReconnectRoot(e Exporter) (ReconnectRoot, error)
// ReconnectRootFromBytes returns false unless b is 32 non-zero bytes.
func ReconnectRootFromBytes(b []byte) (ReconnectRoot, bool)
func (r ReconnectRoot) Token(svc ServiceID, i int) Token
func (r ReconnectRoot) Funcs() []TokenFunc  // ReconnectPoolSize, index order
```

Derived tokens (from `PairKey` and `ReconnectRoot`) have `derived = true`.
`NewRandomToken`, `ParseToken` and `TokenFromWire` give `derived = false` (a
parsed token is one the user already holds in full). `NewPairKey` maps
`attest.ErrSameKey` to `ErrSamePeer` and passes `attest.ErrInvalidKey`
through. There is no `Destroy`: `PRK_pair` is a Go value the runtime may
copy, so zeroing cannot be promised.

One type with a `derived` flag, rather than separate bearer and pair token
types, keeps `WithToken`, `ListenResult.Token`, RFC011's `Register` and the
client structs single. No format, log or marshal path prints a derived token,
and no method returns its hex: `Reveal` returns `ErrDerivedToken`, and
`Bytes` is the wire accessor for `relayconn` and the broker client. The
redaction tests of section 16 check this.

### 10.3 Root package `kamune`

`PeerConstraint` and `ExpectPeer` as in section 7.7, in the new file
`peerconstraint.go`, and `ErrPeerKeyMismatch` in `errors.go`. Commit prefix
`kamune:`.

### 10.4 `pkg/relayconn`

Commit prefix `relayconn:`. On top of RFC009's API:

```go
func Dial(ctx context.Context, a Address, opts ...Option) (*RelayConn, error)
func Listen(ctx context.Context, a Address, opts ...Option) (*ListenResult, error)

// WithToken registers (Listen) or joins (Dial) a token the caller holds.
func WithToken(t rendezvous.Token) Option
// WithTokenFunc derives the token from the authenticated relay key.
func WithTokenFunc(f rendezvous.TokenFunc) Option
// WithExpectedPeer makes the resulting conns implement
// kamune.PeerConstraint for this PKIX key.
func WithExpectedPeer(pkix []byte) Option
// WithPair is WithTokenFunc(pk.RelayListen()) on Listen or
// WithTokenFunc(pk.RelayDial()) on Dial, plus WithExpectedPeer(pk.Peer()).
func WithPair(pk *rendezvous.PairKey) Option

// AllowPeer implements kamune.PeerConstraint; true without an expected peer.
func (c *RelayConn) AllowPeer(pkix []byte) bool

var (
	ErrNoToken        = errors.New("relayconn: dial needs a token option")
	ErrTokenOptions   = errors.New("relayconn: more than one token option")
	ErrTokenInUse     = errors.New("relayconn: relay reports token in use")
	ErrTokenNotFound  = errors.New("relayconn: relay has no session for token")
	ErrTokenInvalid   = errors.New("relayconn: relay rejected the token")
	ErrSessionFull    = errors.New("relayconn: relay session table is full")
	ErrSessionExpired = errors.New("relayconn: relay session expired")
	ErrRefused        = errors.New("relayconn: relay refused the registration")
)

type ListenResult struct {    // RFC009's, one field changed
	Listener     *RelayListener
	Token        rendezvous.Token // was []byte
	TTL          time.Duration
	SessionTTL   time.Duration
	RelayKey     relayleg.PublicKey
	FirstContact bool
}
```

Rules:

- Option checks run before any network I/O. `Dial` with no token option
  returns `ErrNoToken`; two of `WithToken`, `WithTokenFunc` and `WithPair`
  return `ErrTokenOptions`. `Listen` with none registers an empty token, and
  the relay assigns a random one, read with `TokenFromWire`.
- A `TokenFunc` runs after `finished_r` verified, with
  `rendezvous.NewServiceID(relayKey)`. If it returns an error or a zero
  token, `Dial` and `Listen` close the channel without sending `Register` and
  return that error (`ErrTokenZero` for a zero token).
- `Refused` maps as follows: `TOKEN_NOT_FOUND` to `ErrTokenNotFound`,
  `TOKEN_IN_USE` to `ErrTokenInUse`, `TOKEN_INVALID` to `ErrTokenInvalid`,
  `SESSION_FULL` to `ErrSessionFull`, `SESSION_EXPIRED` to
  `ErrSessionExpired`, and anything else (`REASON_UNSPECIFIED`,
  `BAD_REGISTER`, unknown) to `ErrRefused` wrapping the number. A channel
  that closes with neither record keeps the read error of RFC009's C4 state
  (today the dial and listen helpers, `relayHandshake` and `listenHandshake`,
  wrap it as "read registered").
- `RelayListener` passes its expected peer to the `RelayConn` it creates.

Deleted: `TokenFromKeys`, `ValidateUserToken`, `ErrTokenTooShort`,
`ErrTokenInsufficientEntropy`, `ErrInvalidKeySize`, `RelayTokenPending` (with
`Complete`), `BeginRelayTokenExchange`, `CompleteRelayTokenPayload`,
`SessionDataPeerKey`, `DeriveRelayTokens`, `ErrECDHPeerKeyMissing`,
`relayTokenSize`, `peerTokenSize`, `tokenPoolSize`, `tokenInfoPrefix`,
`log2`. Most of `pkg/relayconn/token.go` goes.

### 10.5 `cmd/relay`

Commit prefix `relay:`.

- `services.SessionManager.Create` returns the bytes of
  `rendezvous.NewRandomToken()`. `CreateWith` and `Join` call
  `rendezvous.CheckWire`. `session.go` imports `relayconn` only for
  `ValidateUserToken` today; that import goes.
- The session map key stays the hex of the token.
- Silent-dialer re-arm (section 13).
- The registration handler sends `Refused{reason}` as record 0 before closing
  when `Create`, `CreateWith` or `Join` fails: `ErrTokenNotFound` to
  `TOKEN_NOT_FOUND`; `ErrTokenInUse` and `ErrTokenConsumed` to
  `TOKEN_IN_USE`; a `CheckWire` error or `MODE_JOIN` without a token to
  `TOKEN_INVALID`; `ErrSessionFull` to `SESSION_FULL`; `ErrSessionExpired` to
  `SESSION_EXPIRED`; an unknown mode to `BAD_REGISTER`. The write uses the
  handler's existing write deadline; a failed write is ignored.
- The three `slog.Error` calls for refused registrations in
  `handleRelayConn` (code RFC009 rewrites) become `slog.Debug` with the reason
  and the client IP, never the token. Static-listener retries and dial misses
  are routine.

### 10.6 `pkg/storage`

Commit prefix `kamune:`.

- Add `RelayReconnectKey = "relay_reconnect"`: a session meta holding the 32
  raw bytes of a `ReconnectRoot`. Any other length is treated as absent.
- Delete `RelayTokensKey` (`"relay_tokens"`) once no client uses it. No
  migration: a leftover `relay_tokens` meta is ignored, and
  `pruneIdleSessions` deletes it with the session.

### 10.7 Names that look alike

`relayconn.ErrTokenInvalid` (the relay sent `Refused TOKEN_INVALID`) and
`relayconn.ErrInvalidRelayToken` (existing: the token in `Registered` has the
wrong length) are different errors. So are `rendezvous.ErrSamePeer` and
`attest.ErrSameKey` (token derivation) and `kamune.ErrSelfConnection`
(RFC007, handshake).

## 11. Error Handling

| Condition | Where | Result |
| --- | --- | --- |
| Peer key fails `IsValidPublicKey` | `NewPairKey` | `attest.ErrInvalidKey`; client code `invalid_peer_key`; nothing registered, no fallback to random |
| Own key equals peer key | `NewPairKey` | `ErrSamePeer`; client code `invalid_peer_key` |
| `TokenFunc` error or zero token | `relayconn` | close before `Register`, return the error |
| Zero `Token` passed to `Register` (RFC011) | broker client | `ErrTokenZero` |
| Token not 32 bytes, or all zero, on the wire | relay | `Refused TOKEN_INVALID`, close, debug log without the token |
| User pastes a 32-hex-character (old) token | `ParseToken` | `ErrTokenFormat`; client code `invalid_token`, message "tokens are 64 hex characters" |
| `Reveal` on a derived token | client | `ErrDerivedToken`; a bug, logged at error, nothing shown |
| Static `CREATE` gets `ErrTokenInUse` | client listener | status `waiting`, retry with backoff (12.1) |
| Static dial gets `ErrTokenNotFound` | client dialer | client code `peer_not_listening` |
| Remote key differs from the pair's peer | handshake | `ErrPeerKeyMismatch`; client code `peer_key_mismatch`; logged at warn with the remote fingerprint |
| Relay authentication fails (RFC009) | `relayconn` | the `TokenFunc` is never called |
| Stored reconnect root of the wrong length | client | treated as absent; cold start |

## 12. State Machines

### 12.1 Static relay listener

This machine runs in the bus and the daemon. One entry per (relay address,
peer). `generate_relay_token` or `StartServer` for a peer that already has a
live static entry on that relay returns that entry.

```
IDLE        --start-->            REGISTERING
REGISTERING --Registered-->       LISTENING              status active
REGISTERING --ErrTokenInUse,
              network error,
              ErrSessionFull-->   WAITING(k)             status waiting
REGISTERING --ErrRelayKeyUnknown,
              ErrRelayKeyChanged,
              ErrTokenInvalid-->  FAILED                 status error, needs user
WAITING(k)  --after backoff(k)--> REGISTERING            k = k + 1
LISTENING   --conn accepted-->    SERVING                status consumed
LISTENING   --token_ttl expiry,
              listener died-->    REGISTERING            immediately
SERVING     --session ended-->    REGISTERING after 1 s + uniform [0, 4 s)
any         --remove(id),
              server stop-->      STOPPED                Stop() the listener
backoff(k)  = 2, 4, 8, 16, 30, 30, ... seconds
```

A static listener serves one session at a time per relay: while the session
runs, the relay still holds the token. The wait before registering again is
the one the clients use today after a resume listener ends unused
(`awaitRelayResume` in the daemon, `resumeBackoff` in the bus), and it gives
the relay time to run `Leave` for the old session.

### 12.2 Static relay dialer

```
pk   = NewPairKey(self, peer)                  error -> invalid_peer_key
conn = relayconn.Dial(ctx, addr, WithPair(pk))
  ErrTokenNotFound -> peer_not_listening
  ErrTokenInUse    -> peer_busy (the peer's listener is serving a session)
t    = kamune dial over conn with DialWithPeerKey(peer)
  ErrPeerKeyMismatch -> peer_key_mismatch
```

One relay connection per attempt.

### 12.3 Static broker rendezvous

On RFC011's client API:

```
listener: once per (p2p listener, peer)
    svc = NewServiceID(broker address key)
    reg = ep.Register(ctx, pk.ListenToken(Broker, svc), RoleListen)
    record reg -> expected peer pk.Peer() for 7.7
    remove(id) -> reg.Close()
dialer:
    reg = ep.Register(ctx, pk.DialToken(Broker, svc), RoleDial)
    m   = reg.Wait(30 s context)
    KCP (after RFC008, the UDP path) to m.Peer,
    conn wrapped with ExpectPeer(conn, pk.Peer()),
    kamune dial with DialWithPeerKey(pk.Peer())
```

RFC011's `Registration` refreshes itself; this RFC adds no refresh loop.

### 12.4 Reconnect

```
on Established (cold or resumed), both sides, unless incognito:
    root = NewReconnectRoot(t)
    if the transport came from DialWithResume(old) and !t.Resumed():
        delete relay_reconnect of old; the session is new (RFC007)
    store root under t.SessionID()
listener re-registration (awaitRelayResume):
    for i, f in root.Funcs():
        Listen(ctx, addr, WithTokenFunc(f), WithExpectedPeer(peer))
        ok -> done; ErrTokenInUse -> next i; other error -> backoff, restart at 0
dialer reconnect (daemon makeReconnectFn, bus reconnect in ConnectToServer):
    for i, f in root.Funcs():
        conn = Dial(ctx, addr, WithTokenFunc(f), WithExpectedPeer(peer))
          ErrTokenNotFound, ErrTokenInUse -> next i
        t = kamune DialWithResume(sessionID) over conn, with a first-frame
            watchdog: conn is closed if no frame arrives within 10 s
          ok -> done
          watchdog fired, or close before Established -> close conn, next i
    exhausted -> cold start (unchanged)
```

Moving on after a handshake failure covers a stale index-0 session that the
relay still pairs. The 10 s bound applies only to the first frame (RFC007's
ServerHello), through a client-side `Conn` wrapper that closes the conn when
its first `ReadBytes` has not returned in time; after that, RFC007's own
deadlines apply. A 10 s limit on the whole handshake would break resumes
toward a Strict responder, which prompts on every handshake, resumed ones
included (RFC007). An `ExportKeyingMaterial` error means the transport has
already closed (section 9.1): it is logged at warn, nothing is stored, and the
session is not resumable through the relay. The `RouteSessionData` handler
for `ecdh_pubkey` is deleted in both clients; `RouteSessionData` stays as a
generic route.

The root is not consumed by registering it, so the per-token removal of
today's loop (`popRelayToken` in the daemon, `removePoolToken` in the bus)
goes. The loop's other exits stay: the session can no longer be resumed, the
user removed the entry, the server stopped, or the resume window passed. On
those exits the client deletes the session's `relay_reconnect` meta where
`dropRelayPool` deletes `relay_tokens` today.

Combined with RFC007 and RFC009, both reconnect loops:

- stop without retrying on RFC007's final errors (`ErrVerificationFailed`,
  `ErrHandshakeRejected`, `ErrPeerKeyMismatch`, `ErrSelfConnection`,
  `ErrNoResumptionState`, `ErrVersionMismatch`, `ErrUnsupportedProtocol`,
  `ErrResumeInProgress`, `ErrResumeRefused`) and on
  `relayconn.IsRelayTrustError(err)` (RFC009);
- move to the next reconnect index on `relayconn.ErrTokenNotFound`,
  `ErrTokenInUse`, or a first-frame watchdog close;
- on other errors, back off and restart at index 0;
- on success with `!t.Resumed()`, close the old live session, start a new
  one with `t.SessionID()` (RFC007), delete the old session's
  `relay_reconnect` and store the new root.

## 13. Relay-Side Hardening

This is the relay half of RC-04. Today a dialer that joins and sends nothing
holds the session until `session_ttl`, and a dialer that leaves tears down the
listener (`SessionManager.Join` and `Leave`). With pair tokens and G5 only the
relay can do this to a static listener, but holders of a bearer random token
still can. The change is in `cmd/relay/internal/services`:

```go
type session struct {
	listener, dialer *exchange.Channel   // RFC009: *relayleg.Channel
	expiry, sessionExpiry time.Time
	joinedAt  time.Time  // new
	forwarded bool       // new: the dialer has forwarded a Message
}
const dialerGrace = 10 * time.Second
```

`SessionManager` gains an unexported `now func() time.Time` (default
`time.Now`), used by every expiry check in `session.go`, so tests can move
time without sleeping.

- `Recipient(token, sender)`: when `sender == sess.dialer`, set
  `sess.forwarded = true` (already under `sm.mu`).
- `Leave(token, ch)` with `ch == sess.dialer` and `!sess.forwarded`: set
  `sess.dialer = nil`, clear `sessionExpiry`, keep the session, and do not
  close the listener. The listener never saw the dialer (`RelayListener`
  creates a conn only on the first `Message`), so nothing needs undoing.
- `Join` on a session with `sess.dialer != nil && !sess.forwarded &&
  now > joinedAt + dialerGrace`: close the old dialer and take its place. A
  kamune initiator sends its first frame at once, so 10 s leaves room for a
  slow link.
- Unchanged: a dialer that forwarded anything consumes the session as today.

## 14. Client Changes

### 14.1 Daemon

`cmd/daemon`, commit prefix `daemon:`.

Token code:

- Replace `deriveP2PToken` with `pairKey(peerPubB64) (*rendezvous.PairKey,
  error)` over `store.Attester()` and `decodePeerPubKey`.
- `listenRelayTracked` takes `[]relayconn.Option` instead of
  `staticToken []byte`. Static mode passes `WithPair(pk)` and runs under the
  machine of section 12.1.
- `dialRelayFuncMultiToken` takes `[]rendezvous.TokenFunc` and the peer key.
- `dial` (`CmdDial`): today the relay branch passes `params.Token` and the
  p2p branch decodes `params.P2PToken`; `DialParams.PeerPubB64` is not read.
  After this RFC, relay with `peer_pub_b64` and no `token` dials with
  `WithPair`; p2p with `peer_pub_b64` and no `p2p_token` uses
  `DialToken(Broker, svc)`; `token` (or `p2p_token`) together with
  `peer_pub_b64` returns `invalid_params`, the rule the bus applies in
  `resolveP2PDialerToken`. With `peer_pub_b64`, the kamune dial passes
  `DialWithPeerKey` once RFC007 provides it.
- `start_server` with `transport: relay` accepts `peer_pub_b64` and starts a
  static listener (today it passes no token to `listenRelayTracked`), for
  parity with the bus.
- `relayToken` and `p2pToken` gain `ID` (8 random bytes, hex), `Handle` and
  `Status`; `Token` is filled only for `mode == "random"`, through
  `Reveal()`.
- `tokenTracker` and `markRelayTokenConsumed` key by `ID`. Keyed by token
  string, as today, an empty `Token` would match every derived entry.
  `listenRelayTracked` stores the `ID`, not the hex of `result.Token`.
- `handleGenerateRelayToken` returns the live static entry for a peer that
  has one, as `GenerateP2PToken` already does; today it registers another.
  Its peer key check moves from `parsePeerPubB64ToRaw` to `NewPairKey`.
- `handleRemoveRelayToken` and `RemoveRelayTokenParams` take `id`.
- p2p listener and dialer: the `ExpectPeer` wrapping of section 7.7 in
  `p2plistener.go`, `broker.go` and, with a known peer key, `directp2p.go`.

Reconnect code:

- Delete `deriveAndStoreRelayTokens`, `finishRelayToken`,
  `liveSession.relayToken` and the `SessionData` branch of the receive loop
  (`messaging.go`). Add `storeReconnectRoot(t, session)` where
  `deriveAndStoreRelayTokens` is called today (`dial`, `serverHandler`,
  `makeReconnectFn`), with the rules of section 12.4.
- `awaitRelayResume` and `makeReconnectFn` follow section 12.4;
  `loadRelayPool` reads `RelayReconnectKey`; `popRelayToken` goes.

Logs and events (the token part of DMN-11):

- Every `addLogEntry` and `slog` call that prints a token or a prefix of one
  (`shortToken`) prints `Handle()`.
- `EvtRelayToken` (`announceRelayToken`) carries `{id, mode, handle,
  token?}`.

`parsePeerPubB64ToRaw` loses its last callers (`deriveP2PToken` and the peer
key check in `handleGenerateRelayToken`) and is deleted. `decodeTokenList`
loses its token callers (`loadRelayPool` and the reconnect dial in
`makeReconnectFn`), but `relayResumable` still reads `resumption_tokens`
with it, so it is deleted once RFC007 replaces that store and removes its
last caller.

### 14.2 Daemon JSON API

Changes to DAEMON.md and `cmd/daemon/schema`:

| Command / event | Change |
| --- | --- |
| `generate_relay_token` | params add `peer_pub_b64?`. Response `{id, mode: random\|static, token?, handle, status, ttl_ns, session_ttl_ns, expires_at}`; `token` only for `random`; an existing static entry for the peer is returned as is |
| `remove_relay_token` | params `{id}` (was `{token}`) |
| `list_relay_tokens`, evt `relay_tokens` | entries `{id, mode: random\|static\|reconnect, token?, handle, peer_pub_b64?, status: registering\|active\|waiting\|consumed\|error, ttl_ns, session_ttl_ns, expires_at}`; mode `ecdh` is renamed `reconnect` |
| evt `relay_token` | `{id, mode, handle, token?}` |
| `generate_p2p_token` | params `{peer_pub_b64?}` (RFC011 removes `broker_addr`: the running p2p listener's broker applies). Response `{id, mode, token?, handle, broker_addr, peer_pub_b64?, status}`; `status` values follow RFC011 (`pending`, `active`, `contested`, `lost`) |
| `remove_p2p_token` | params `{id}` |
| `list_p2p_tokens`, evt `p2p_tokens` | same shape as the relay entries |
| `dial` | relay: `token` (64 hex) or `peer_pub_b64`; p2p: `p2p_token` or `peer_pub_b64`; both: `invalid_params` |
| `start_server` | relay: `peer_pub_b64?` starts a static listener |
| `get_share_info` | relay: a relay-assigned random token, as today (now 32 B). p2p: the first `random` entry, else `p2p_token_required` (today it takes the first entry whatever its mode). Never a static token or its handle, relay or p2p |
| error codes | new: `invalid_token`, `peer_not_listening`, `peer_busy`, `peer_key_mismatch`, `p2p_token_required`. `invalid_peer_key` is not new: it exists today (the peer commands and `generate_relay_token`) and widens to every `NewPairKey` failure. RFC007's client commit also uses `peer_key_mismatch` for `kamune.ErrPeerKeyMismatch` from a pin |

Share URLs carry a token only for random tokens: relay
`relay://?addr=...&token=...&psk=1` (RFC009), p2p
`p2p://host:port?rk=...&token=<64 hex>` (RFC011).

Schema files: `_shared/relay-token.schema.json` (mode enum, `token`
optional, `id` and `handle` required), `events/relay_token`, `relay_tokens`,
`p2p_tokens`, `commands/generate_relay_token`, `remove_relay_token`,
`list_relay_tokens`, `generate_p2p_token`, `remove_p2p_token`,
`list_p2p_tokens`, `dial`, `start_server`.

### 14.3 Bus

`cmd/bus`, commit prefix `bus:`. Go: the same changes as the daemon in
`network.go`, `p2p.go`, `p2plistener.go`, `broker.go`, `directp2p.go` and
`relay.go`, plus:

- `StartServer` in relay mode with a non-empty `peerPubB64` already fails
  when the derivation fails. After this RFC the failure comes from
  `NewPairKey`, the error is `invalid_peer_key`, and nothing is registered.
- `StartServer` in static mode returns `""` as the token (today it returns
  the static token). The `relay-token` event and the log line carry the
  handle.
- Static dials in `ConnectToServer` (`relayDialToken`) and
  `resolveP2PDialerToken` use `WithPair` or `DialToken`, and
  `DialWithPeerKey` once RFC007 provides it.
- `tokenTracker` and `markRelayTokenConsumed` (`app.go`) key by `ID`;
  `logToken` call sites print the handle.
- `storeReconnectRoot` where `deriveAndStoreRelayTokens` is called today
  (twice in `ConnectToServer`, once in `serverHandler`); `loadRelayPool`
  reads `RelayReconnectKey`; `awaitRelayResume` and `registerResumeToken`
  follow section 12.4, and `removePoolToken` goes.
- `decodeTokenList` (`network.go`) and `parsePeerPubB64ToRaw` (`peers.go`) as
  in the daemon.

The bus already has an application-level peer gate (section 2.4): `pinPeer`
on dials, and `peerGate`, `peerKeySet`, `pinRelayListener` and `admittedBy`
on static listeners, checked in `serverHandler` after the verifier. For the
conns this RFC constrains, `PeerConstraint` rejects the same keys earlier,
before the verifier. Whether the bus keeps the gate as a second check is open
(section 22). The resume-listener check `admitsSession` concerns the session
ID, not the key, and this RFC does not change it.

Bound methods:

```go
func (a *App) GenerateRelayToken(peerPubB64 string) (relayToken, error)
func (a *App) RemoveRelayToken(id string) error
func (a *App) GenerateP2PToken(peerPubB64 string) (p2pToken, error) // RFC011
func (a *App) RemoveP2PToken(id string) error
```

Today `GenerateRelayToken` returns the token string, `GenerateP2PToken`
takes a broker address and returns a string, and both remove methods take a
token.

Frontend:

- `lib/models.ts`: `RelayToken` and `P2PToken` gain `id`, `handle` and
  `status`; `token` becomes optional.
- `lib/stores.ts`, `lib/Sidebar.svelte`, `lib/SignalingTokens.svelte`: rows
  and removal are keyed by `id`; static rows show the peer name, the handle
  and the status, with no copy button.
- `App.svelte`: the `relay-token` toast shows the handle for a static
  listener. The three places that say static tokens are derived from the
  peers' public keys and that anyone who knows both keys can derive the same
  token, and the static-token tip in `lib/hints.ts`, are replaced with: "Only
  you and this peer can compute this token. The relay sees it; a connection
  on it is accepted only from this peer's key."
- `lib/P2PFallbackDialog.svelte`: the relay token input accepts 64 hex
  characters.
- Regenerate the Wails bindings.

This closes the token part of BUS-21.

### 14.4 TUI

`cmd/tui`, commit prefix `tui:`. The TUI uses random tokens only.

- The relay dial (RFC009's `relayconn.Dial` on an `Address`) passes
  `relayconn.WithToken(tok)`.
- `relayclient.go`: `relayDial` parses the token with
  `rendezvous.ParseToken` instead of `hex.DecodeString`, and maps
  `ErrTokenFormat` to "tokens are 64 hex characters".
- `welcome.go`: the placeholder "Token (hex)" becomes "Token (64 hex)".
- `relayserver.go`: `result.Token` is a `rendezvous.Token`, shown with
  `Reveal()` (relay-assigned, random).
- `tea.go`: drop the `receiveLoop` comment about bus and the daemon sending
  `RouteSessionData` frames to set up relay tokens.

## 15. Constants and Labels

| Item | Value | Used by |
| --- | --- | --- |
| `PairSecret` salt | `kamune/pair/v1` | relay and broker static tokens, `PunchKey` |
| Expand info prefix | `kamune/rendezvous/v1` | purposes `relay-static`, `broker-static`, `relay-reconnect`, `p2p-punch` |
| Hash labels | `kamune/service-id/v1`, `kamune/token-handle/v1` | `NewServiceID`, `Handle` |
| Exporter label | `kamune/relay-reconnect` | RFC007's exporter, this RFC's only use |
| Token size | 32 B on every wire (`rendezvous.TokenSize`) | `checkRegisteredToken` (RFC009), relay `CheckWire`, `DeriveRID` input (RFC011) |
| Handle | 12 hex characters (48 bits) | logs, events, UI |
| Reconnect pool | 3 indices (`ReconnectPoolSize`) | both clients |
| Reconnect first-frame watchdog | 10 s | client reconnect dialer |
| Relay dialer grace | 10 s (`dialerGrace`) | relay `SessionManager` |
| Broker match wait | 30 s (RFC011) | static and random P2P dials |
| Relay-leg handshake | 30 s (RFC009) | `Register` and `Refused` travel inside it |
| Session meta `relay_reconnect` | 32-byte reconnect root; other lengths are absent | both clients |
| Session meta `relay_tokens` | removed; ignored if present | none |

No other RFC uses these strings for another purpose. RFC007 reserves a second
`PairSecret` salt, `kamune/2 contact tag` (RFC007 sections 12.6 and 25.1),
for the contact-only listeners now left to a future RFC; a different salt
gives an independent PRK from the same DH.

## 16. Test Plan

All tests use `a := require.New(t)`.

### 16.1 Unit: `pkg/attest`

- `edToX25519Public(pk)` equals the public key of
  `ecdh.X25519().NewPrivateKey(SHA-512(seed)[0:32])` for 1000 random keys.
- `a.PairSecret(B, s) == b.PairSecret(A, s)`; different salts differ.
- Rejected peers (table): identity point `01 00..00`, a small-order point,
  non-canonical `y >= p`, wrong PKIX algorithm, a 31-byte raw key, own key
  (`ErrSameKey`). Salts `""` and `"x/"` are rejected.

### 16.2 Unit: `pkg/rendezvous`

- The known answers of section 7.9, including the 75-byte info.
- Direction: `ListenToken` of (A, B) equals `DialToken` of (B, A) and
  differs from `ListenToken` of (B, A); the same for `Broker`.
- Separation table, all pairwise distinct: relay vs broker, svc1 vs svc2,
  both directions, pair (A, B) vs (A, C), reconnect indices 0, 1 and 2,
  reconnect vs static under one svc.
- Public data cannot reproduce a token: `SHA256(lo‖hi)`, `SHA256(lo‖hi)[:16]`
  padded, and HKDF over `lo‖hi` without `dh` all differ from every token.
- `ErrSamePeer`; `ErrInvalidKey` passes through.
- `CheckWire`: 0, 16, 31, 33 bytes and 32 zeros rejected; `00 01 .. 1f`
  accepted (the entropy heuristic is gone on purpose).
- `ParseToken`: round trip with `Reveal`; uppercase accepted; surrounding
  spaces and newline trimmed; an inner space, a `0x` prefix, 32 and 63 hex
  digits, and all-zero rejected.
- Redaction: for a derived and a random token, `fmt.Sprint`, `%v`, `%s`,
  `%x`, `%#v`, `%d`, the `slog` text and JSON handlers with `slog.Any`, and
  `json.Marshal` of a struct holding a `Token` contain neither the 64-hex
  form nor any 12-character window of it, and do contain the handle.
- `Reveal` on a derived token returns `ErrDerivedToken`.
- `ReconnectRoot` with a fake `Exporter`: label `kamune/relay-reconnect`,
  context nil, length 32; `ReconnectRootFromBytes` rejects 31 and 33 bytes
  and zero.
- `Handle` is 12 hex characters and is not a prefix of the hex.

### 16.3 Unit: `pkg/relayconn`

With an in-process relay, as the existing tests use:

- `WithPair` on `Listen`: the `TokenFunc` receives the svc of the relay key
  RFC009's handshake authenticated; the relay sees `ListenToken(Relay, svc)`.
- `Listen` with no token gets a 32-byte random token; a fake relay answering
  16 bytes fails with `ErrInvalidRelayToken`.
- `Dial` without a token returns `ErrNoToken`; two token options return
  `ErrTokenOptions`; both without connecting (counting dialer).
- A `TokenFunc` that returns an error, and one that returns a zero `Token`:
  the fake relay counts zero `Register` records and the channel closes.
- A relay that fails RFC009's authentication: the `TokenFunc` counter stays
  at 0.
- `Refused` mapping, one case per reason, plus `REASON_UNSPECIFIED`, value 42
  (`ErrRefused`), and `Refused` after `Registered` (`ErrBadMessage`).
- `AllowPeer`: a conn from `WithExpectedPeer(B)` allows B and rejects C; a
  conn without it allows any key.

### 16.4 Unit: root `kamune`

- `ExpectPeer` with the handshake: a server over a constrained conn with an
  accept-all verifier rejects identity C with `ErrPeerKeyMismatch`, and the
  verifier is never called (counter). The same on the dialer side.

### 16.5 Unit: `cmd/relay/internal/services`

- `Create` returns 32 bytes; `CreateWith` and `Join` reject 16, 31, 33 bytes
  and zero, and accept any other 32 bytes.
- Silent dialer: join, leave without a `Message`: the session is still
  listed, the listener channel is open, and a second `Join` succeeds. Join,
  stay silent 11 s (the `now` hook of section 13): a second `Join` replaces
  it and the first channel is closed. Join, forward one `Message`, leave:
  the session is removed as today.

### 16.6 Unit: `cmd/relay/internal/handlers`

- One `Refused` reason per `SessionManager` error, then close; `MODE_JOIN`
  with an empty token gets `TOKEN_INVALID`; `MODE_UNSPECIFIED` gets
  `BAD_REGISTER`.
- The log line of a refused registration is at debug and holds no token
  bytes.

### 16.7 Client tests

- Daemon log test: `generate_relay_token` with `peer_pub_b64`; capture
  stderr, `get_logs` and the `relay_tokens` and `relay_token` events; the
  derived token's hex appears in none of them, and its handle appears.
- Daemon `generate_relay_token` twice for one peer: one entry, the same `id`.
- Daemon `dial` with `token` and `peer_pub_b64`: `invalid_params`.
- Daemon `get_share_info` with only static entries (relay and p2p): no token
  and no handle in the result; p2p returns `p2p_token_required`.
- Static listener re-registration: end a session while the relay holds the
  token for 2 s more (a test hook delays `Leave`); the listener reports
  `waiting`, retries, and is `active` again.
- Bus `StartServer` with a malformed `peerPubB64`: error `invalid_peer_key`,
  and the test relay sees no `Register`.
- Bus Wails `relay-token` event for a static entry has no `token` field.
- Reconnect after a cold fallback (`DialWithResume` returns
  `Resumed() == false`): the old session's `relay_reconnect` meta is deleted
  and the loop uses the new session ID.
- Storage: a store with a leftover `relay_tokens` meta opens, and the meta is
  ignored; a `relay_reconnect` value of 31 bytes is treated as absent.

### 16.8 Negative integration tests

In the relay module's `handlers` package:

- Squat: A listens with `WithPair`; identity C, which knows both public keys,
  sends `MODE_JOIN` and `MODE_CREATE` with `SHA256(lo‖hi)` and both HKDF
  variants without `dh`. The joins get `TOKEN_NOT_FOUND`, the creates
  register unrelated sessions, and B's dial still reaches A.
- Malicious relay: the test reads A's listen token (it holds `pkAB`, as a
  relay that logged `Register` would) and dials it as identity C, with an
  accept-all verifier on A. A's handshake fails with `ErrPeerKeyMismatch` and
  A's verifier is not called. Mirror case: C listens on B's dial token; B's
  dial fails with `ErrPeerKeyMismatch` before B sends its identity.
- Cross-relay: a token derived for relay R1 used at R2 gets
  `TOKEN_NOT_FOUND`.
- Both directions: A listens for B and B listens for A on one relay at the
  same time; both registrations succeed; A's `WithPair` dial reaches B's
  listener (the handshake peer is B), not its own.
- Stale reconnect index: index 0 is held by a silent fake listener and the
  real listener is on index 1; the dialer gives up on index 0 when the
  first-frame watchdog fires and resumes on index 1.
- Broker (in RFC011's `brokertest`, owned jointly with RFC011): a third party
  registering `SHA256(lo‖hi)` in 16- or 32-byte form gets no match; two
  listeners of one pair (both directions) hold separate slots across ten
  refreshes; A's `DIAL` never matches A's own `LISTEN`.

### 16.9 End-to-end test

The test lives in `cmd/relay/internal/handlers/tokens_e2e_test.go` and
follows the pattern of `frame_size_test.go`, which runs kamune servers and
dialers over a real relay: `startTestRelay` runs the relay's hub and its TCP,
TLS and WebSocket handlers on loopback listeners, and `openTestStorage` opens
each peer's store in `t.TempDir()`. `startTestRelay` leaves `session_ttl` at
0; no step depends on a timer.

1. Start the relay with a generated static key (RFC009's API) on loopback,
   through `startTestRelay`.
2. Identities A, B and C with `attest.New`, storage from `openTestStorage`.
3. A: `relayconn.Listen(ctx, addr, WithPair(pkAB))` wrapped in
   `kamune.ServeWithListener`, with an accept-all verifier. B:
   `relayconn.Dial(ctx, addr, WithPair(pkBA))` through `kamune.NewDialer`
   with `DialWithPeerKey(A)`. One message each way.
4. Both compute `NewReconnectRoot(t)`; assert they are equal.
5. The test closes B's `RelayConn`. A registers again with
   `root.Funcs()[0]` on a new `kamune.Server` over the same storage (a
   `RelayListener` yields one conn). B dials with the root funcs and
   `DialWithResume`. One message; assert `t.Resumed()` and a new root that
   differs from the old one.
6. C tries `MODE_JOIN` with every token it can compute from public data while
   A listens again with `WithPair`; all get `TOKEN_NOT_FOUND`, and B's next
   dial still reaches A.

Steps 4 and 5 need RFC007's exporter and land with the reconnect commits;
steps 1 to 3 and 6 land with the switch.

### 16.10 Cross-RFC tests

RFC007 owns the cross-RFC run of RFC006, which uses this RFC's pieces: a relay
with a generated key and access key; listener and dialer with `WithPair`;
RFC007's handshake with `DialWithPeerKey` and the conn's `PeerConstraint`;
Strict verifiers on both sides; a reconnect through reconnect index 0 with the
first-frame watchdog, checking that the Strict responder is prompted on the
resume without the dialer giving up. A second case on the broker uses RFC011's
`brokertest`, directional broker tokens, RFC008's `ListenUDP`/`DialUDP`, and
`ExpectPeer` on both conns: a third identity handed the pair's broker listen
token registers `RoleListen` before the real listener, the honest dialer
matches it, the UDP path completes, and the handshake fails with
`ErrPeerKeyMismatch` before the dialer sends its identity or any verifier runs.

## 17. Documentation Changes

Prefix `docs:`, one commit per file.

- `docs/RELAY.md` (gets the derivation; SPEC does not):
  - "What the Relay Observes" (the "Persistent identifier" and "Social
    graph" rows and the static-token paragraph under the table) and "What a
    Compromised Relay Can and Cannot Do" (the bullet on computing the pair's
    static token from the two public keys): replace with section 6 of this
    RFC, including the classical-only pair secret and the key-compromise
    scope.
  - "Frame Schema" (`Register` and `Registered` comments, the new `Refused`
    record) and "Connection Flow" (listener and dialer steps): 32-byte tokens
    only.
  - "Token Lifecycle", including "Design decision: 16-byte tokens": one
    32-byte length on every wire. The silent-dialer re-arm goes into "Token
    Lifecycle" and "Session Lifetime".
  - "Go Client": the token-check bullet.
  - "Static Tokens" becomes "Rendezvous Token Derivation" with sections 7.1
    to 7.8 and the vectors; properties G1 to G5; the exact claim: "Only the
    two peers can compute it. The relay it is presented to learns it. A
    connection on it is accepted only from the peer's key." No rotation, and
    why.
  - "ECDH-Derived Relay Tokens" becomes "Reconnect Tokens": exporter
    derivation, no `SessionData` exchange, pool and dialer rules.
  - "Relay Listener Reconnection": drop "ECDH-derived tokens"; describe
    sections 12.1 and 12.4.
  - The broker "Static Tokens": input to RFC011's `RID`, jointly with
    RFC011's rewrite.
- `docs/SPEC.md`: §5.2 use case (remove the `ecdh_pubkey` exchange); one line
  in RFC007's exporter text listing `kamune/relay-reconnect` as a user; the
  `PeerConstraint` step in RFC007's authentication text; §11.3 replaces
  `relay_tokens` with `relay_reconnect`; §13 gains the token size (32
  bytes).
- `docs/DAEMON.md`: `generate_relay_token`, `generate_p2p_token`, `dial`,
  `start_server`, `get_share_info`, every token schema of section 14.2, the
  examples and the `relay_tokens` event (no `token` for static entries;
  `id`, `handle`, `status`), and the new error codes. Remove "via ECDH";
  state what the token is derived from, who can compute it, and the
  expected-peer rule. This closes DOC-01.
- `cmd/tui/README.md` and `cmd/bus/README.md` where they mention token
  length or static tokens.
- `AGENTS.md`: `pkg/rendezvous` joins the `pkg/` list in the rework's final
  cleanup commit.
- `CHANGELOG.md` is not touched unless the maintainer asks.

Order per document, from RFC006: SPEC after RFC007, RFC008 and RFC009;
RELAY.md after RFC009 and before RFC011 and RFC008; DAEMON.md after RFC009
and RFC011 and before RFC008 and RFC007; `cmd/bus/README.md` and
`cmd/tui/README.md` after RFC009 and before RFC007.

## 18. Implementation Plan

Each line is one commit with a subject of 72 characters or fewer. Numbers
are local to this RFC; dependencies on other RFCs name the RFC.

### 18.1 Root additions

These land first, before the other RFCs' new packages. Additive; each commit
builds and tests green in every module.

| # | Prefix | Change | Depends on |
| --- | --- | --- | --- |
| 1 | `kamune:` | `attest.PairSecret`, conversion helpers, `ErrSameKey`, tests (`pkg/attest/pairsecret.go`) | none |
| 2 | `kamune:` | `pkg/rendezvous` with tests and vectors, including `PunchKey` | 1 |
| 3 | `kamune:` | `PeerConstraint`, `ExpectPeer` (`peerconstraint.go`), `ErrPeerKeyMismatch`, interim check in `verifyPeer` | none |
| 4 | `kamune:` | storage `RelayReconnectKey` | none |

RFC009's `Dial`/`Listen` commit and RFC011's codec commit use
`rendezvous.Token` and `TokenFunc` directly, so they come after commit 2.
RFC007's root switch moves the check of commit 3 into its handshake.

### 18.2 Relay module

After RFC009's relay commits:

| # | Prefix | Change | Depends on |
| --- | --- | --- | --- |
| 5 | `relay:` | 32-byte random tokens, `CheckWire` (today's clients accept a 32-byte `Registered` token) | 2 |
| 6 | `relay:` | silent-dialer re-arm in `SessionManager` | none |
| 7 | `relayconn:` | `Refused` in `relay.proto`, regenerated | RFC009 `Dial`/`Listen` |
| 8 | `relay:` | send `Refused`; refusal logs at debug | 7, RFC009's relay-leg switch in the relay |

`relay.proto` is regenerated with `make gen-proto` in each commit that
changes it; the later of this RFC's commit 7 and RFC009's `Auth` removal
rebases and regenerates, never hand-merges. RFC011's relay switch follows
these commits.

### 18.3 Switch

These commits merge as one unit. The root module's tests pass at every
commit; the sub-modules build again at the last commit of the unit, as RFC009
does for its own switch.

| # | Prefix | Change | Depends on |
| --- | --- | --- | --- |
| 9 | `relayconn:` | `WithExpectedPeer`, `WithPair`, `AllowPeer`, `Refused` mapping and sentinels, `ListenResult.Token` as `rendezvous.Token`, 32-byte only | 2, 3, 7, RFC009 `Dial`/`Listen` |
| 10 | `daemon:` | static relay and p2p through `PairKey`, `dial` and `start_server`, ids, `ExpectPeer` wrapping, schemas | 9 |
| 11 | `daemon:` | handles in logs and events | 10 |
| 12 | `bus:` | the same Go changes, fail-closed `StartServer` | 9 |
| 13 | `bus:` | frontend and Wails bindings | 12 |
| 14 | `tui:` | section 14.4 | 9 |

Commit 9 touches no root file and may land before RFC007's root switch.
Within each client file the order across RFCs is: RFC009's client commits,
RFC011's, this RFC's 10 to 14, RFC008's, this RFC's 15 and 16, then RFC007's
client commits. RFC007's compile fixes for the new `RemoteVerifier` land with
its root switch, before 15 and 16. Each RFC's schema edits sit in its own
client commit; this RFC rebases onto RFC011's schema edits.

### 18.4 Reconnect

After RFC007's root switch, which provides the exporter:

| # | Prefix | Change | Depends on |
| --- | --- | --- | --- |
| 15 | `daemon:` | reconnect roots from the exporter, section 12.4 | RFC007, 4, 9 |
| 16 | `bus:` | the same | RFC007, 4, 9 |

### 18.5 Deletions, end-to-end test, docs

| # | Prefix | Change | Depends on |
| --- | --- | --- | --- |
| 17 | `relayconn:` | delete `TokenFromKeys`, `ValidateUserToken`, the `SessionData` exchange and the old constants | 10 to 16 |
| 18 | `kamune:` | storage: drop `RelayTokensKey` | 15, 16 |
| 19 | `relay:` | end-to-end test (steps 1 to 3 and 6 may land after 14) | 9, 15 |
| 20 | `docs:` | section 17, one commit per file | all |

RFC007's storage cleanup comes after 17 and 18. The rework's final
`kamune: delete pkg/exchange` commit comes after RFC007's root switch,
RFC009's helper removal, RFC011's relay switch and v1 removal, and commit
17. RFC011's broker client takes `rendezvous.Token` in RFC011's own commits.

## 19. Compatibility

The change is a wire-incompatible hard cut. It lands with RFC007, RFC009 and
RFC011, which change the peer handshake, the relay leg and the broker wire,
so no peer, relay or broker from before the rework interoperates with one
after it. Within this RFC:

- a relay-assigned token of 16 bytes fails `checkRegisteredToken` with
  `ErrInvalidRelayToken`, and the relay refuses any token that is not 32
  non-zero bytes (`Refused TOKEN_INVALID`);
- a 32-hex-character token pasted by a user fails `ParseToken` with
  `ErrTokenFormat`;
- a stored `relay_tokens` meta is ignored and pruned with its session;
- static tokens change value; both peers derive the new ones from the keys
  they already hold.

## 20. Findings

From `docs/RED_TEAM_REVIEW.md`:

| Finding | Status | Notes |
| --- | --- | --- |
| RC-04 | Closed, jointly with RFC011 | Third-party squatting: secret directional tokens (7.2 to 7.5). Identity behind a learned token: G5 (7.7). Relay teardown and holding by a silent dialer: section 13. Broker address leak to a passive observer: RFC011 (the token never leaves the client) |
| RC-18 | Closed, needs RFC007 | The raw-X25519 PRK code is deleted; reconnect tokens come from RFC007's exporter (7.6) |
| RC-07 | Closed, jointly with RFC011 | This RFC makes every token 32 bytes and removes the client-side compare of a notified token; RFC011 removes truncation (`RID`) and owns the 30 s match wait |
| DOC-01 | Closed | DAEMON.md and code comments state the real derivation and the expected-peer rule, which ships with it (G5) |
| BUS-21 | Partly closed | Token part: handle-only logging and `Token` formatting. Exported log file permissions are not addressed here |
| DMN-11 | Partly closed | Token part: handle-only logging and `Token` formatting. Exported log file permissions and line injection through peer names are not addressed here |
| BUS-03, DMN-07 | Not closed here | Owned and closed by RFC011: `RemoveP2PToken` calls `Registration.Close` |

Touched but not claimed. The implementer checks these after the change and
records the result:

| Finding | Why it may close |
| --- | --- |
| RC-19, RC-20 | `ValidateUserToken` is deleted; token size and comments are rewritten |
| BUS-34, DMN-33 | Static derivation fails closed with `invalid_peer_key`; the current code already fails closed on both paths |
| DMN-37 | `deriveAndStoreRelayTokensForPeers` is already gone from the current code |
| DMN-09, BUS-16 | The reconnect pool is replaced by exporter roots and the rules of 12.4; the current clients already register each stored token once |
| TUI-15 | The `SessionData` `ecdh_pubkey` exchange is deleted; the TUI already drops `SessionData` frames |
| BUS-01 | With RFC007: `PeerConstraint` on every pair rendezvous rejects the keys the bus gate rejects, before the verifier; `DialWithPeerKey` on dials with a known key. Whether the bus gate stays is open (section 22) |

## 21. Deferred

- **Rotation of static tokens.** Not in v1 (section 4.4). Rotation protected
  only against the service operator linking one pair's registrations over
  days, which source IP and timing already allow. It cost a clock
  dependency: peers whose clocks differ by more than the overlap window fail
  to meet near each rotation boundary, every day. It also needed overlap
  listeners and match dedupe. A leaked token (relay logs) can be squatted at
  that relay for denial of service until the relay key changes; G5 stops it
  from being used for anything else. `n` in `info` is reserved, so rotation
  or a manual re-key counter can return without a layout change, preferably
  with the epoch taken from the authenticated relay rather than from local
  clocks.
- **Post-quantum pair secret.** Mixing a stored per-peer PSK (from a session
  exporter) into `PRK_pair` would make static tokens post-quantum, but if one
  side loses the PSK (reinstall, deleted peer) the two sides derive different
  tokens with no way to notice. Deferred until a peer-state sync exists.
- **Constant-time token lookup** on the relay: map lookup timing leaks bits
  only to an attacker already probing that relay with guessed tokens.
- **Merging reconnect and static tokens.** With secret, relay-bound static
  tokens, the reconnect pool still adds per-session freshness and works for
  random sessions that have no pair key. Both are kept.
- **Listener confirmation of a pairing** (the last suggestion in RC-04). G5
  and the silent-dialer re-arm cover the cases an attacker other than the
  relay can reach.

## 22. Open Questions

1. The bus already rejects a wrong key on its static relay and broker
   listeners through an application-level gate (`peerGate`, `peerKeySet`,
   `pinRelayListener`, `admittedBy`) that runs after the verifier. With
   `PeerConstraint` the same keys are rejected before the verifier. Do the
   bus commits delete the gate, or keep it as a second check?
2. Bus `ConnectToServer` accepts a relay token together with a peer: it dials
   the token and pins the peer through `pinPeer` (`relayDialToken`). This RFC
   makes the daemon's `dial` reject `token` with `peer_pub_b64` as
   `invalid_params`. Should the bus reject the combination too, or should
   both clients accept it as `WithToken` plus `WithExpectedPeer`?
