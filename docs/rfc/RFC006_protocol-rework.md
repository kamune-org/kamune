# RFC: Protocol Rework Before v1.0 (Overview)

**Status:** Draft

**Target:** Kamune Protocol Specification before v1.0 (not scheduled)

**Relates to:** §2 (Terminology), §3 (Cipher Suite), §5 (Routes), §6 (Protocol
Flow), §7 (Encryption and Key Derivation), §8 (Message Integrity and Replay
Protection), §9 (Transport Layer), §10 (Endpoint Roles), §11 (Storage and
Persistence), §12 (Security Properties), §13 (Constants and Limits), §14 (Error
Conditions); RELAY.md (all sections); RFC001, RFC002, RFC003, RFC004, RFC005

---

## 1. Summary

This RFC is the overview of five RFCs that replace every exchange that runs
before two peers share an established session, and the relay and broker
protocols around them:

| RFC    | Part              | Replaces | With |
| ------ | ----------------- | -------- | ---- |
| RFC007 | Peer handshake v2 | Exchange, Introduction, Handshake, Challenge, `ResumeRequest`/`ResumeAccept`, the 20-token resumption set | One 2-round-trip SIGMA-I handshake over a single X-Wing (ML-KEM-768 + X25519) HPKE encapsulation; one SHA-512 transcript under both signatures and three Finished MACs; resumption as a PSK with a binder; the verifier on every handshake; two labelled 40-digit verification codes; a session exporter |
| RFC008 | UDP path layer    | kcp-go's `Listener` and unauthenticated KCP packets | `internal/udppath`: a stateless cookie (return routability), ephemeral X25519 path keys, ChaCha20-Poly1305 on every KCP packet with a 2,048-packet replay window, an authenticated CLOSE, an optional knock key; per-source, per-network and global handshake rate limits (`internal/admit`) |
| RFC009 | Relay leg v2      | The unauthenticated HPKE exchange between client and relay, and the relay password sent in an `Auth` frame | A relay static X25519 key (`rk1-...`) that clients pin; the `relayleg` v2 handshake (HPKE DHKEM to the static key plus an X-Wing ephemeral, TLS 1.3 style key schedule, PSK binder, `finished_r`); generated access keys (`psk1-...`); one relay address parser and a relay key store |
| RFC010 | Rendezvous tokens | Static tokens equal to the SHA-256 of both public keys, reconnect tokens from a raw X25519 output, 16-byte and 32-byte tokens | A pair secret from X25519 between the two converted Ed25519 identity keys; directional tokens bound to the service key; the expected-peer check (`PeerConstraint`); reconnect tokens from RFC007's exporter; 32-byte tokens on every wire; a `Refused` relay record |
| RFC011 | Broker v2         | STUN-style echo, a REGISTER carrying a 16-byte token in the clear, NOTIFY sealed under anonymous ECDH | A REGISTER sealed to the relay static key and bound to a cookie (source address and client ephemeral); a downlink sealed under `K_DOWN`; a registry ordered by broker-minted sequence numbers; one `Endpoint` per punch socket, shared with RFC008 |

Each of the five is a wire-incompatible hard cut, as RFC004 is. No backward
compatibility is kept: the peer wire protocol, the UDP, relay-leg and broker
wire formats, the on-disk resumption and token formats, the relay
configuration, the daemon JSON API and the exported Go APIs all change. A v1
peer, relay or broker drops or refuses v2 traffic, and the reverse.
`kamune.AppVersion` becomes `0.8.0` in RFC007's switch commit, so logs and
share data show which peers speak v2.

This RFC holds what crosses the five parts: the findings they close, how the
parts fit together, the decisions, the shared constants and domain-separation
labels, the interfaces between parts, the client changes, the cross-RFC tests,
the implementation order, the documentation plan and the open questions. Wire
formats, key schedules, state machines, error tables and per-part tests are in
RFC007 to RFC011.

## 2. Current Behavior

**Peer handshake** (SPEC §6.1 to §6.4). Dialer and server run an ephemeral
HPKE exchange (`exchange.Initiate` and `exchange.Accept` in `pkg/exchange`) in
which no long-term key takes part. Inside it the initiator sends a signed
`Introduce{Name, PublicKey, AppVersion}`; the responder checks the version,
runs the `RemoteVerifier` and answers with its own Introduce
(`Server.handleNewConnection`). ML-KEM-768 then runs inside the tunnel
(`requestHandshake`, `acceptHandshake`), and the Challenge is the first use of
the session keys. `RemoteVerifier` is
`func(store *storage.Storage, peer *storage.Peer) error`.

**Resumption** (SPEC §6.8). A session stores 20 single-use tokens in the
`resumption_tokens` meta. A `ResumeRequest{SessionID, Token}` signed by the
initiator takes the place of the Introduction. `Server.handleResume` checks the
token length, the stored peer, the signature and a 24 h window counted from
`established_at`, which only a cold handshake writes. With resumption enabled
it answers every request with a signed `ResumeAccept` (`rejectResume` for a
refusal, including a refusal for a bad signature), and the verifier does not
run for a resumed session.

**UDP** (SPEC §9.2). `ServeWithUDP` runs `kcp.Listen` on the server address
and `DialWithUDP` runs `kcp.Dial`. KCP packets carry no authentication and FEC
is off; kcp-go creates a session for the first parsable datagram from a new
address. The bus's plain UDP server uses `ServeWithUDP`; the daemon's tcp and
udp servers bind the socket themselves to learn the bound address
(`listenDirect` in `cmd/daemon/network.go` calls `kcp.Listen` for udp and
wraps the listener in `boundListener`, served through `ServeWithListener`).
The bus and daemon P2P code runs `kcp.ServeConn` and `kcp.NewConn4` on its
punch sockets, and the bus's cancellable UDP dial (`dialUDP` in
`dialattempt.go`) calls `kcp.Dial` itself.

**Relay leg** (SPEC §9.3, RELAY.md "Protocol" and "Authentication Modes").
`relayconn` runs `exchange.Initiate` against the relay's `exchange.Accept`; the
relay has no long-term key. With a relay password the client sends it in an
`Auth` frame (`pb.Frame` field 6), then `Register`. A relay-generated token is
16 bytes, a listener-chosen one 32 bytes. Clients can add TLS (wss, tls) and
pin the relay certificate: `relayconn` pinning, the bus `?pin=` address
parameter, the daemon `relay_pin` field and the TUI fingerprint field.

**Tokens** (RELAY.md "Static Tokens" and "ECDH-Derived Relay Tokens"). A static
token is `relayconn.TokenFromKeys`: the SHA-256 of the two Ed25519 public keys
in byte order, which anyone who knows both keys can compute. Relay reconnect
tokens come from a `RouteSessionData` exchange of `ecdh_pubkey` values
(`BeginRelayTokenExchange`, `CompleteRelayTokenPayload`) and an `HKDF-Expand`
over the raw X25519 output (`RelayTokenPending.Complete`).

**Broker** (RELAY.md "Broker: STUN-Echo and Signal Introduction"). Clients send
`STUN_ECHO` and a 60-byte REGISTER that carries a 16-byte token (`WireToken`
cuts a 32-byte token to 16) and the client's X25519 public key in the clear.
The broker answers a match or a token assignment with a NOTIFY sealed under
ECDH between a fresh broker ephemeral and that public key (`Broker.sendNotify`);
nothing in it authenticates the broker. The bus holds one X25519 broker key per
process, the daemon one per registered token.

## 3. Motivation

The red-team review (`docs/RED_TEAM_REVIEW.md`, commit `36b6e1c`) confirmed
218 findings. It found no way for a network attacker, the relay operator or a
third party to decrypt or forge messages between two peers whose keys match
what they verified. The medium findings this rework takes up sit in the
exchanges before a session exists: the HPKE exchange is unauthenticated
(KAM-02, RC-03), the 8-emoji fingerprint carries 52.7 bits (KAM-03), Strict
mode does not prompt on resumed sessions (KAM-08), static tokens can be
computed from public keys (RC-04), and broker NOTIFYs carry no origin
authentication (RC-05). Fixes made since the review closed many client
findings and documented the protocol ones; the protocol ones need the wire
changes of RFC007 to RFC011.

Each table lists the findings one RFC claims. "Current code" is the state on
`main` with the bus fixes; "After" is the state once the RFC is implemented.
Severities are the review's.

### 3.1 RFC007: peer handshake

| ID     | Sev.   | Finding | Current code | After |
| ------ | ------ | ------- | ------------ | ----- |
| KAM-01 | Medium | Introduce, ResumeRequest and ResumeAccept have no nonce, freshness or channel binding and replay across connections; the verifier runs before key confirmation | Protocol unchanged; bus, daemon and TUI store a peer only once its session is established | Closed |
| KAM-02 | Medium | The unauthenticated HPKE Exchange lets an active relay or on-path attacker read both identities, session IDs and resumption tokens | Documented, unchanged | Closed |
| KAM-03 | Medium | The 8-emoji fingerprint, the documented verification method, has 52.7 bits of second-preimage resistance | `fingerprint.Numeric` (132.9 bits) exists and all three clients show it on verify prompts, next to the emoji | Closed |
| KAM-08 | Medium | Resumption skips the `RemoteVerifier`, so Strict mode does not prompt for resumed sessions | Documented; the TUI flags resumed sessions | Closed |
| KAM-10 | Low    | The server signs a ResumeAccept for any unauthenticated client, an identity-confirmation oracle | Unchanged | **Partly closed**: the resume oracle is gone; listener key exposure to probers, larger than today for Quick and Strict listeners, is accepted (section 5.1, decision 3) |
| KAM-15 | Low    | A lost final challenge echo desynchronises the resumption token sets | Unchanged | Closed |
| KAM-26 | Info   | The pseudonym is listed as a fingerprint format with 29.6 bits and wrong counts | Size corrected; the pseudonym is marked as a nickname | Closed (verify prompts label it a nickname and keep the self-asserted name outside the code area) |
| KAM-27 | Info   | The Challenge receiver never recomputes the challenge | SPEC describes the Challenge as key confirmation only | Closed (Challenge removed; every Finished MAC is checked) |
| KAM-28 | Info   | The resumption window never resets on resume | SPEC states that the window counts from the cold handshake | Closed (24 h sliding idle window, 7-day maximum age) |
| KAM-31 | Info   | Handshake, transport and storage failure paths have no tests | Failure-path tests and raw-byte fuzzers added | **Partly closed** (handshake, resume, AEAD, duplicate and signature failure paths of the new code) |
| KAM-32 | Info   | Resume rejection tests reimplement server logic | Tests drive `Server.serve` | Closed (the resume tests of RFC007 drive `Server.serve`) |

Regression tests are kept for findings the rewrite could reopen, all fixed on
the current code: KAM-07 (a late verifier accept is a rejection), KAM-16 (a
close never re-creates a deleted session namespace), KAM-22 (peer name limits)
and KAM-23 (small-order identity keys).

### 3.2 RFC008: UDP path layer

| ID     | Sev.   | Finding | Current code | After |
| ------ | ------ | ------- | ------------ | ----- |
| KAM-11 | Low    | KCP runs with no FEC and no packet authentication; spoofed UDP creates pre-auth sessions and resets live ones | SPEC §9.2 no longer claims FEC; code unchanged | Closed |
| KAM-05 | Medium | No accept backoff and no cap on pre-auth connections doing KEM work | Accept backoff, pending caps and a per-source cap; forged UDP sources still take waiting slots, and KEM work is not rate-limited | Closed |

### 3.3 RFC009: relay leg

| ID     | Sev.   | Finding | Current code | After |
| ------ | ------ | ------- | ------------ | ----- |
| RC-03  | Medium | The relay PSK and session token go to an unauthenticated HPKE peer, so an active MITM on ws, tcp or unverified TLS captures them | Documented, unchanged | Closed |
| REL-02 | Medium | Default TLS and WSS certificates were regenerated per process and could not be pinned | The certificate is kept in `data_dir` and logged; `relayconn`, bus, daemon and TUI can pin it | Closed (the pin becomes `cert=` in the shared parser; TLS 1.3 minimum; `tls=skip` never yields a relay key without the user) |
| DMN-10 | Low    | A relay address without a scheme defaults to plaintext ws | Defaults to wss and warns on plaintext; the relay is authenticated only by TLS | Closed |
| BUS-36 | Low    | Imported URLs set Skip TLS verification and default to plain ws | Fixed | Closed (`insecure` no longer exists; an imported `rk` never overwrites a pin) |
| BUS-29 | Low    | The P2P relay fallback referenced an undeclared `useRelayPassword` | Fixed | Closed (the dialog is rewritten to the `RelayOptions` call) |
| RC-14  | Low    | The dial and listen context also bounds the session lifetime | Fixed | Kept; tests ported |
| RC-17  | Low    | Listen and dial accept any `Registered` token | Fixed (`checkRegisteredToken`) | Kept; tests ported |

### 3.4 RFC010: rendezvous tokens

| ID             | Sev.   | Finding | Current code | After |
| -------------- | ------ | ------- | ------------ | ----- |
| RC-04          | Medium | Static relay and P2P tokens are the SHA-256 of both public keys; anyone who knows the keys can squat relay sessions or take the broker match and learn the listener's address | Documented, unchanged | Closed, with RFC011 for the broker wire |
| RC-18          | Info   | ECDH reconnect tokens skip HKDF-Extract and bind no session or identity context | Unchanged | Closed |
| RC-07          | Medium | Static-token broker P2P never matched: tokens cut to 16 bytes on the wire but compared at 32 | Clients compare at wire size (`TokenMatches`) | Closed with RFC011 (32 bytes on every wire; no client-side compare) |
| DOC-01         | Medium | DAEMON.md says static tokens are ECDH-derived and peer-exclusive | Unchanged | Closed (DAEMON.md and code comments state the derivation and the expected-peer rule) |
| BUS-21, DMN-11 | Low    | Relay and P2P tokens are written to logs and exported log files | Logs show an 8-hex-character prefix; exports are readable by their owner only | **Partly closed**: the token parts (logs show only a 12-hex-character handle hashed from the token); exported log files are not addressed |

### 3.5 RFC011: broker

| ID             | Sev.        | Finding | Current code | After |
| -------------- | ----------- | ------- | ------------ | ----- |
| RC-05          | Medium      | Broker NOTIFY has no origin authentication; anyone who knows the client's X25519 public key can forge or replay PEER_MATCHED | Documented, unchanged | Closed |
| REL-06         | Medium      | Spoofed random-mode REGISTERs fill the registry; when full, each REGISTER scans the whole map | No full scan; spoofed REGISTERs still create entries | Closed |
| REL-07         | Medium      | The broker shared the relay's per-IP limiter, so spoofed UDP locked a victim IP out of TCP, TLS and WS | The broker has its own limiters, still keyed by unverified sources | Closed (buckets keyed by cookie-verified sources) |
| REL-12         | Low         | The broker rebinds a held registration to any source that repeats the public key | Rebinds once the old address goes quiet, or at once on a port-only change | Closed |
| REL-15         | Low         | X25519 work and larger replies for unverified sources | Documented, unchanged | Closed |
| RC-11          | Low         | `Client.Listen` binds 127.0.0.1 and is never the REGISTER source | Rendezvous runs on a caller-owned socket | Closed (one `Endpoint` per socket) |
| RC-12          | Low         | `Register` and `Echo` use throwaway sockets and lose an immediate PEER_MATCHED | Fixed | Closed |
| DMN-12         | Low         | One process-lifetime X25519 broker key makes random P2P tokens linkable | Daemon: one key per token; bus: one key per process | Closed (fresh ephemeral per REGISTER; no client clock on the wire) |
| DMN-14         | Low         | The P2P dial waits for a match with no timeout | Fixed | Closed (30 s match wait) |
| DMN-07, BUS-03 | Medium      | Removing a P2P token does not stop its re-registration | Fixed | Closed (`Registration.Close` stops the refresh and sends WITHDRAW) |
| DMN-18, BUS-23 | Low         | Token generation without a listener registers from a throwaway socket | Fixed | Closed |
| DMN-21, BUS-06 | Low, Medium | The P2P listener never processes PEER_MATCHED and never punches toward the dialer | Fixed | **Partly closed** (broker part); KCP source filtering is RFC008's |
| BUS-35         | Low         | `echoFrom` takes the first datagram from any source as the echo reply | Fixed | Closed (no echo; a downlink is accepted only from the broker address and only if it authenticates) |
| BUS-41         | Low         | Random P2P token generation returns the same token | Fixed | Closed |
| BUS-27         | Low         | Binding defects, `RegisterP2PDialer` among them | `RegisterP2PDialer` removed | **Partly closed** (`RegisterP2PDialer` part) |
| DOC-02         | Low         | RELAY.md says the broker echoes the claimed address | Fixed | Closed (kept by RFC011's doc pass) |
| DOC-10         | Info        | DAEMON.md P2P examples use `wss://` broker addresses | Unchanged | Closed |

RFC011 also closes the passive-observer part of RC-04: the token never leaves
the client, and a REGISTER carries only a `RID` inside the AEAD.

### 3.6 Findings in rewritten code that no RFC claims

These findings sit in code the RFCs rewrite. The implementer keeps the current
fix and its tests, and checks the result after the rewrite rather than
assuming it.

| ID              | Sev.   | Current code | Where the rework meets it |
| --------------- | ------ | ------------ | ------------------------- |
| BUS-01          | High   | Bus: dials pin the selected peer's key in the verifier (`pinPeer`), sessions on a pair token from another key are dropped (`peergate.go`), peers are named by their stored name. Daemon: unchanged | RFC007: the Quick initiator accepts only pinned keys, `DialWithPeerKey` on peer-list dials (superseding `pinPeer`). RFC010: `PeerConstraint` on pair rendezvous. Both reject the same keys before the verifier; whether the bus keeps its listener gate (`peergate.go`, `pinRelayListener`, `admittedBy`) as a second check is open question 5 |
| BUS-15, DMN-03  | Medium | Bus queues prompts under a cap; the daemon caps inbound prompts and allows one per key | RFC007 client limits: one open prompt per client, 6 prompts per rolling minute |
| KAM-17          | Low    | `Transport.Close` invalidates the session's tokens | RFC007: a local `Close` deletes the resumption state of its generation |
| KAM-20          | Low    | Idle sessions per peer capped at 8 (`storage.WithIdleSessionLimit`) | RFC007: `Storage.SweepSessions` at server start and every hour |
| TUI-19          | Low    | The TUI closes the transport before it releases the server handler | RFC007: state survives only network-caused ends |
| DOC-16          | Info   | SPEC and RFC001 corrected | RFC007 rewrites SPEC §6.8; RFC001 gets a superseded banner |
| BUS-17          | Low    | Bus: the direct-P2P listener takes KCP only from the peer's IP. Daemon: unchanged | RFC008: `UDPWithSourceFilter` and the knock key in both clients |
| DMN-20          | Low    | The daemon sends the whole kick burst before the dial goes on | RFC008: `HolePunch` blocks on `DialUDP`; HELLO retransmissions replace the kicks |
| DOC-05          | Info   | FEC claim removed from SPEC §9.2 | RFC008 rewrites SPEC §9.2; FEC stays off |
| REL-01          | High   | The relay's broker loop survives read errors (`TestRun_SurvivesPacketReadErrors`) | RFC011's loop keeps the v1 read-error backoff; its buffer size is open question 7. RFC008 reads every path-layer socket, and RFC011's `Endpoint` its socket, with the 65,536-byte read rule |
| TUI-08          | Low    | The TUI reaches relays over wss (default), tls, ws or tcp, with a password field | RFC009: `relayconn.Address` and the access key |
| RC-19, RC-20    | Info   | Doc comments and docs corrected | RFC010 deletes `ValidateUserToken` and rewrites the token size text |
| BUS-34, DMN-33  | Low    | Start and token generation fail on an unusable peer key | RFC010: a `NewPairKey` error is `invalid_peer_key`, with no random fallback |
| DMN-37          | Info   | Dead code deleted | none |
| DMN-09, BUS-16  | Medium | Each reconnect token is used once; pools of ended sessions are dropped | RFC010: reconnect roots from the exporter and the reconnect rules |
| TUI-15          | Low    | The TUI shows only `RouteExchangeMessages` frames as chat | RFC010 deletes the SessionData `ecdh_pubkey` exchange |

## 4. How the Parts Fit Together

### 4.1 Layers

```
  bus, daemon, tui
      | RemoteVerifier(ctx, store, VerifyRequest), DialWithPeerKey,
      | ExportKeyingMaterial, rendezvous.PairKey
      v
  RFC007 peer handshake v2  <---- PeerConstraint.AllowPeer (RFC010)
  (end to end over any kamune.Conn; identities, names, versions and
   session ID only under the hybrid KEM)
      |                     |                          |
      | TCP framing         | KCP                      | relay Message records
      |                     v                          v
      |              RFC008 UDP path layer      RFC009 relay leg v2
      |              (cookie, path keys,        (relay static key, PSK binder,
      |               replay window, CLOSE)      finished_r; token in record 0)
      |                     |                          |
      |              punch socket read side     token from RFC010, bound to
      |              owned by RFC011 Endpoint    service_id(relay key)
      |                     |
      |              RFC011 broker v2 (REGISTER sealed to the relay key,
      |              RID from an RFC010 token, authenticated MATCHED)
      v
   TCP socket         UDP socket                 TCP or WebSocket socket
```

RFC007 is the only part that peer authentication and confidentiality rest on.
It runs over any `kamune.Conn`: TCP framing, KCP over an RFC008 path, or relay
`Message` records over an RFC009 channel. RFC008, RFC009 and RFC011 protect
availability, the client-to-relay leg and rendezvous metadata. RFC008 states
that its path keys carry no confidentiality claim and that no layer may rely
on them.

RFC009 gives every relay a long-term X25519 key. Relay clients pin it (`rk=` in
the address or the key store), and broker clients carry it in the broker
address (`udp://host:port?rk=rk1-...`). RFC010 binds tokens to it through
`rendezvous.NewServiceID`, and RFC011 seals broker traffic to it through
`relayleg.PrivateKey.ExtractShared`. A broker in its own process is a relay
with only `[broker]` enabled and its own `data_dir`, so it has its own key.

RFC010 derives the tokens. It needs RFC007's exporter for reconnect roots and
RFC007's handshake to enforce the expected peer: the check runs after the
remote has proved possession of its key and before the verifier, on both
sides, so a token holder cannot put another identity behind a pair
rendezvous. RFC010 also gives RFC008 the direct-P2P knock key
(`PairKey.PunchKey()`).

RFC011's `Endpoint` owns the read side of a punch socket and consumes broker
datagrams. RFC008's path layer runs on `Endpoint.PacketConn()`. The first byte
of a datagram separates them: `0x00` NAT kick, `0x01`-`0x0F` path layer,
`0x10` and above other protocols (broker `"KBRK"` starts with `0x4B`).

### 4.2 Two rendezvous flows across the parts

Static relay rendezvous:

1. Both clients build `rendezvous.NewPairKey(self, peer)` (RFC010).
2. `relayconn.Listen` and `relayconn.Dial` with `WithPair(pk)` run the relay
   leg handshake (RFC009). Once `finished_r` verifies, the `TokenFunc` derives
   `ListenToken(Relay, svc)` or `DialToken(Relay, svc)` with
   `svc = NewServiceID(relayKey)`, and the token goes out as record 0.
3. The relay pairs the two sessions, or answers with `Refused` (RFC010).
4. RFC007 runs over the paired `RelayConn`: the dialer passes
   `DialWithPeerKey(peer)`, and both conns implement `PeerConstraint` for the
   pair's peer key.
5. Both peers store `NewReconnectRoot(t)` under `relay_reconnect` (RFC010);
   the next reconnect uses tokens derived from it, and a resume through them
   runs RFC007's PSK resumption.

Static broker rendezvous:

1. Listener and dialer each open a UDP socket and call
   `broker.Client.NewEndpoint` (RFC011) with a client built from the broker
   address and its `rk=` key.
2. The listener registers `ListenToken(Broker, svc)` as `RoleListen`, the
   dialer `DialToken(Broker, svc)` as `RoleDial`. The broker sees only the
   `RID` derived from the token and the broker key.
3. Both receive an authenticated MATCHED with the other's address. The
   listener kicks `Match.Peer`; the dialer calls `kamune.DialUDP` on
   `Endpoint.PacketConn()` (RFC008), and the listener's
   `kamune.ListenUDP` on its own `PacketConn()` answers.
4. RFC007 runs over the KCP conn, wrapped with `kamune.ExpectPeer`, and the
   dialer passes `DialWithPeerKey`.

### 4.3 Relation to earlier RFCs

- **RFC001** (session resumption, merged): superseded by RFC007's resumption.
  It gets a banner pointing to SPEC §6.8 as rewritten by RFC007.
- **RFC002** (signed metadata, merged): still applies. Session frames keep the
  `SignedTransport` format with per-frame Ed25519 signatures. Introduce and the
  resume messages no longer exist; RFC002 gets a note saying so.
- **RFC003** (sequence replay window, withdrawn): duplicates and gaps stay
  fatal. Under RFC007 they end the session but keep its resumption state,
  because a relay or an on-path attacker can cause them.
- **RFC004** (double ratchet, draft): its initial setup takes `mlkemSecret`,
  both handshake salts and the session-static X25519 keys from the v1
  Handshake, and it uses `pkg/exchange.ECDH`. RFC007 removes those inputs and
  the rework deletes `pkg/exchange`. How RFC004 would start from RFC007's key
  schedule is open (section 12).
- **RFC005** (file transfer, draft): uses `RouteSessionData` and the minor
  version check, which RFC007 keeps.

## 5. Decisions

### 5.1 Maintainer decisions

1. **Not implemented now; hard cut.** The rework is specified, not scheduled.
   RFC006 to RFC011 have Status Draft and target the Kamune Protocol
   Specification before v1.0. Each is a wire-incompatible hard cut with no
   backward compatibility.
2. **Generated relay access keys, no passwords** (RFC009). A relay with access
   control holds a generated 32-byte key, written `psk1-` plus 52 lowercase
   base32 characters and produced by `kamune-relay -gen-psk` or
   `relayleg.GeneratePSK()`. The binder in every ClientHello and `finished_r`
   in every ServerHello let an observer test guesses offline, so a password
   would fall to a dictionary attack. Passwords are not supported; a PAKE
   (CPace, OPAQUE) is not in the dependency set and is deferred. The relay
   config key `password` is removed, and the config loader's unknown-key check
   stops a relay that still has it.
3. **Listener identity exposure is accepted for now** (RFC007). Anyone who can
   deliver a ClientHello to a listener, the relay operator included, learns
   the listener's identity key and gets a fresh signature by it over a
   transcript the prober chose. The listener's name and version are sent only
   after it accepts the initiator. For Quick and Strict listeners this
   exposure is larger than today, where the listener's Introduce follows its
   verifier; in exchange, dialers no longer reveal their identity first.
   RFC007 documents this exposure in SPEC §12 and RELAY.md. Contact-only
   listeners are left for a future RFC; RFC007 keeps the 32-byte `tag` field
   of the ClientHello (random) so that RFC needs no frame layout change, and
   the salt `kamune/2 contact tag` stays reserved for it. KAM-10 is therefore
   partly closed.

### 5.2 Decisions between the parts

Decisions that span two or more RFCs:

| Decision | RFCs |
| -------- | ---- |
| RFC007 runs RFC010's `PeerConstraint` check on both roles, after the remote proved key possession and before the verifier; failure is `ErrPeerKeyMismatch`, and a pass sets `VerifyRequest.Pinned` on the responder too. RFC010's interim check in today's `verifyPeer` moves into RFC007's switch commit | RFC007, RFC010 |
| `Refused` is an alternative relay record 0 (`pb.Frame` field 7). `Dial` and `Listen` take the token only through options | RFC009, RFC010 |
| Static broker tokens are directional; `Endpoint.Register` takes a `rendezvous.Token` | RFC010, RFC011 |
| One socket mode: RFC011's `Endpoint` owns the read side of every broker punch socket and RFC008 runs on `Endpoint.PacketConn()` under a written contract. Listeners close every `Registration` first, then the RFC008 listener | RFC008, RFC011 |
| One X25519 key per relay serves the relay leg and the broker. The broker uses it only through `ExtractShared` with a domain starting `kamune broker v2`. No `[broker] key_file`, no `broker_pin` | RFC009, RFC011 |
| No channel binding from RFC008 into RFC007's transcript; the `binding` label stays reserved | RFC007, RFC008 |
| RFC008 owns the handshake rate limit; RFC007 adds none. `forgeable` stays, computed from `ReturnRoutable` | RFC007, RFC008 |
| The raw DH between identity keys never leaves `pkg/attest`; only `attest.(*Attest).PairSecret` exists | RFC007, RFC010 |
| No relay token travels in the peer handshake; reconnect tokens come from the exporter label `kamune/relay-reconnect` | RFC007, RFC010 |
| The knock key is used on direct P2P only; broker P2P listeners serve many contacts on one socket and run without one | RFC008, RFC010 |
| The reconnect dialer bounds only the first frame (10 s watchdog), not the whole handshake, because a Strict responder prompts on resumes | RFC007, RFC010 |
| Each RFC's daemon schema edits go in its own client commit, in merge order (RFC009, RFC011, RFC010, RFC007), instead of one joint schema commit | RFC010, RFC011 |

### 5.3 Proposed defaults

The main defaults the RFCs propose. Each RFC's own decisions and proposed
defaults sections list them all and hold the detail.

| RFC    | Item | Proposed default |
| ------ | ---- | ---------------- |
| RFC007 | Resumption window | 24 h sliding idle window from the last handshake or transport end; 7 days maximum since the last cold handshake. Constants, no option |
| RFC007 | Strict initiator on a pinned resume offer | No prompt (the key is the one the user approved and cannot change) |
| RFC007 | Reconnect fallback | Clients accept a COLD answer and start a new session; no client sets `DialWithResumeOnly` by default |
| RFC007 | Client prompt limits | One open verification prompt per client; at most 6 prompts per rolling minute; no exemption, prompts for the user's own dials included (open question 2) |
| RFC007 | `fingerprint.Emoji` | Output unchanged; removed from every verification prompt and verify event; other uses stay |
| RFC007 | Identity key encoding | PKIX `SubjectPublicKeyInfo` (44 bytes) with a fixed 12-byte prefix check, so one key has one encoding; a later move to raw 32-byte keys would be a separate wire change |
| RFC007 | Fingerprint format setting | `numeric`, the default in bus and daemon |
| RFC007 | Daemon error codes for handshake errors | `self_connection`, `handshake_rejected`, `version_mismatch`, `unsupported_protocol`, `verification_failed`, `resume_refused` |
| RFC008 | UDP path caps | 4,096 paths in total, 32 per source (IPv4 address, IPv6 /64), 128 per network (IPv4 /24, IPv6 /48); 256 pending, 4 pending per source; INIT 4/s, burst 8 per source |
| RFC008 | Handshake rate (`ServeWithHandshakeRate`) | On by default: source 8/s burst 16, network 32/s burst 64, global `512 * GOMAXPROCS`/s with a burst of twice that |
| RFC008 | KCP MTU | 1,200 (DATA at most 1,232 bytes, within the IPv6 minimum MTU) |
| RFC009 | Relays without a PSK | Keep answering `KeyRequest`; only PSK relays are silent |
| RFC009 | First contact over verified TLS | The key is stored without a prompt |
| RFC010 | Static token rotation | None in v1; the counter `n` in the Expand info is reserved for it |
| RFC010 | Relay `dialerGrace` | 10 s before a silent dialer can be replaced |
| RFC010 | Reconnect pool | 3 tokens per session |
| RFC011 | Broker limits | TTL 60 s (20 s to 1 h); 256 live slots per IP; 2,048 per /24; 100,000 entries; 200,000 recent-cache entries; X25519 10/s burst 60 per verified IP and 4,000/s burst 400 in total with a reserve of 100 for IPs holding slots; `cookie_rate` unlimited. Memory at these caps is about 85 MB (about 33 MB of registry entries and 50 MB of recent-cache entries). A benchmark of `brokerserver.Server.Handle` on the reference relay host sets the final values before release |
| RFC011 | Broker server read loop | 2,048-byte read buffer, 500 ms read deadline; the v1 read-error backoff is kept (after 16 failed reads in a row, 100 ms before each further read); the buffer size is open question 7 |

## 6. Shared Constants and Domain Separation

### 6.1 Wire versions, types and first bytes

| Protocol | RFC | Carrier | Header | Version | Types and codes |
| -------- | --- | ------- | ------ | ------- | --------------- |
| Peer handshake | RFC007 | any `kamune.Conn` frame | `ver[1] type[1]` | `0x02` | 0x01 ClientHello 1,282 B, 0x02 ServerHello 1,154 B, 0x03 ResponderAuth 214 B, 0x04 InitiatorAuth 426 B, 0x05 Confirm 234 B. Confirm status 1 COLD, 2 RESUMED, 3 REJECTED; reason 1 VERIFIER, 2 VERSION |
| Session frames | RFC007 | `box.proto` `Route` | protobuf | n/a | kept: 0 INVALID, 7 EXCHANGE_MESSAGES, 8 CLOSE_TRANSPORT, 9 PING, 10 PONG, 13 SESSION_DATA; `reserved 1 to 6, 11, 12` |
| UDP path | RFC008 | UDP datagram | `type[1] version[1] reserved[2]` | `0x01` | 0x01 HELLO 1,200, 0x02 COOKIE 28, 0x03 INIT 1,200, 0x04 ACCEPT 60, 0x05 DATA 33 to 1,232, 0x06 CLOSE 32 |
| UDP first byte | RFC008, RFC011 | any socket the path layer reads | | | `0x00` NAT kick; `0x01`-`0x0F` path layer; `0x10`-`0xFF` others; broker `"KBRK"` is `0x4B` |
| Relay leg | RFC009 | WebSocket message or 2-byte length-prefixed frame | `"KR"` (`0x4B 0x52`), `version[1]`, `type[1]` | `0x02` | 0x01 KeyRequest 4, 0x02 KeyResponse 36, 0x03 ClientHello 1,289, 0x04 ServerHello 1,156, 0x05 Alert 5; alerts 1 `bad_message`, 2 `psk_unexpected`, 3 `unknown_key`; `flags` bit 0 = PSK |
| Relay records | RFC009, RFC010 | `pb.Frame` `oneof kind` | protobuf | n/a | 1 Register, 2 Registered, 3 Message, 4 Ping, 5 Pong, 6 reserved (`auth`, RFC009), 7 Refused (RFC010). `Refused.Reason`: 0 REASON_UNSPECIFIED, 1 TOKEN_NOT_FOUND, 2 TOKEN_IN_USE, 3 TOKEN_INVALID, 4 SESSION_FULL, 5 SESSION_EXPIRED, 6 BAD_REGISTER |
| Broker | RFC011 | UDP datagram | `"KBRK"` + `VER[1]` + `TYPE[1]` | `0x02` | 0x01 COOKIE 68, 0x02 REGISTER 174, 0x03 SEALED 118; downlink kinds 1 REGISTERED, 2 MATCHED, 3 REJECTED, 4 REPLACED; reasons 1 STALE, 2 FULL, 3 IP_QUOTA, 4 BAD_FIELDS; roles 1 LISTEN, 2 DIAL |
| Library version | RFC007 | `kamune.AppVersion` | | | `0.8.0` in the switch commit; at most 32 bytes |

No two protocols share a carrier and a first byte. Peer handshake frames ride
inside a `kamune.Conn` (relay records, KCP over RFC008 DATA, TCP framing) and
never raw on a socket. The relay leg runs on TCP or WebSocket only, so its
`0x4B` first byte never meets the broker's. The UDP path layer and the broker
share punch sockets and are split by first byte.

### 6.2 KDF, MAC and hash domain strings

| RFC | Kind | Strings |
| --- | ---- | ------- |
| RFC007 | HKDF-Expand-Label prefix | `kamune2 ` + `r hs traffic`, `i hs traffic`, `key`, `finished`, `derived`, `res binder`, `res psk`, `r confirm`, `i ap traffic`, `r ap traffic`, `exp master`, `res master`, `session id`, `exporter`, caller exporter labels |
| RFC007 | Transcript hash prefix | `kamune/2 transcript` |
| RFC007 | HPKE (X-Wing) info / export context | `kamune/2 kex` / `kamune/2 kex secret` |
| RFC007 | AEAD AD prefix | `kamune/2 hs` |
| RFC007 | Ed25519 signature contexts (`pkg/attest/contexts.go`) | `kamune/2 responder signature\x00`, `kamune/2 initiator signature\x00`, `kamune/transport-sign/v1` |
| RFC007 | Exporter labels (prefix `kamune/` reserved) | `kamune/relay-reconnect` (RFC010's only use) |
| future contact-only listener RFC | `PairSecret` salt (reserved) | `kamune/2 contact tag` |
| RFC008 | Cookie MAC | `kamune udp cookie v1` |
| RFC008 | Path transcript | `kamune udp path v1` |
| RFC008 | Expand-Label prefix | `kamune udp ` + `c2s`, `s2c`, `binding` (reserved, not derived) |
| RFC008 | Knock MAC | `kamune udp knock v1` |
| RFC009 | Expand-Label prefix | `kamune relayleg v2 ` + `binder`, `derived`, `relay finished`, `c2r key`, `c2r iv`, `r2c key`, `r2c iv` |
| RFC009 | HPKE info / export context | `kamune relayleg v2 static` (DHKEM X25519), `kamune relayleg v2 ephemeral` (X-Wing) / `kamune relayleg v2 ss` |
| RFC009 | Transcript prologue | `kamune relayleg v2 prologue` |
| RFC009, RFC011 | Key hint | `kamune relayleg v2 key hint` (one function, `relayleg.KeyHint`, one purpose: naming the relay key) |
| RFC010 | `PairSecret` salt | `kamune/pair/v1` |
| RFC010 | Expand info prefix and purposes | `kamune/rendezvous/v1` + `relay-static`, `broker-static`, `relay-reconnect`, `p2p-punch` |
| RFC010 | Hashes | `kamune/service-id/v1`, `kamune/token-handle/v1` |
| RFC011 | `ExtractShared` domain (RFC009's rule: prefix `kamune broker v2`) | `kamune broker v2 dh ` |
| RFC011 | RID extract salt | `kamune broker v2 rid ` |
| RFC011 | Expand-Label prefix | `kamune broker v2 ` + `rendezvous`, `upload key`, `download key`, `registration id` |
| RFC011 | Cookie MAC | `kamune broker v2 cookie` |

No string serves two purposes. Repeated short labels (`derived`, `binder`,
`key`) appear only behind different prefixes or under different secrets, as in
TLS 1.3. The one string two RFCs use, the key hint, is one function with one
purpose. The two broker salts that are followed by the relay public key
(`kamune broker v2 dh ` and `kamune broker v2 rid `) differ in the first byte
after their common prefix (`d` and `r`), and `ExtractShared` refuses any
domain without the `kamune broker v2` prefix. The two `PairSecret` salts
(`kamune/pair/v1`, `kamune/2 contact tag`) give independent PRKs from one DH.

### 6.3 Long-term keys and their permitted uses

| Key | Owner | Uses, and only these |
| --- | ----- | -------------------- |
| Peer identity, Ed25519 (`attest`) | RFC007 | Signatures under the three registered contexts. Converted to X25519 only inside `attest.PairSecret` (RFC010); the raw DH never leaves `attest`. There is no separate X25519 identity key |
| Relay static key, X25519 (`relayleg.PrivateKey`, `<data_dir>/relay-static-key.pem`, text `rk1-` + 52 base32) | RFC009 | Relay-leg HPKE DHKEM decapsulation; the broker PRK through `ExtractShared("kamune broker v2 dh ", E_C_PUB)` (RFC011). Never signs; no raw accessor. Its public key is RFC010's `relay_id` and, at a broker, `broker_id` (`rendezvous.NewServiceID`). Clients pin it in relay addresses (`?rk=`) and broker addresses (`udp://host:port?rk=`) |
| Relay access key (`psk1-` + 52 base32) | RFC009 | First extract of the relay-leg key schedule and the binder only |
| UDP path cookie secret | RFC008 | One per listener, drawn at start, never rotated or persisted |
| Broker cookie secret | RFC011 | One per broker process, replaced every 10 minutes (the previous one kept until the next replacement), never persisted |
| `PRK_pair` (64 B, in memory) | RFC010 | Relay and broker static tokens; `PunchKey` (RFC008's direct-P2P knock key) |
| Exporter root (`exp_master`) | RFC007 | `ExportKeyingMaterial`; RFC010's reconnect root (`relay_reconnect` meta, 32 B) |

### 6.4 Storage keys

| Key | RFC | Content |
| --- | --- | ------- |
| Session meta `resumption_i`, `resumption_r` | RFC007 | `ResumptionState` protobuf, encrypted, one row per role |
| Session meta `resumption_tokens` | RFC007 (removed) | Ignored if present |
| Session meta `relay_reconnect` | RFC010 | 32-byte reconnect root; any other length is treated as absent |
| Session meta `relay_tokens` | RFC010 (removed) | Ignored if present |
| Settings app `kamune-relay-keys`, key `Address.StoreName()` | RFC009 | `rk1-...` pin |

### 6.5 Sizes and timeouts that cross RFCs

| Constant | Value | Defined by | Used by |
| -------- | ----- | ---------- | ------- |
| Token size | 32 B on every wire | RFC010 (`rendezvous.TokenSize`) | RFC009 (`checkRegisteredToken`), relay `CheckWire`, RFC011 (`DeriveRID` input) |
| Relay key, access key | 32 B | RFC009 | RFC010 (`NewServiceID`), RFC011 (`S_pub`) |
| Peer handshake timeouts | handshake 30 s, verify 150 s, accept to ClientHello 10 s, hello stage 180 s | RFC007 | RFC010's reconnect watchdog (first frame within 10 s); clients |
| Resumption window | 24 h idle, 7 days maximum age | RFC007 | RFC010 (a reconnect root is of no use past it) |
| Relay-leg handshake | 30 s (`session.handshake_timeout`, `WithHandshakeTimeout`) | RFC009 | RFC010 (`Register` and `Refused` fall inside it) |
| Relay dialer grace | 10 s | RFC010 | RFC007's initiator sends its ClientHello at once |
| UDP hole-punch dial | 10 s (`DefaultHolePunchTimeout`) | RFC008 | RFC011's dial path after `WaitMatch` |
| Broker match wait | 30 s | RFC011 | RFC010 (static dial), clients |
| UDP path cookie lifetime | 10 s (valid for `now - 10 s <= t <= now + 1 s`) | RFC008 | |
| Broker cookie lifetime | 60 s | RFC011 | |
| Largest non-broker datagram RFC011's `Endpoint` forwards | 1,500 B | RFC011 | RFC008 (largest path packet 1,232 B) |
| `Endpoint` and path-layer socket read buffer | 65,536 B; every read error other than `net.ErrClosed` is transient | RFC008 rule | RFC011 |
| Relay pre-authentication frame limit | 1,289 B | RFC009 | |

## 7. Interfaces Between the Parts

### 7.1 Provider and user

| Provider -> user | Interface |
| ---------------- | --------- |
| RFC007 -> RFC010 | `(*Transport).ExportKeyingMaterial(label, context, n)` with label `kamune/relay-reconnect`; `DialWithPeerKey`, `DialWithResume`, `Transport.Resumed()`, `Transport.SessionID()`; `ErrPeerKeyMismatch`, `ErrSelfConnection` |
| RFC010 -> RFC007 | `PeerConstraint` and `ExpectPeer` (root `peerconstraint.go`). RFC007 calls `AllowPeer` at the initiator's step 4a and the responder's step 3a and sets `Pinned`. `attest.PairSecret` for the future contact-only listener |
| RFC007 -> RFC008 | Frame sizes for the amplification budget (initiator 1,282 B; responder 1,154 + 214 B); one X-Wing encapsulation and one Ed25519 signature per ClientHello |
| RFC008 -> RFC007 | The handshake-rate check runs first in `admit`; `forgeable` comes from `ReturnRoutable`; RFC007 counts a forgeable conn on entering its authenticated stage |
| RFC007 -> all | The signature-context registry in `pkg/attest` (`Contexts()`, prefix-freeness test); any context signed with an identity key goes there. RFC008 to RFC011 sign nothing with it |
| RFC007 -> RFC009 | The RELAY.md paragraph on what a relay learns about peers. Peer handshake security does not depend on the relay leg |
| RFC009 -> RFC010 | `Dial` and `Listen` with `WithToken(rendezvous.Token)` and `WithTokenFunc(rendezvous.TokenFunc)`. The hook runs after `finished_r` verifies and before record 0, with `rendezvous.NewServiceID(relayKey)`. The relay's record 0 is `Registered` or `Refused` |
| RFC009 -> RFC011 | `relayleg.PublicKey` (`ParsePublicKey`, `String`, `Display`, `ECDH`), `KeyHint`, `PrivateKey.ExtractShared`, `LoadPrivateKeyFile` (test vectors), `services.Service.StaticKey()` |
| RFC010 -> RFC011 | `rendezvous.Token` (`Bytes`, `Handle`, `IsZero`), `NewRandomToken`, `NewServiceID`, `ErrTokenZero`; directional `ListenToken` and `DialToken(rendezvous.Broker, svc)` |
| RFC011 -> RFC010 | `Endpoint.Register(ctx, tok, role)`, `Registration.Matches()`, `Wait`, `Close`, `Match{Peer, Self}`, `Client.ServiceID()` |
| RFC011 -> RFC008 | `Client.NewEndpoint(pc)` and `Endpoint.PacketConn()`: read deadlines honoured; every non-broker datagram up to 1,500 B delivered unchanged with its source; socket reads into a 65,536-byte buffer; `ReadFrom` returns only `net.ErrClosed`-wrapped or deadline errors; other read errors are transient; `Close` closes the socket |
| RFC010 -> RFC008 | `PairKey.PunchKey() [32]byte` for `UDPWithKnockKey` on direct P2P |
| RFC008 -> RFC010, RFC011 | `kamune.ListenUDP(pc, ...)`, `kamune.DialUDP(ctx, pc, raddr, ...)`, `UDPWithSourceFilter`, `UDPWithKnockKey`. RFC010's `ExpectPeer` wrappers stay around the returned conns |

### 7.2 Public Go API changes

| Package | RFC | Added | Removed |
| ------- | --- | ----- | ------- |
| `kamune` | RFC007 | `DialWithPeerKey`, `DialWithResumeOnly`, `DialContext`, `Transport.Resumed`, `Transport.ExportKeyingMaterial`, `Role`, `VerifyRequest`, `ErrSelfConnection`, `ErrHandshakeRejected`, `ErrUnsupportedProtocol`, `ErrInvalidHandshake`, `ErrNoResumptionState`, `ErrResumeInProgress`, `ErrResumeRefused`, `ErrInvalidExport`; changed `RemoteVerifier` | `ErrResumptionRejected`, the handshake routes |
| `kamune` | RFC008 | `ListenUDP`, `DialUDP`, `UDPOption`, `UDPWith*`, `UDPPathLimits`, `RateLimit`, `ServeWithHandshakeRate`, `ErrUDPHandshakeTimeout`; changed `ServeWithUDP`, `DialWithUDP` | |
| `kamune` | RFC010 | `PeerConstraint`, `ExpectPeer`, `ErrPeerKeyMismatch` | |
| `pkg/attest` | RFC007, RFC010 | RFC007: `Contexts`, context constants. RFC010: `PairSecret`, `ErrSameKey` | |
| `pkg/storage` | RFC007, RFC009, RFC010 | RFC007: resumption API (`GetResumption`, `SwapResumption`, `DeleteResumption`, `DeleteResumptionAll`, `TouchResumption`, `SweepSessions`). RFC009: `DeleteSettings`. RFC010: `RelayReconnectKey` | RFC007: `PutSessionResumption`, `ResumptionTokensKey`, the list helpers. RFC010: `RelayTokensKey` |
| `pkg/fingerprint` | RFC007 | `SafetyNumber` | |
| `pkg/rendezvous` | RFC010 | new package | |
| `pkg/relayconn` | RFC009, RFC010 | RFC009: `Address`, `ParseAddress`, `Dial`, `Listen`, `WithToken`, `WithTokenFunc`, `WithPSK`, `WithKeyStore`, `WithReplaceStoredKey`, `WithTLSConfig`, `KeyStore`, `SettingsKeyStore`, `NewMemoryKeyStore`, `ForgetRelayKey`, `IsRelayTrustError`, the trust errors. RFC010: `WithExpectedPeer`, `WithPair`, `RelayConn.AllowPeer`, `ErrNoToken`, `ErrTokenOptions`, `ErrTokenInUse`, `ErrTokenNotFound`, `ErrTokenInvalid`, `ErrSessionFull`, `ErrSessionExpired`, `ErrRefused` | RFC009: the eight `DialRelay*` and `ListenRelay*` helpers, `WithPassword`. RFC010: `TokenFromKeys`, `ValidateUserToken`, the SessionData exchange |
| `pkg/relayconn/relayleg`, `relaytest` | RFC009 | new packages | |
| `pkg/relayconn/broker` (with `wire`, `brokerserver`, `brokertest`) | RFC011 | v2 client and server | the v1 API |
| `pkg/exchange` | RFC007, RFC009, RFC010, RFC011 | | `mlkem.go` (RFC007); the package is deleted at the end |

Names that look alike and do not collide: `relayconn.ErrTokenInvalid` (the
relay sent `Refused TOKEN_INVALID`) and `relayconn.ErrInvalidRelayToken`
(existing: a relay-assigned token in `Registered` is empty or of an unknown
length; a changed echo of a client-sent token is `ErrRelayTokenMismatch`);
`relayconn.ErrInvalidAddress`
and `broker.ErrInvalidAddress`; `rendezvous.ErrSamePeer`, `attest.ErrSameKey`
and `kamune.ErrSelfConnection` (token derivation against handshake).
`relayleg.ErrHandshakeRejected` (the relay closed the relay-leg handshake
before ServerHello) and `kamune.ErrHandshakeRejected` (the peer sent
`Confirm{REJECTED}`) are different values; clients match them by
package-qualified name and map them to different codes.

## 8. Client Changes

### 8.1 Rules that combine several RFCs

- **Reconnect loops** (daemon and bus):
  - stop without retrying on RFC007's final errors (`ErrVerificationFailed`,
    `ErrHandshakeRejected`, `ErrPeerKeyMismatch`, `ErrSelfConnection`,
    `ErrNoResumptionState`, `ErrVersionMismatch`, `ErrUnsupportedProtocol`,
    `ErrResumeInProgress`, `ErrResumeRefused`) and when
    `relayconn.IsRelayTrustError(err)` is true (RFC009);
  - move to the next reconnect index on `relayconn.ErrTokenNotFound`,
    `relayconn.ErrTokenInUse` or a first-frame watchdog close (RFC010);
  - on other errors, back off and restart at index 0 (RFC010);
  - on success with `!t.Resumed()`, end the old session through the existing
    close path and start a new one with `t.SessionID()` (RFC007); delete the
    old session's `relay_reconnect` and store the new root (RFC010).
- **Peer pins.** RFC010's client commits use `WithPair`, `WithExpectedPeer`
  and `ExpectPeer` on every pair rendezvous (static relay, static broker,
  reconnect, direct P2P with a known key). RFC007's client commit adds
  `kamune.DialWithPeerKey(peer)` on every dial path with a known peer key,
  RFC010's paths included; it does not exist before RFC007's switch.
- **Name collision.** The two `ErrHandshakeRejected` values (section 7.2) map
  to `relay_handshake_rejected` and `handshake_rejected`.
- **Addresses.** Stored relay addresses carry no `rk`; the key store holds the
  pin (RFC009). Broker addresses always carry `rk` (RFC011). Share URLs:
  relay `relay://?addr=<URL-escaped Address.String()>&token=...&psk=1`
  (`token` only for random tokens, RFC010; the access key itself never), p2p
  `p2p://host:port?rk=rk1-...&token=<64 hex>` (random tokens only).
- **File order.** In a client file that several RFCs change, commits land in
  the order RFC009, RFC011, RFC010, RFC008, then RFC007's compile fix when its
  switch merges, then RFC010's reconnect commit, then RFC007's client commit.
  Each changes only the functions its RFC names.

### 8.2 Daemon (`cmd/daemon`)

| Order | RFC | Changes |
| ----- | --- | ------- |
| 1 | RFC009 | `relay.go`, `param.go` and the relay call sites in `network.go` (`startServer`, `dial`, the relay reconnect path, `handleRestartServer`, `handleGenerateRelayToken`, `shareRelayInfo`): `relayconn.ParseAddress`, `Dial`/`Listen`, `WithPSK`, `SettingsKeyStore` (a memory store in incognito). `parseRelayAddr`, `parseInsecureFlag`, `parseRelayPin`, `checkRelayPin` and `relayTLSConfig` go; the `relay_pin` field becomes the `cert=` parameter of `relay_addr`. `password` becomes `relay_psk`; `replace_relay_key` and the command `forget_relay_key` are new; share info gains `relay_addr` and `psk`; the error event gains `relay_key` and `stored_relay_key` |
| 2 | RFC011 | `broker.go` (`BrokerClient` deleted; `WaitMatch` and `HolePunch` on the `Endpoint`), `p2plistener.go` (`Endpoint`, `RegisterToken`, a `Matches()` reader that kicks the matched peer, `Holds`, close order; the v1 broker packet handling and `refreshLoop` go), `p2p.go` (`GenerateP2PToken(peerPubB64)`, a fresh random token per call, `status`), `directp2p.go` (`sendNATKick` signature), `network.go` (p2p dial with a 30 s match wait, `p2p_self_dial`, share URL), `param.go` (`BrokerAddr` parsed with `broker.ParseAddress`) |
| 3 | RFC010 | `PairKey` replaces `deriveP2PToken`; the static relay listener state machine; a relay `start_server` with `peer_pub_b64` starts a static listener (today `startServer` passes no static token), and `dial` derives pair tokens from `peer_pub_b64` (`token` or `p2p_token` together with it is `invalid_params`); tokens get `ID`, `Handle` and `Status`; `remove_*_token` take `{id}`; handles in every log and event (replacing `shortToken`); `ExpectPeer` wrapping in the p2p listener (per match) and dialer; `decodeTokenList` and `parsePeerPubB64ToRaw` deleted |
| 4 | RFC008 | `directp2p.go`, `p2plistener.go` (`kamune.ListenUDP` on `ep.PacketConn()`), `broker.go` `HolePunch` (`kamune.DialUDP`, 10 s); the direct-P2P paths in `network.go` stop wrapping with `kamune.NewConn`, and dials block up to 10 s, the reconnect path included; `listenDirect` for udp binds with `net.ListenUDP` and returns `kamune.ListenUDP(pc)` in place of `kcp.Listen` wrapped in `boundListener`, and still reports the bound address (`pc.LocalAddr()`); knock key from `PunchKey()` on direct P2P; `kcp-go` becomes indirect |
| (with the RFC007 switch) | RFC007 | `verifier.go`: new verifier signature only, so the module compiles |
| 5 | RFC010 | Reconnect roots from the exporter replace `deriveAndStoreRelayTokens`, `finishRelayToken` and the SessionData branch; the relay resume listener (`awaitRelayResume`) and dialer (`makeReconnectFn`) follow RFC010's reconnect rules |
| 6 | RFC007 | Verifier policy per mode and role, prompt limits, name-collision warning, `verify_peer` payload with two labelled codes, `numeric` as the default format (the daemon already accepts it), the reconnect stop list, COLD fallback, `DialWithPeerKey`; resumption checks (`relayResumable`) read the per-role rows instead of the `resumption_tokens` meta; client code that clears resumption state without a transport calls `DeleteResumptionAll`. RFC007 §20.1 and §20.2 give the detail |

New daemon error codes after all five RFCs (existing codes unchanged):

| RFC | Codes |
| --- | ----- |
| RFC009 | `relay_key_unknown`, `relay_key_changed`, `relay_key_required`, `relay_auth_failed`, `relay_key_not_held`, `relay_handshake_rejected`, `relay_psk_unexpected`, `relay_tls_verify` |
| RFC010 | `invalid_token`, `invalid_peer_key`, `peer_not_listening`, `peer_busy`, `peer_key_mismatch` (also used by RFC007's client commit for `kamune.ErrPeerKeyMismatch` from a pin) |
| RFC011 | `invalid_broker_address`, `broker_key_required`, `broker_key_mismatch`, `p2p_listener_required`, `p2p_self_dial`; `p2p_match_failed` carries the reason |
| RFC007 | proposed: `self_connection`, `handshake_rejected`, `version_mismatch`, `unsupported_protocol`, `verification_failed`, `resume_refused` |

No code is defined twice with different meanings.

Schema files (`cmd/daemon/schema`), in merge order:

1. RFC009: `start_server`, `dial`, `restart_server`, `generate_relay_token`,
   `get_share_info`, `events/error`, new `forget_relay_key`.
2. RFC011: `start_server`, `dial`, `restart_server` (`broker_addr`);
   `generate_p2p_token` loses `broker_addr`; `p2p_tokens` and
   `list_p2p_tokens` gain `status`.
3. RFC010: `_shared/relay-token`, `events/relay_token`, `relay_tokens`,
   `p2p_tokens`, `generate_relay_token`, `remove_relay_token`,
   `list_relay_tokens`, `generate_p2p_token`, `remove_p2p_token`,
   `list_p2p_tokens`, `dial`, `start_server`. RFC010 rebases onto RFC011's
   schema edits.
4. RFC007: `events/verify_peer`.

### 8.3 Bus (`cmd/bus`)

| Order | RFC | Changes |
| ----- | --- | ------- |
| 1 | RFC009 | `relay.go`, `network.go`, `app.go`: `RelayOptions{Address, AccessKey, TrustRelayKey, ReplaceStoredKey}` replaces the address, password and skip-verification arguments; `parseRelayAddr` (with its `insecure` and `pin` parameters) gives way to `relayconn.ParseAddress` (`pin=` becomes `cert=`); `ConnectResult` gains `RelayKey` and `StoredRelayKey`; `StartServer` returns `StartServerResult`; `ForgetRelayKey`, `ParseShareURL`; the relay resume listener (`awaitRelayResume`) stops with a `relay-trust-error` event. Frontend: `App.svelte` relay address and access-key inputs (the Skip TLS verification checkbox goes), the address helpers `relayaddr.ts` and `importurl.ts` (scheme, `pin` and `insecure` handling) go, `ImportDialog.svelte`, `ShareDialog.svelte`, new `RelayKeyDialog.svelte`, `P2PFallbackDialog.svelte` |
| 2 | RFC011 | As the daemon; `p2pListenerI` gains `Holds`, `RegisterToken` and `Unregister`; `(*p2pListener).Token()` is deleted (the listener has no primary token any more), and the `StartServer` block in `network.go` that seeds `a.p2pTokens` from it is rewritten; `NewApp` loses the process X25519 key and the `os.Exit(1)` that only its failure needed; `StartServer` and `ConnectToServer` keep their `brokerAddr` argument (now with `?rk=`) next to RFC009's `RelayOptions`; broker address placeholders; `SignalingTokens.svelte` calls `GenerateP2PToken(peerPubB64)`; tests move to `brokertest`. `RegisterP2PDialer` and the auto-register block are already gone from the current code |
| 3 | RFC010 | `StartServer` fails closed on a bad `peerPubB64` (`invalid_peer_key`); static mode returns no token; tracking keyed by `ID`; handles in logs and events (replacing `logToken`); `WithPair` and `DialToken`; `ExpectPeer` wrapping; the library's `PeerConstraint` rejects the keys the bus's listener gate (`peergate.go`, `pinRelayListener`, `admittedBy` in `serverHandler`) rejects, and does so before the verifier; whether the bus keeps that gate, and with it its own `ErrPeerKeyMismatch`, as a second check is open question 5; frontend `models.ts`, `stores.ts`, `Sidebar.svelte`, `SignalingTokens.svelte`, the `App.svelte` toast and copy text, `hints.ts`, the 64-hex input in `P2PFallbackDialog.svelte` |
| 4 | RFC008 | `directp2p.go`, `p2plistener.go`, `broker.go` `HolePunch` (honours its timeout, 10 s default, `ErrHolePunchFailed`); direct-P2P and broker dials in `network.go` block up to 10 s; `dialUDP` in `dialattempt.go` moves from `kcp.Dial` to `kamune.DialUDP` under the attempt's context; knock key on direct P2P; `kcp-go` becomes indirect |
| (with the RFC007 switch) | RFC007 | `verifier.go` signature (compile only) |
| 5 | RFC010 | Reconnect roots; `loadRelayPool` reads `relay_reconnect` |
| 6 | RFC007 | Verifier policy and limits, `verify-peer` event fields, `VerifyDialog.svelte` (two labelled codes, read-back text, resumed banner, collision warning, no emoji), `numeric` as the default format, reconnect rules, `DialWithPeerKey` (it supersedes `pinPeer` on dials: the library pin runs before the dialer sends its identity, while `pinPeer` runs in the verifier); `relayResumable` reads the per-role rows; client code that clears resumption state without a transport calls `DeleteResumptionAll`; `session_test.go`, which reads `ResumptionTokensKey` today, moves to `GetResumption`. RFC007 §20.1 and §20.3 give the rest |

The Wails bindings (`go.ts`, `models.ts`) are regenerated in every commit that
changes a bound method or type (RFC009, RFC011, RFC010, RFC007).

### 8.4 TUI (`cmd/tui`)

| Order | RFC | Changes |
| ----- | --- | ------- |
| 1 | RFC009 | `relayaddr.go` deleted (its TLS 1.2 minimum with it); `relayconn.Address`; the field "Relay key (rk1-..., empty to fetch)" replaces the certificate fingerprint field (a certificate pin stays possible with `?cert=`); "Relay access key" replaces the password field; a confirm screen for `UnknownRelayKeyError` and `RelayKeyChangedError`; `SettingsKeyStore` once storage is open |
| 2 | RFC010 | `rendezvous.ParseToken` (64 hex), `WithToken`, `Reveal()` for relay-assigned tokens, placeholder "Token (64 hex)", the `RouteSessionData` comment in `tea.go` dropped |
| (with the RFC007 switch) | RFC007 | Verifier literal signatures in `tea.go` and five test files |
| 3 | RFC007 | Verify screen with two labelled codes and no emoji, "Reconnecting session" banner on resumed sessions, the resume notice removed, `DialContext` in `client.go` and `relayclient.go`; `session_test.go` moves from `PopList(sid, ResumptionTokensKey)` to `GetResumption` and `DeleteResumptionAll`; `verify_test.go` expects a prompt for a resumed session on the responder (RFC007 §20.4) |

The TUI has no UDP or broker code, so RFC008 and RFC011 do not change it.

## 9. Test Plan Across RFCs

Unit, negative and fuzz tests stay with each RFC. Tests use real
implementations and `a := require.New(t)` (AGENTS.md). The end-to-end tests:

| Test | Owner | Location | Needs |
| ---- | ----- | -------- | ----- |
| `TestUDPEndToEnd`: cold handshake, 100 messages each way, close, resume over a new path, an attacker socket | RFC008 | root `udp_test.go` | U8-U11 |
| Relay-leg table across transport pairs with access key, `rk` and `cert` | RFC009 | `cmd/relay/internal/handlers/relay_test.go` | L7 |
| `tokens_e2e_test.go`: pair tokens, reconnect roots, squat attempts | RFC010 | `cmd/relay/internal/handlers` | T9; reconnect steps after T15 |
| Broker e2e: real broker, two `Endpoint`s, KCP or `DialUDP`, a tap attacker | RFC011 | `cmd/relay/internal/broker/e2e_test.go` | K4; the `DialUDP` variant after U8 |
| `TestE2E_RelayBlindHandshake`: recorded relay frames contain no key, name, version or session ID | RFC007 | `cmd/relay/internal/handlers/handshake_e2e_test.go` | H6, L7, T9 |

**Cross-RFC run.** Owned by RFC007's implementer, after phase 5 (section 10.3),
as an extension of `TestE2E_RelayBlindHandshake` rather than a new file:

- Relay case: a relay with a generated key and access key; listener and dialer
  with `WithPair`, one over `wss` with `cert=` and one over `ws` with `rk=`;
  RFC007's handshake with `DialWithPeerKey` and the conn's `PeerConstraint`;
  Strict verifiers on both sides. Inject one garbage frame, reconnect through
  RFC010's reconnect index 0 under the first-frame watchdog, and resume. Check
  that the Strict responder was prompted on the resume and that the dialer did
  not give up while the prompt was open.
- Broker case: RFC011's `brokertest`, RFC010's directional broker tokens,
  RFC008's `ListenUDP` and `DialUDP` on `ep.PacketConn()`, `ExpectPeer` on both
  conns, and a third identity that is handed the pair's broker listen token
  (standing in for a leaked token) and registers `RoleListen` with it before
  the real listener. The honest dialer matches the third identity, its UDP path
  completes, and the handshake fails with `ErrPeerKeyMismatch` at the dialer's
  step 3 (the `DialWithPeerKey` pin) or step 4a (`AllowPeer`) of RFC007
  §13.3, before the dialer sends its identity and before any verifier runs.

Negative tests that check one RFC's assumption about another:

| Assumption | Test | Owner |
| ---------- | ---- | ----- |
| RFC011 feeds the relay key to nothing but `ExtractShared` | RFC009's key-usage test (reflection on the exported methods of `*PrivateKey`; a relay-leg `enc_s` given to `ExtractShared`) and RFC011's cross-protocol test (a relay-leg `enc` as `E_C_PUB` fails `OpenRegister`) | RFC009, RFC011 |
| RFC007 runs `AllowPeer` before the verifier on both sides | RFC010's root test: `ExpectPeer` with an accept-all verifier; the verifier counter stays 0 | RFC010 |
| RFC008's reader and RFC011's `Endpoint` survive floods of read errors | RFC008's read-error test; RFC011's `PacketConn` test with 100 transient errors in a row | RFC008, RFC011 |
| The relay logs no token-derived string | RFC010's handlers log test; RFC009's `authFailLog` test | RFC010, RFC009 |
| RFC010's reconnect works with a Strict responder that prompts for longer than 10 s | the cross-RFC run | RFC007 |

## 10. Implementation Plan

Commits follow AGENTS.md: `<module>: <lowercase description>`, at most 72
characters, one logical change each, and nothing is committed without the
maintainer's prompt. Every commit builds and passes `go vet` and
`go test ./...` in all five modules, except inside a merge unit (section
10.4). Client commits apply to the current client code; section 8 names the
current functions.

### 10.1 Commit groups

Labels used below. Each RFC's own implementation plan holds the content.

**RFC007 (H):**

| Label | Commit |
| ----- | ------ |
| H1 | `kamune: add handshake v2 key schedule and transcript` (`keyschedule.go`, `transcript.go`, `enigma.NewFromKey`, vectors) |
| H2 | `kamune: add handshake v2 frame codec` (`hsframe.go`, fuzzers) |
| H3 | `kamune: add per-role resumption state to storage` (new API beside the old one, sweep) |
| H4 | `kamune: add signature context registry` (`pkg/attest/contexts.go`) |
| H5 | `kamune: add fingerprint safety number` |
| H6 | `kamune: switch to handshake v2` (dial, server, admission stages, verifier, transport, old phases and routes deleted, protobuf regenerated, root tests migrated, `AppVersion` 0.8.0) |
| H7 | `relayconn: adapt tests to the new verifier` |
| H8 | `relay:`, `bus:`, `daemon:`, `tui:` compile commits for the new `RemoteVerifier` |
| H9 | `kamune: remove resumption token storage helpers` |
| H10 | `daemon:`, `bus:`, `tui:` verifier policy, prompts, codes, reconnect rules and COLD fallback, `DeleteResumptionAll` where resumption state is cleared without a transport (and in the TUI tests), pins |
| H11 | `kamune,relay: add relay end-to-end handshake test` |
| H12 | `docs:` SPEC, RELAY.md (with RFC009), DAEMON.md, READMEs, RFC banners, diagrams |

**RFC008 (U):**

| Label | Commit |
| ----- | ------ |
| U1 | `kamune: guard the fake clock with a mutex` |
| U2 | `kamune: move source and network keys into internal/admit` |
| U3 | `kamune: add fixed-memory keyed rate limiter to internal/admit` |
| U4 | `kamune: add in-memory packet network for udp tests` |
| U5 | `kamune: add udp path handshake with return-routability cookies` |
| U6 | `kamune: seal udp path packets with a replay window and close` |
| U7 | `kamune: add udp path server with caps, eviction and accept` |
| U8 | `kamune: run udp listeners and dialers over the path layer` |
| U9 | `kamune: trust source addresses only from return-routable conns` |
| U10 | `kamune: rate-limit handshakes per source, network and in total` |
| U11 | `kamune: add udp end-to-end test` |
| U12 | `kamune: fuzz udp path input` |
| U13 | `bus: hole-punch over the kamune udp path layer` |
| U14 | `daemon: hole-punch over the kamune udp path layer` |
| U15 | `docs: describe the udp path layer in SPEC 9.2` |
| U16 | `docs: update server limits, constants and errors for udp paths` |
| U17 | `docs: update daemon transport table and broker socket text` |
| U18 | `docs: list admit and udppath internal packages` |

**RFC009 (L):**

| Label | Commit |
| ----- | ------ |
| L0 | `kamune: add Storage.DeleteSettings` |
| L1 | `relayconn: add relayleg keys, psk and their text forms` |
| L2 | `relayconn: add the relayleg v2 handshake and record channel` |
| L3 | `relayconn: add relay addresses and the relay key store` |
| L4 | `relayconn: add Dial and Listen over relayleg` (beside the v1 helpers) |
| L5 | `relayconn: add the relaytest server` |
| L6 | `relay: keep a static relay key in the data dir and log it` |
| L7 | `relay: authenticate the relay leg with relayleg and a psk` (v1 clients now fail at runtime against the relay) |
| L8 | `relay: add -gen-psk and -print-key` |
| L9 | `daemon: use relayconn addresses, psk and relay key trust` |
| L10 | `bus: use relayconn addresses, psk and relay key trust` |
| L11 | `tui: replace the certificate pin field with a relay key` |
| L12 | `relayconn: remove the v1 relay helpers, password option and auth frame` |
| L13 | `docs:` one commit per document |

**RFC010 (T):**

| Label | Prefix | Change |
| ----- | ------ | ------ |
| T1 | `kamune:` | `attest.PairSecret`, conversion helpers, tests |
| T2 | `kamune:` | `pkg/rendezvous` with tests and vectors, `PunchKey` included |
| T3 | `kamune:` | `PeerConstraint`, `ExpectPeer`, interim check in today's `verifyPeer`, `ErrPeerKeyMismatch` |
| T4 | `kamune:` | storage `RelayReconnectKey` |
| T5 | `relay:` | 32-byte random tokens and `CheckWire` (today's clients accept a 32-byte relay-assigned token) |
| T6 | `relay:` | silent-dialer re-arm in `SessionManager` |
| T7 | `relayconn:` | `Refused` in `relay.proto`, regenerated |
| T8 | `relay:` | send `Refused`; refusal logs at debug |
| T9 | `relayconn:` | token options, `WithPair`, `AllowPeer`, `Refused` mapping, 32-byte tokens only |
| T10 | `daemon:` | static relay and p2p through `PairKey`, `dial` and `start_server`, ids, schemas |
| T11 | `daemon:` | handles in logs and events |
| T12 | `bus:` | the same Go changes, fail-closed `StartServer` |
| T13 | `bus:` | frontend and Wails bindings |
| T14 | `tui:` | 64-hex tokens, `WithToken`, `Reveal()` |
| T15 | `daemon:` | reconnect roots from the exporter, reconnect dialer rules |
| T16 | `bus:` | the same |
| T17 | `relayconn:` | delete `TokenFromKeys`, `ValidateUserToken`, the SessionData exchange and the old constants |
| T18 | `kamune:` | storage: drop `RelayTokensKey` |
| T19 | `relay:` | token end-to-end test |
| T20 | `docs:` | one commit per file |

**RFC011 (K):**

| Label | Commit |
| ----- | ------ |
| K1 | `relayconn: add broker v2 wire codec` (`wire`, golden vectors, cookie jar, `Ephemeral`, address parser) |
| K2 | `relayconn: add broker v2 server core` (`brokerserver`, `brokertest`; `golang.org/x/time` becomes a direct requirement of the root module) |
| K3 | `relayconn: add broker v2 endpoint and registration` (beside the v1 API) |
| K4 | `relay: switch broker to v2 server core` |
| K5 | `daemon: use broker v2 endpoints for p2p` |
| K6 | `bus: use broker v2 endpoints for p2p` |
| K7 | `relayconn: remove broker v1 api` |
| K8 | `relay: add broker v2 end-to-end test` |
| K9 | `docs: describe broker v2 protocol` |

**Final cleanup (F):**

| Label | Change |
| ----- | ------ |
| F1 | `kamune:` `Conn` declares `ReadBytes` and `WriteBytes` itself instead of embedding `exchange.ReadWriter` |
| F2 | `kamune: delete pkg/exchange` |
| F3 | `docs:` AGENTS.md: add `pkg/rendezvous`, remove `pkg/exchange` from the `pkg/` list |

### 10.2 Dependency graph

Hard edges only:

```
L0 -> L3
L1 -> L2 -> L3 -> L4 -> L5 -> L6 -> L7 -> L8
T1 -> T2 -> L4            (L4 uses rendezvous.Token and TokenFunc directly)
T2 -> K1 <- L1            (relayleg.PublicKey, LoadPrivateKeyFile)
L1 -> K2 -> K3            (PrivateKey.ExtractShared)
L6 -> K4                  (Service.StaticKey)
L4 -> T7 -> T8 <- L7      (Refused in relay.proto, then sent from L7's record 0)
T2, T3, T7, L4 -> T9      (relayconn token options, WithPair, AllowPeer)
T3 -> H6                  (H6 moves the PeerConstraint check into the handshake)
U8, U9, U10 -> H6         (H6 rebases onto the admit, forgeable and UDP code)
H1..H5 -> H6 = H7 = H8    (one merge unit: root switch and compile fixes)
H6 -> T15, T16            (exporter for reconnect roots)
clients:   L9-L11 -> K5-K6 -> T10-T14 -> U13-U14 -> T15-T16 -> H10
deletions: L12 after L9-L11 and T9; K7 after K5-K6; T17 after T10-T16;
           T18 after T15-T16; H9 after T17-T18
final:     F1, F2 after H6, L12, T17, K4, K7
e2e:       H11 after L7, T9, H6; T19 after T9, T15; K8 after K4 (UDP variant
           after U8); the relay-leg e2e table lands with L7
docs:      after the code of the same RFC, in the order of section 11
```

### 10.3 Phases

| Phase | Work, in merge order within a row | Gate |
| ----- | --------------------------------- | ---- |
| 0. Shared prerequisites | U1 (fake clock mutex), L0 (`Storage.DeleteSettings`), H4 (`pkg/attest/contexts.go`), T1 (`attest.PairSecret`), T2 (`pkg/rendezvous`, `PunchKey` included), T3 (`PeerConstraint`, `ExpectPeer`, interim check in `verifyPeer`, `ErrPeerKeyMismatch`), T4 (`RelayReconnectKey`) | root `go test ./...` green |
| 1. New packages, no shared files | H1, H2, H3, H5 (new root files; storage API beside the old one); U2-U7 (`internal/admit`, `internal/udppath`); L1-L5 (`relayleg`, addresses, key store, `Dial`/`Listen` beside the v1 helpers, `relaytest`); K1-K3 (broker `wire`, `brokerserver`, `brokertest`, client) | each package's tests green; nothing else changes behaviour |
| 2. Relay module | L6, L7, L8, then T5, T6, T7, T8, then K4 | relay module green; v1 clients fail at runtime against the relay, as expected |
| 3. Root integration | U8-U12, then the H6 unit (H6, H7, H8), then T9 (T9 may land before H6; it touches no root file) | all five modules build and test green after the H6 unit |
| 4. Clients | per client, in this order: L9/L10/L11, K5/K6, T10-T14, U13/U14, T15/T16, H10 | each client green after each commit |
| 5. Deletions | L12, K7, T17, T18, H9, then F1 and F2 | no caller of a deleted API remains (`grep`) |
| 6. End-to-end | the relay-leg e2e table, K8, T19, H11; the cross-RFC run of section 9 | all e2e tests green under `-race` |
| 7. Docs | section 11 order, then F3 | docs build; links checked |

Why the UDP path commits come before the handshake switch in phase 3: RFC008's
root changes are small and local (`ServeWithUDP`, `DialWithUDP`, `admit`,
`forgeable`, `conn.go`), while H6 rewrites the handshake files. H6 is
developed in parallel and rebased once onto U8-U10. It keeps RFC008's rate
check as the first step of `admit` and RFC008's `forgeable` computation.

Why T3 comes before H6: T3 is a few lines in today's `verifyPeer` plus a new
file, and lets RFC010's client commits rely on `ExpectPeer` before H6 lands.
H6 deletes `verifyPeer` and moves the check to the initiator's step 4a and
the responder's step 3a.

Why T2 comes before L4 and K1: L4's token options and K1's `DeriveRID` use
`rendezvous.Token` from the start, so neither needs a `[]byte` stand-in and T9
retypes nothing.

### 10.4 Merge units that must not be split

| Unit | Commits | Reason |
| ---- | ------- | ------ |
| Root switch | H6, H7 (`relayconn:` tests), H8 (`relay:`, `bus:`, `daemon:`, `tui:` compile fixes for the new `RemoteVerifier`) | H6 changes `RemoteVerifier`; every module's tests fail until H7 and H8 land. AGENTS.md requires separate commits per module, so they merge together |
| relayconn token switch | T9-T14 | T9 changes `ListenResult.Token` and the token options; root tests stay green at every commit and the clients build again at T14 |
| Relay leg switch | L7 with the relay-leg e2e table | v1 relay clients stop working against the relay at L7; the e2e test proves v2 works in the same merge |

### 10.5 Shared files and merge order

Files that only one RFC changes:

| RFC | Root module | Relay module | Clients | Docs |
| --- | ----------- | ------------ | ------- | ---- |
| RFC007 | New `hsframe.go`, `keyschedule.go`, `transcript.go`, `verify.go`, `name.go`, `admission.go`; rewritten `handshake.go`, `resume.go`, `transport.go`, `serde.go`, `routes.go`, `version.go` (`AppVersion`), `kamune.go` (the changed `RemoteVerifier` type; the v1 handshake and resumption constants removed); `intro.go` deleted; tests `handshake_test.go`, `name_test.go` (from `intro_test.go`), `transport_test.go`, `routes_test.go`, `version_test.go`, `preauth_fuzz_test.go`, `serve_fuzz_test.go`, `resume_test.go` deleted; `internal/box/box.proto`, `model.proto` and regenerated `internal/box/pb`; `internal/enigma` (`NewFromKey`); `pkg/storage/resumption.go` and its tests; `pkg/fingerprint` (`SafetyNumber`); `pkg/attest/contexts.go`; `pkg/exchange/mlkem.go` and `mlkem_test.go` deleted | test literals only (H8) | `cmd/daemon/verifier.go`, `cmd/daemon/messaging.go` (reconnect errors); `cmd/bus/verifier.go`, `cmd/bus/messaging.go`, `VerifyDialog.svelte`; `cmd/tui/tea.go` (`mkVerifier`, verify screen, resume notice), `cmd/tui/client.go` (`DialContext`), `cmd/tui/verify_test.go` | `docs/rfc/RFC001_*`, `RFC002_*`, `assets/diagrams/*`, the protocol paragraph of the root `README.md` |
| RFC008 | `internal/admit`, `internal/udppath` (with `udptest`), `internal/clock/fake.go`, new `udp.go` and `udp_test.go` | none | `cmd/bus/directp2p.go`, `cmd/daemon/directp2p.go` (after RFC011's `sendNATKick` signature change) | the internal-package list of `AGENTS.md` |
| RFC009 | `pkg/relayconn/relayleg`, `pkg/relayconn/relaytest`, new `pkg/relayconn/address.go` and `keystore.go`; `pin.go`, `auth.go` (deleted), `framing.go` (`SetReadLimit`), `transport.go`; `pkg/storage` `DeleteSettings` (L0) | `main.go` (flags), `run/relaykey.go` (new), `run/tls.go`, `internal/services/hub.go`, `services.go`, `internal/handlers/*` except RFC010's `Refused` lines, `internal/handlers/mitm_test.go` (new), `logsample.go`, `Dockerfile` | `cmd/tui/relayaddr.go` (deleted), the relay fields of `cmd/tui/welcome.go`, `ImportDialog.svelte`, `ShareDialog.svelte`, new `RelayKeyDialog.svelte` | the relay sections of `cmd/relay/README.md` |
| RFC010 | `pkg/attest/pairsecret.go` (conversion, `PairSecret`, `ErrSameKey`); `pkg/rendezvous`; new root `peerconstraint.go` and its test; `pkg/relayconn/token.go` (mostly deleted) and `token_test.go` | the behaviour of `internal/services/session.go` (`CheckWire`, 32-byte tokens, `dialerGrace`, `now` hook), `session_test.go`, `internal/handlers/tokens_e2e_test.go` | `hints.ts`, the token rows of `Sidebar.svelte` | none of its own |
| RFC011 | `pkg/relayconn/broker` (`wire`, `brokerserver`, `brokertest`, client; v1 code deleted) | `internal/broker` including `e2e_test.go`; `run.newBroker` | `cmd/daemon/broker.go`, `cmd/bus/broker.go` (until RFC008's `HolePunch` edit) | none of its own |

A later RFC rebases onto an earlier one and does not reformat or move the
earlier RFC's code in the shared files below.

Root module and library:

| File | Order | Who changes what |
| ---- | ----- | ---------------- |
| `server.go` | RFC008 -> RFC007 | RFC008: `ServeWithUDP` body (binds and calls `ListenUDP`), `ServeWithHandshakeRate`, the rate check at the top of `admit`, `p.forgeable = !isReturnRoutable(cn)`, removal of `forgeableAddr`, `sourceKey`, `networkKey`, `prefixKey` and `hostIP` (moved to `internal/admit`). RFC007: everything else (stages move to `admission.go`, `serveConn`, options and their doc comments, base context, sweep ticker) |
| `dial.go` | RFC008 -> RFC007 | RFC008: `DialWithUDP`. RFC007: `DialContext`, `DialWithPeerKey`, `DialWithResume`, `DialWithResumeOnly`, the state machine |
| `conn.go` | RFC008 -> F1 | RFC008: `returnRoutable`, `(*conn).ReturnRoutable`, the `NewConn` doc. F1: the methods of `exchange.ReadWriter` declared on `Conn` |
| `errors.go` | T3 -> U8 -> H6 | T3: `ErrPeerKeyMismatch` (RFC007 keeps this definition). U8: `ErrUDPHandshakeTimeout`. H6: RFC007's other errors |
| `handshake.go` | T3 -> H6 | T3: interim `AllowPeer` check in `verifyPeer`. H6: rewrite |
| `server_test.go` | RFC008 -> RFC007 | RFC008: KCP flood test rewrite, the udp case of `TestPendingCapsByTransport`, `TestSourceKey` moved, rate-limit opt-outs. RFC007: the root test migration |
| `pkg/storage/session.go` | T4 -> T18 -> H9 | T4: `RelayReconnectKey`. T18: drop `RelayTokensKey`. H9: drop `ResumptionTokensKey`, `PutSessionResumption` and the list helpers (H3 adds the new API in `resumption.go` beside them) |
| `pkg/storage/storage.go` | L0 | `DeleteSettings` |
| `pkg/attest` | H4, T1 | separate new files (`contexts.go`, `pairsecret.go`); no shared lines |
| `pkg/relayconn/options.go`, `dial.go`, `listener.go`, `relayconn.go`, `conn.go` | RFC009 -> RFC010 | RFC009: `Dial`/`Listen` over `relayleg`, `WithPSK`, key store options, `WithToken`/`WithTokenFunc` typed with `rendezvous`, `RelayKey()`, `FirstContact()`, package doc. RFC010: `WithExpectedPeer`, `WithPair`, `AllowPeer`, the `Refused` mapping and its sentinels, `ListenResult.Token` as `rendezvous.Token`, the 32-byte `checkRegisteredToken` |
| `pkg/relayconn/pb/relay.proto`, `relay.pb.go` | RFC009, RFC010 | RFC009: delete `Auth` with `reserved 6; reserved "auth";`. RFC010: `Refused refused = 7` and `message Refused`. Each commit runs `make gen-proto`; the later one rebases and regenerates and never merges the generated file by hand |
| `go.mod` (root) | K2 | `golang.org/x/time` becomes direct |
| `pkg/exchange/**` | H6 -> F2 | H6 deletes `mlkem.go`; L12, T17, K4 and K7 remove the last callers; F2 deletes the package |
| `AGENTS.md` | U18, F3 | U18 adds `internal/admit` and `internal/udppath`; F3 adds `pkg/rendezvous` and removes `pkg/exchange` |

Relay module:

| File | Order | Who changes what |
| ---- | ----- | ---------------- |
| `run/run.go` | RFC009 -> RFC011 | RFC009: load the relay key first, `services.New(ctx, cfg, key)`, key and address log lines. RFC011: `newBroker(cfg, key)` from `svc.StaticKey()` |
| `internal/config/config.go`, `config_test.go` | RFC009 -> RFC011 | RFC009: `Server.PSK`, `ParsedPSK`, `password` removed. RFC011: the `[broker]` section and its validation |
| `assets/config.toml` | RFC009 -> RFC011 | RFC009: `[server] psk`, `data_dir` comment. RFC011: `[broker]` block, `[rate_limit]` comment |
| `internal/services/session.go` | RFC009 -> RFC010 | RFC009: `*exchange.Channel` becomes `*relayleg.Channel` (mechanical). RFC010: 32-byte tokens, `CheckWire`, silent-dialer re-arm, `dialerGrace`, the `now` hook |
| `internal/handlers/ws_handler.go`, `tcp_handler.go`, `handlers.go` | RFC009 -> RFC010 | RFC009: read limits, `relayleg.Accept`, silent rejection, record-0 authentication failure. RFC010: `Refused` on `Create`, `CreateWith` and `Join` failures; refusal logs at debug without the token |
| `cmd/relay/README.md` | RFC009 -> RFC011 | RFC009: relay leg, `psk`, key file, flags. RFC011: broker section and config row |
| `run/run_test.go`, `internal/handlers` e2e files | RFC009 -> RFC011 (run); separate files in handlers | `relay_test.go` (RFC009), `tokens_e2e_test.go` (RFC010), `handshake_e2e_test.go` (RFC007) |

## 11. Documentation Plan

| Document | Order | Sections and owners |
| -------- | ----- | ------------------- |
| `docs/SPEC.md` | RFC007 -> RFC008 -> RFC009 -> RFC010 | RFC007: §2, §3, §5 and §5.1, all of §6, §7, §8.1, §9.4, §10 (roles, admission stages, timeouts), the resumption rows of §11.3, §11.6, §12.1, §12.3, §12.5, §12.6 (authentication, replay protection by the transcript, the identity table, the listener key exposure of decision 3, the non-goals), §13 handshake constants, §14 handshake errors, a new Appendix A with test vectors; §15 gains the RFC007 row when merged. RFC008: §9.2 rewritten as "UDP (KCP over the path layer)", §10.1 UDP and rate limits, §12.7, §13 UDP constants, §14 UDP errors. RFC009: the relay-leg paragraph of §9.3. RFC010: the §5.2 use case, the exporter-user line and the `PeerConstraint` step in RFC007's text, the `relay_reconnect` row of §11.3, the token size in §13 |
| `docs/RELAY.md` | RFC009 -> RFC010 -> RFC011 -> RFC008 | RFC009: Design Goals, Threat Model, What the Relay Observes (with RFC007's paragraph on what a relay learns about peers, verbatim), What a Compromised Relay Can and Cannot Do, Protocol (Wire Format, Frame Schema, Connection Flow), Authentication Modes, Rate Limiting, TLS, Handshake Timeout, Go Client, Configuration Reference and Field Semantics, Deployment Patterns and the CDN footnotes, Known Limits, a new "Replacing the relay key". RFC010: the threat-model token rows, `Register`/`Registered`/`Refused`, Token Lifecycle, "Rendezvous Token Derivation" (replacing "Static Tokens", with vectors), "Reconnect Tokens" (replacing "ECDH-Derived Relay Tokens"), Relay Listener Reconnection, the silent-dialer re-arm. RFC011: all of "Broker: STUN-Echo and Signal Introduction", broker rows of the Configuration Reference, "Direct UDP Broker (single host)", the broker item of Known Limits. RFC008: the first-byte rule in the broker section, and the endpoint socket arrangement in place of the paragraph under the broker's `REGISTER` format that tells clients to read NOTIFYs on the punch socket |
| `docs/DAEMON.md` | RFC009 -> RFC011 -> RFC010 -> RFC008 -> RFC007 | RFC009: relay params, address grammar, relay error codes and fields, `forget_relay_key`, `replace_relay_key`, the relay part of `get_share_info`; a key is shown to a human and never accepted automatically. RFC011: p2p inputs, `generate_p2p_token`, token `status`, broker codes, the p2p share URL, the `wss://` broker examples (DOC-10). RFC010: token commands and events, `id`, `handle`, `status`, codes, the derivation and the expected-peer rule (DOC-01). RFC008: the `p2p` and `direct-p2p` rows of the transport table, hole-punch prose. RFC007: verify event, mode table, reconnect errors, the AutoAccept caveat (an unpinned AutoAccept dialer reveals its identity to any key) |
| `cmd/relay/README.md` | RFC009 -> RFC011 | as in section 10.5 |
| `cmd/bus/README.md` | RFC009 -> RFC010 -> RFC007 | relay fields; token text; verification modes, reading the two codes, the AutoAccept caveat (an unpinned AutoAccept dialer reveals its identity to any key) |
| `cmd/tui/README.md` | RFC009 -> RFC010 -> RFC007 | relay fields and the key screen; token length; verify screen |
| `README.md` (root) | RFC007 | protocol summary |
| `docs/rfc/RFC001_session-resumption.md`, `RFC002_signed-metadata.md` | RFC007 | RFC001: banner "Superseded by SPEC §6.8 (handshake v2)". RFC002: note that Introduce and the resume messages no longer exist |
| `assets/diagrams/*` | RFC007 | `handshake-flow.svg`, `key-derivation.svg`, `session-phases.svg`, `protocol-overview.svg`, `cipher-suite.svg`, `message-pipeline.svg`, `wire-format.svg` redrawn for four flights and the new key schedule, or removed from SPEC and README until redrawn; `storage-hierarchy.svg` gets the two resumption rows |
| `AGENTS.md` | U18, F3 | internal packages; the `pkg/` list |
| `cmd/relay/assets/config.toml`, `Dockerfile` | RFC009 -> RFC011 | changed in code commits, not `docs:` commits |
| `docs/RED_TEAM_REVIEW.md`, `CHANGELOG.md` | none | changed only if the maintainer asks |

## 12. Open Questions

Collected from RFC007 to RFC011, plus one that crosses into RFC004. Each
owning RFC states the question in full.

1. **`fingerprint.Emoji`** (RFC007). When a later UI item removes emoji from
   the remaining surfaces (share card, peer lists, settings), delete
   `fingerprint.Emoji`, or keep it as a labelled identicon?
2. **Prompts for user-initiated dials** (RFC007). The daemon's outbound
   verifier (`outboundVerifier`) is not held back by prompts that inbound
   peers keep open, so an inbound flood cannot stop the user from reaching a
   peer. The proposed limits (section 5.3) apply to every prompt. Should the
   initiator side of a user's own dial be exempt from the one-open-prompt
   limit and from the per-minute rate?
3. **Source filter on broker P2P listeners** (RFC008, RFC011). The current
   clients pass KCP packets on a broker punch socket only from IPs that a
   PEER_MATCHED named (bus `punchFilter`, daemon `p2pListener.admitted`).
   RFC008 gives broker listeners no knock key and applies
   `UDPWithSourceFilter` to direct P2P only; RFC011 delivers the
   authenticated `Match.Peer` either way. Should the listener feed those IPs
   into `UDPWithSourceFilter` for a match window, or rely on the path-layer
   caps and RFC010's `ExpectPeer`?
4. **Relay key notice** (RFC009). Storing a key fetched over verified TLS
   trusts a TLS-terminating CDN for the first contact. No prompt is shown
   either way; should clients show a one-time "new relay key stored" notice?
   `FirstContact()` gives them what they need to show one.
5. **Bus pair gate** (RFC010). The bus rejects a wrong key on its static relay
   and broker listeners through an application-level gate that runs after
   the verifier (`peergate.go`, `pinRelayListener`, `admittedBy`). With
   `PeerConstraint` the library rejects the same keys before the verifier.
   Do the bus commits delete the gate or keep it as a second check? (On
   dials, RFC007's `DialWithPeerKey` supersedes `pinPeer`.)
6. **Relay token together with a peer key** (RFC010). The bus dials a relay
   token given together with a peer and pins the peer (`relayDialToken`,
   `pinPeer`); RFC010 makes the daemon reject `token` with `peer_pub_b64` as
   `invalid_params`. Should the bus reject the combination too, or should both
   clients accept it as `WithToken` plus `WithExpectedPeer`?
7. **Broker server read buffer** (RFC011). Under the proposed read loop
   (section 5.3), a datagram larger than 2,048 bytes fails the read on
   Windows with `WSAEMSGSIZE` (the REL-01 pattern), so a stream of oversize
   datagrams would hold the loop at one read per 100 ms. Should the loop
   change to a 65,536-byte buffer, as the `Endpoint` uses, or treat
   `WSAEMSGSIZE` as a dropped packet without backoff?
8. **RFC004 on RFC007** (RFC004, RFC007). RFC004's initial ratchet setup reads
   inputs RFC007 removes (`mlkemSecret`, the two handshake salts, the
   session-static X25519 keys) and uses `pkg/exchange.ECDH`, which F2 deletes.
   If RFC004 is taken up, it needs a root secret from RFC007's key schedule
   (an exporter label or a master-derived secret) and `crypto/ecdh` directly.

## 13. Deferred Across the RFCs

| Item | RFC | Reason |
| ---- | --- | ------ |
| Contact-only listeners | future RFC | Maintainer decision 3; RFC007 keeps the `tag` field and the reserved salt |
| Post-quantum signatures (ML-DSA) | RFC007 | Not in the dependency set; `DialWithResumeOnly` gives PSK authentication for resumed sessions meanwhile |
| PAKE for human passwords | RFC009 | Not in the dependency set; generated access keys remove the need (decision 2) |
| Relay key rotation with overlap | RFC009 | Needs an authenticated next-key announcement; `key_hint` is on the wire so it needs no version change |
| Post-quantum relay authentication | RFC009 | An ML-KEM static key (1,184 bytes) does not fit in an address |
| Channel binding from the UDP path into the handshake | RFC007, RFC008 | Gives no property beyond DoS; the `binding` label is reserved |
| Stateless reset on the UDP path | RFC008 | Covers a server restart only with a persisted reset key; CLOSE, read deadlines and resumption cover the rest |
| Static token rotation | RFC010 | Protects only against the service operator, who can link by IP; `n` is reserved |
| Post-quantum pair secret | RFC010 | Needs a peer-state sync so both sides keep the same mixed-in PSK |
| Hybrid KEM and forward secrecy for broker traffic | RFC011 | Over 1 KB per REGISTER; protects RIDs and address pairing only |
| IPv6 broker | RFC011 | Needs per-family cookies and limits; the wire already carries 18-byte addresses |
