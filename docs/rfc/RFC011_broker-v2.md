# RFC: Broker v2: Cookies, Proof of Possession and Authenticated Notifications

**Status:** Draft

**Target:** Kamune Protocol Specification before v1.0 (not scheduled)

**Relates to:** §9.2 (UDP (via KCP)), §9.3 (Relay); RELAY.md "Broker:
STUN-Echo and Signal Introduction", "Configuration Reference", "Deployment
Patterns" and "Known Limits"; RFC006 (overview), RFC008 (UDP path), RFC009
(relay leg), RFC010 (tokens)

---

## 1. Summary

Replace the UDP broker protocol (`"KBRK"`, version `0x01`) with version
`0x02`:

- Every broker reply other than the cookie retry is sealed under `K_DOWN`,
  derived from `X25519(e_c, S)`, where `e_c` is a fresh client ephemeral
  for each REGISTER and `S` is the relay static key (RFC009) that the
  client pins in the broker address. A third party that knows every public
  value cannot make the client accept such a packet, and a match is
  accepted at most once per registration ID.
- The broker does no asymmetric work and keeps no state for a source until
  the source returns a stateless cookie bound to its address and its
  ephemeral. Every reply to an unverified source is smaller than the
  request.
- A REGISTER is sealed to the broker key. It carries the address the client
  claims inside the AEAD, the public key of the client's next ephemeral, and
  a cookie whose broker-minted sequence number orders the REGISTERs of a
  slot. A captured REGISTER replayed from elsewhere fails the cookie; one
  replayed from its own source is answered from a cache without a state
  change; one withheld and released later is rejected as stale.
- The token never travels. The broker sees a 32-byte rendezvous ID (`RID`)
  derived from RFC010's 32-byte token and the broker key.
- The client library runs all broker traffic of a socket through one
  `Endpoint`, which also hands the socket's other datagrams to RFC008's UDP
  path layer, and each `Registration` refreshes itself until it is closed
  or matched.

The broker is symmetric: a client knows a 32-byte token shared with its
peer, registers it with a role (`LISTEN` or `DIAL`), and the broker matches
one `LISTEN` with one `DIAL` on the same `RID`. Broker-assigned random
tokens (`TOKEN_ASSIGNED`) are gone: a client that wants a random token calls
`rendezvous.NewRandomToken()` (RFC010) and shares it out of band.

This RFC is one part of the pre-v1.0 protocol rework described in RFC006;
the rework is not implemented now. The change is a wire-incompatible hard
cut, as RFC004 is, and no backward compatibility is kept. The v2 broker and
v2 clients drop v1 packets (`VER=0x01`), and the v1 API of
`pkg/relayconn/broker` is deleted, not deprecated.

## 2. Current Behavior

### 2.1 Wire format

The v1 format is described in RELAY.md "Broker: STUN-Echo and Signal
Introduction" and implemented in `pkg/relayconn/broker/codec.go`. Every
packet starts with `"KBRK"`, `VER = 0x01` and an opcode:

| Opcode | Packet    | Size                                      | Content                                                                                 |
| ------ | --------- | ----------------------------------------- | --------------------------------------------------------------------------------------- |
| `0x01` | STUN_ECHO | 6                                         | Header only. The broker answers with ASCII `ip:port\0`, the packet's source address     |
| `0x02` | REGISTER  | 60                                        | 16-byte token, the client's X25519 public key, a claimed IPv4 address and port, in clear |
| `0x03` | NOTIFY    | 99 (`TOKEN_ASSIGNED`), 133 (`PEER_MATCHED`) | Broker ephemeral X25519 public key, 24-byte nonce, XChaCha20-Poly1305 ciphertext         |

The NOTIFY key is `SHA-256(X25519(client key, broker ephemeral))`, and the
client takes the broker ephemeral from the packet header
(`Client.openNotify`). The broker has no long-term key. Anyone who knows a
client's X25519 public key, which every REGISTER carries in clear and every
`PEER_MATCHED` hands to the matched peer, can seal a NOTIFY that the client
accepts, and a captured NOTIFY decrypts again when replayed. The only check
left is the UDP source address.

A token longer than 16 bytes travels as its first 16 bytes (`BuildRegister`,
`WireToken`). Static tokens are `relayconn.TokenFromKeys`, the SHA-256 of
the two identity keys (32 bytes), so they travel cut to 16 bytes, and
clients compare matches with `TokenMatches`. A REGISTER with an all-zero
token is random mode: the broker picks a 16-byte token and returns it in
`TOKEN_ASSIGNED`.

### 2.2 Broker server

`cmd/relay/internal/broker` runs one UDP socket (`udp4`) on one goroutine:

- `handleStaticRegister` keys the registry by the 16-byte token. A REGISTER
  with the held X25519 key refreshes the entry and moves it to the packet's
  source when the source IP is the held IP (any port), or when the held
  address has gone 35 s without a refresh (`rebindAfter`); a REGISTER with
  another key matches the entry, sends `PEER_MATCHED` to both sides and
  deletes the entry. The claimed IPv4 address and port are checked for form
  only; the broker records the source.
- `handleRandomRegister` creates an entry for every all-zero-token REGISTER
  and answers with `TOKEN_ASSIGNED`.
- `sendNotify` generates a fresh X25519 key pair for every NOTIFY.
- Entries expire `registration_ttl` (default 60 s) after their last REGISTER
  and are purged every 500 ms; the registry holds at most 100,000 entries
  (`defaultMaxRegistry`), and a REGISTER that would add one to a full
  registry is dropped.
- `run.newBrokerLimits` builds two per-IP limiters from `[rate_limit]`, one
  for STUN_ECHO and one for REGISTER, separate from the hub's limiter. Both
  are keyed by the unverified UDP source. `rate_limit.disabled = true` turns
  them off.
- `Run` reads into a 64 KiB buffer; after 16 failed reads in a row it waits
  100 ms before each further read until one succeeds or times out.

### 2.3 Client library and clients

`pkg/relayconn/broker` exports `Client` (`NewClient`, `NewClientWithKey`,
`Echo`, `Register`, `Listen`, `PublicKey`), the socket helpers `EchoOn`,
`RegisterOn` and `ReadNotify` (`socket.go`), and the codec. `Register` and
`Listen` are marked deprecated: `Register` sends from a socket it closes on
return, and `Listen` reads a loopback socket that never sends a REGISTER.
The socket helpers drop packets from any address other than the broker's
and fail after 16 failed reads in a row.

Both shipped clients run the broker on their punch sockets:

- **Keys.** The daemon's `BrokerClient` gives each token its own X25519 key
  (`newBrokerIdentity`), kept while the token is registered and for 2
  minutes after (`brokerIDHold`). The bus's `BrokerClient` holds one X25519
  key for the whole process; `NewApp` creates it and exits the process if
  key generation fails.
- **Address discovery.** Before the first REGISTER, a client sends
  STUN_ECHO from the punch socket and claims the reported address in every
  REGISTER. The bus uses `Client.EchoOn`; the daemon's own `echoFrom` takes
  the first datagram from any source as the reply.
- **Listener.** `newP2PListener` binds the punch socket, registers its
  first token (random mode when it has none: the daemon through
  `RegisterOn`, the bus through `readTokenAssigned`) and starts
  `kcp.ServeConn` behind a wrapper (daemon `punchConn`, bus `punchFilter`)
  that hands broker packets to the listener, kicks the matched peer, and
  passes KCP packets only from hosts a `PEER_MATCHED` named. It re-sends a
  REGISTER for every token every 30 s. `RegisterToken` and
  `UnregisterToken` add and drop tokens; v1 has no withdraw message, so the
  broker keeps a dropped token until its TTL ends.
- **Dialer.** `WaitMatch` opens a fresh punch socket, echoes, registers,
  re-sends the REGISTER every 25 s and returns on the first `PEER_MATCHED`
  whose token passes `TokenMatches`. Both clients bound the wait at 30 s
  (daemon `defaultMatchTimeout`, bus dial path). `HolePunch` then sends NAT
  kicks and opens `kcp.NewConn4` on the same socket.
- **Token generation.** `GenerateP2PToken(brokerAddr, peerPubB64)` requires
  a running p2p server on that broker in both clients. The bus generates a
  fresh random token on every call; the daemon returns an existing random
  token for the same broker when it has one.

## 3. Motivation and Findings Closed

### 3.1 Problems

| Problem today                                                                                       | v2 mechanism                                                                                                                                                                                                                                                              | Pattern reused                                                                                |
| --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| NOTIFY sealed with anonymous ECDH; anyone who knows the client X25519 key forges or replays it      | Every downlink packet except COOKIE is sealed under `K_DOWN`, derived from `X25519(e_c, S)` where `S` is the relay static key the client pins (RFC009). Fresh client ephemeral per REGISTER; one-shot acceptance per registration ID                                                    | Noise `NK` first message (`-> e, es`); TLS 1.3 `HKDF-Expand-Label`                            |
| Captured REGISTER replayed from another source moves or squats the entry                            | Cookie bound to source address and client ephemeral, inside the AEAD transcript; the client also claims its address inside the AEAD; broker-minted sequence numbers order the REGISTERs of a slot; a cache of recent REGISTERs answers replays without state change      | DTLS HelloVerifyRequest, QUIC Retry; WireGuard cookie bound to the initiator message           |
| X25519 and larger replies for unverified sources                                                    | No asymmetric crypto and no state until a cookie verifies. Every reply to an unverified source is smaller than the request. Per-verified-IP X25519 buckets under a global cap                                                                                            | QUIC anti-amplification rule                                                                  |
| Spoofed random-mode REGISTERs fill the registry                                                     | Random mode removed; admission only after cookie and AEAD verify; per-IP and per-/24 live-slot caps checked on every move; WITHDRAW never creates state; retained entries counted and evictable                                                                         |                                                                                               |
| `Client.Listen` and `Client.Register` use sockets the broker never sends to                         | One `Endpoint` per caller socket; all broker traffic for a registration runs on it; the library refreshes on that socket                                                                                                                                                 |                                                                                               |
| Broker limiter keyed by spoofable source                                                            | Broker buckets keyed by cookie-verified source only; `[rate_limit]` no longer applies to the broker                                                                                                                                                                      |                                                                                               |
| 16-byte truncated tokens                                                                            | 32-byte rendezvous ID `RID` derived from RFC010's 32-byte token and the broker key                                                                                                                                                                                       |                                                                                               |
| A slot moves to a new IP only after 35 s without a refresh, so a matched peer can be sent a dead address | A REGISTER with a newer cookie moves the slot at once; the cookie, the claimed address and the sequence number replace the quiet period                                                                                                                             |                                                                                               |

### 3.2 Red-team findings

IDs refer to `docs/RED_TEAM_REVIEW.md`. "Current tree" notes what the v1
code already does about a finding; v2 replaces that code.

| Finding        | Status                                          | How v2 closes it                                                                                                      | Current tree                                                                                                  |
| -------------- | ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| RC-05          | Closed                                          | Downlink sealed under `K_DOWN` from the pinned relay key and a fresh ephemeral; one-shot per `REG_ID` (§7.5, §8, §10.5) | Unchanged: NOTIFY key from the header ephemeral                                                               |
| REL-12         | Closed                                          | Cookie bound to source and ephemeral; claimed address inside the AEAD; broker sequence numbers; recent cache (§7, §9.3, §9.4) | Same-key moves to another IP wait 35 s (`rebindAfter`); no proof of possession                               |
| REL-15         | Closed                                          | No X25519 or state before a cookie; replies to unverified sources smaller than requests (§7.6, §9.3)                   | Unchanged: every NOTIFY costs an X25519 key generation and exchange                                           |
| REL-06         | Closed                                          | Random mode removed; admission after cookie and AEAD; per-IP and per-/24 caps on every move (§9.4)                     | Registry capped at 100,000 without a scan on insert; random mode and spoofed fill remain                      |
| RC-11          | Closed                                          | One `Endpoint` per socket (§10.3, §10.4)                                                                              | `Client.Listen` deprecated, still exported                                                                    |
| RC-12          | Closed                                          | No throwaway sockets; immediate match returned by `Register` (§10.3)                                                  | `Client.Register` deprecated; shipped clients register from their punch sockets                               |
| REL-07         | Closed                                          | Broker buckets keyed by cookie-verified source only (§9.6)                                                            | Broker has its own echo and REGISTER limiters, keyed by unverified source                                     |
| DMN-12         | Closed                                          | Fresh ephemeral per REGISTER; no client clock on the wire (§8.5)                                                      | Daemon uses one key per token; bus uses one key per process                                                   |
| DMN-14         | Closed                                          | 30 s match timeout in the daemon dial path (§11.3)                                                                    | Daemon already bounds the match wait at 30 s                                                                  |
| DMN-18, BUS-23 | Closed                                          | Throwaway-socket registration deleted; `generate_p2p_token` needs a running p2p listener (§11.3, §11.4)               | Both clients already require a running p2p server                                                             |
| BUS-35         | Closed                                          | No echo exchange; downlink accepted only from the broker address and only if it authenticates (§10.5)                 | Bus filters the echo reply by source (`EchoOn`); daemon `echoFrom` does not                                   |
| BUS-41         | Closed                                          | Random p2p tokens from `rendezvous.NewRandomToken()` on every call (§11.3)                                            | Bus already fresh per call; daemon returns an existing random token                                           |
| DOC-02, DOC-10 | Closed                                          | Documentation pass (§17)                                                                                              | RELAY.md already says the broker records the source; DAEMON.md still shows `wss://` broker addresses          |
| RC-07          | Closed jointly with RFC010                      | No 16-byte wire token; clients never compare tokens on the wire; `RID` from the 32-byte token (§8.1)                  | Clients compare the 16-byte wire form with `TokenMatches`                                                     |
| DMN-07, BUS-03 | Closed                                          | `Registration.Close` stops the refresh and sends WITHDRAW (§10.7)                                                     | `UnregisterToken` stops the refresh; the broker keeps the token until its TTL ends                            |
| RC-04          | Partly closed                                   | Passive-observer part: the token is never on the wire. The derivation part is RFC010's                                | Token in clear in every REGISTER                                                                              |
| DMN-21, BUS-06 | Partly closed (broker part)                     | The Endpoint consumes broker packets; the listener reads MATCHED and kicks. KCP source filtering and the dialer's kick and timeout handling are RFC008's | Both listeners already read `PEER_MATCHED` on the punch socket and kick                                       |
| BUS-27         | Partly closed (`RegisterP2PDialer` part)        | The method stays deleted; v2 adds no replacement                                                                      | `RegisterP2PDialer` is already gone from the bus                                                              |

## 4. Decisions

### 4.1 Scope and rollout

| Question         | Decision                                                                                                                                                                       |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Schedule         | Not implemented now. The RFC is a Draft targeting the specification before v1.0, not scheduled                                                                                 |
| Compatibility    | **Wire-incompatible hard cut**, as RFC004 is. No backward compatibility and no version negotiation; v1 packets (`VER=0x01`) are dropped by the v2 broker and v2 clients; the v1 Go API is deleted, not deprecated            |
| Other protocols  | Part of the pre-v1.0 rework in RFC006, together with RFC007 (handshake), RFC008 (UDP path), RFC009 (relay leg) and RFC010 (tokens); each is a hard cut of its own wire format |

### 4.2 Design decisions

| Question                         | Decision                                                                                                                                                                         |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Broker key                       | One X25519 key per relay, shared by the relay leg and the broker (RFC009). A broker in its own process is a relay with only `[broker]` enabled and its own `data_dir`            |
| Key distribution                 | The key travels in the broker address (`?rk=`). No first contact: an address without `rk` is an error (`ErrBrokerKeyRequired`); no key fetch, no key store lookup                 |
| Address syntax                   | `[udp://]host:port?rk=rk1-...`, parsed by this RFC with the `rk=` spelling of RFC009's relay addresses                                                                           |
| Client authentication of the broker | Static-ephemeral DH with the pinned key, modelled on Noise `NK` and written with HKDF-SHA512 (`crypto/hkdf`)                                                                   |
| Return routability               | Stateless cookie (DTLS and QUIC pattern), bound to source address and client ephemeral; a cookieless REGISTER asks for it                                                       |
| REGISTER order                   | Broker-minted cookie sequence (`CTS`); no client timestamp on the wire                                                                                                           |
| Random tokens                    | Generated by the client (`rendezvous.NewRandomToken()`), fresh on every call. Broker-assigned tokens removed                                                                     |
| Static broker tokens             | Directional tokens from RFC010: `ListenToken` for `RoleListen`, `DialToken` for `RoleDial`                                                                                       |
| Socket arrangement               | One mode: the Endpoint owns the read side of the punch socket; RFC008's layer and kcp-go read `Endpoint.PacketConn()`                                                            |
| Post-quantum                     | Classical X25519 only (§8.6); hybrid broker KEM deferred                                                                                                                         |
| IP version                       | The broker listens on `udp4` only; the wire carries 18-byte addresses for a later IPv6 version                                                                                  |
| Access control                   | None, as today: RFC009's access keys (`psk1-`) apply to the relay leg, not to the broker                                                                                        |
| `[rate_limit]`                   | No longer applies to the broker; the broker has its own limits (§9.6, §12)                                                                                                       |

### 4.3 Proposed defaults

| Item                                              | Proposed default                                                             | Where |
| ------------------------------------------------- | ---------------------------------------------------------------------------- | ----- |
| Registration TTL                                  | 60 s (configurable 20 s to 1 h)                                              | §9.7, §12 |
| Cookie lifetime                                   | 60 s; secret replaced every 10 minutes, previous kept until the next replacement | §7.2 |
| Seals per ephemeral                               | 3 (`MaxEphemeralSeals`)                                                      | §7.4 |
| Broker limits                                     | §9.6 table: X25519 10/s burst 60 per verified IP, 4,000/s burst 400 global with a reserve of 100, 256 live slots per IP, 2,048 per /24, 100,000 entries, 200,000 recent entries, `cookie_rate` unlimited | §9.6 |
| Broker memory at those caps                       | About 33 MB for a full registry plus about 50 MB for a full recent cache (about 85 MB) | §9.6 |
| Listener refresh                                  | `min(TTL/2, 30 s)`, ±10 % jitter                                             | §10.7 |
| Dialer refresh                                    | Every 5 s, ±10 %, until matched                                              | §10.7 |
| Match wait in the clients                         | 30 s                                                                         | §11 |
| `Register` without a context deadline            | 5 s                                                                          | §10.3 |
| Broker server read loop                           | 2,048-byte read buffer, 500 ms read deadline, the v1 read-error backoff (after 16 failed reads in a row, 100 ms before each further read); the buffer size is open question 2 | §9.7, §18 |

The limits are design values; a benchmark of `Handle` on the reference relay
host sets the release values (§16). Operators can raise or lower each one.

### 4.4 Alternatives not adopted

| Alternative                                                                  | Reason                                                                                                                                                                                                                                                                                       |
| ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `max_registrations_per_ip` of 64                                              | One public IPv4 address of a carrier-grade NAT serves many subscribers; 64 live slots would lock out a handful of daemons with a few dozen contacts each. Quota checks on every move and the per-/24 cap (2,048) bound a single network. The default stays 256; operators can lower it        |
| Count retained entries against the IP that created them                       | Retained entries hold no live slot and are evicted first when the registry is full; `floor` keeps replay safety after eviction. Charging them would need a creator field and a second counter, and would let a self-matching attacker on a shared NAT spend its neighbours' quota            |
| Never replace an authenticated cookie with one from a COOKIE packet for 90 s  | Cookies are bound to one ephemeral, so a client never holds a reusable cookie. The claimed-address rule (§10.6) makes a foreign cookie useless instead                                                                                                                                       |
| A post-AEAD success quota next to a pre-DH attempt budget                     | With the cookie bound to the ephemeral and the recent cache, a passive observer cannot make the broker spend X25519 for the victim's IP (§14.2). One per-IP bucket charged before X25519 bounds CPU per IP                                                                                 |
| Prefer REGISTERs whose `RID` already has a live slot                           | `RID` is inside the AEAD and unknown before the X25519 the bucket protects. The closest pre-DH signal is used: the source IP holds a live slot (§9.3 step 4)                                                                                                                                |
| Counter nonce for REGISTER                                                     | A counter nonce is still catastrophic if reused under one key; `wire.Ephemeral` removes the possibility instead (§7.4)                                                                                                                                                                      |
| A process-wide set of live `(RID, role)` inside `Client`                        | It needs every caller in a process to share one `Client` per broker, a cache or a package global. Directional tokens remove the static case; the rest is caught per Endpoint (`ErrSelfMatch`), by dropping `Peer == Self`, and by the clients' `p2p_self_dial` check                      |
| One cookie fetch in flight per Endpoint, shared by its registrations           | Cookies are bound to one ephemeral and each registration has its own ephemeral chain. Lockstep refreshes are spread by ±10 % jitter and the per-IP burst of 60                                                                                                                              |
| A HELLO packet before REGISTER                                                 | It has no consumer once the cookieless REGISTER asks for the cookie                                                                                                                                                                                                                         |
| A separate `[broker] key_file` and a `broker_pin` client field                 | The relay key (RFC009) serves the broker, and carrying it in the address keeps every client signature that takes `broker_addr` unchanged                                                                                                                                                   |

## 5. Terminology

| Term                  | Definition                                                                                                                       |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **Broker key**        | The relay static X25519 key of RFC009. `S_priv` is the private key, `S_pub` the public key (`relayleg.PublicKey`)                 |
| **Ephemeral**         | A client X25519 key pair used for one logical REGISTER. `e_c` is its private key, `E_C_PUB` its public key                       |
| **NEXT**              | The public key of the ephemeral the client will use for its next REGISTER of the same registration                               |
| **Token**             | RFC010's 32-byte `rendezvous.Token`, shared by the two peers. Never sent to the broker                                           |
| **RID**               | Rendezvous ID: 32 bytes derived from the token and `S_pub` (§8.1). The broker's registry key                                     |
| **Role**              | `LISTEN` (the side that runs the p2p listener) or `DIAL`                                                                         |
| **Entry**             | The broker's state for one `RID`: two slots, one per role                                                                        |
| **Slot**              | One role of an entry: the address, keys and sequence number of the REGISTER that set it                                         |
| **Live**              | A slot that counts against quotas and can be matched: `live` set and not expired                                                |
| **Holder**            | The client whose REGISTER set a live slot                                                                                        |
| **Cookie**            | 24 bytes minted by the broker for a (source address, `E_C_PUB`) pair (§7.2)                                                     |
| **CTS**               | Cookie sequence: broker microseconds since process start, strictly increasing                                                  |
| **TH**                | SHA-512 of the first 62 bytes of a REGISTER (header, `E_C_PUB`, cookie)                                                          |
| **K_UP, K_DOWN, REG_ID** | Per-REGISTER upload key, download key and 8-byte registration ID (§8.2)                                                      |
| **Recent cache**      | The broker's cache of recently processed REGISTERs, keyed by `E_C_PUB`, consulted before any X25519                              |
| **floor**             | The highest slot sequence of any evicted entry; the starting sequence of a new entry                                             |
| **Endpoint**          | The client object that owns a UDP socket's read side and carries all broker traffic on it                                        |
| **Registration**      | One token registered in one role on one Endpoint                                                                                 |

## 6. Interfaces from Other RFCs

### 6.1 RFC009: relay static key

Server:

```go
// cmd/relay/internal/services
func (s *Service) StaticKey() *relayleg.PrivateKey

// pkg/relayconn/relayleg
func (k *PrivateKey) PublicKey() PublicKey
// HKDF-Extract(SHA-512, salt = domain || pk_R, ikm = X25519(sk_R, peer)).
// domain must start with "kamune broker v2" (ErrKeyUsage otherwise).
func (k *PrivateKey) ExtractShared(domain string, peer []byte) ([]byte, error)
```

Client:

```go
type PublicKey [32]byte
func ParsePublicKey(s string) (PublicKey, error) // "rk1-...", ErrInvalidRelayKey
func (k PublicKey) String() string
func (k PublicKey) Display() string
func (k PublicKey) ECDH() (*ecdh.PublicKey, error)
func KeyHint(k PublicKey) [4]byte
```

Rules for this RFC's use of the key, as RFC009 sets them:

- the broker computes its PRK only through
  `key.ExtractShared("kamune broker v2 dh ", E_C_PUB)`;
- every other label of this RFC starts with `kamune broker v2 ` (§8.4);
- the key never signs;
- anything sealed to `pk_R` is classical only (§8.6).

Consequences:

- `run.newBroker` cannot fail for lack of a key: RFC009 loads or creates the
  key before the broker starts, even when only `[broker]` is enabled.
- This RFC does not need RFC009's `LoadPrivateKeyFile` for configuration;
  the golden vectors use it to load a fixed key (§10.1).
- The bus's "empty to fetch" behaviour of RFC009's relay form does not apply
  to the broker field.

### 6.2 RFC010: tokens

```go
// pkg/rendezvous
const TokenSize = 32
type Token struct{ /* 32 bytes and a derived flag; prints as its handle */ }
type ServiceID [32]byte
func NewRandomToken() (Token, error)
func (t Token) Bytes() []byte  // wire accessor, for DeriveRID only
func (t Token) Handle() string // only token string that may be logged
func (t Token) IsZero() bool
func NewServiceID(pub [32]byte) ServiceID
var ErrTokenZero error

// PairKey (static tokens), directional:
func (k *PairKey) ListenToken(p Purpose, svc ServiceID) Token // self listens
func (k *PairKey) DialToken(p Purpose, svc ServiceID) Token   // peer listens
```

This RFC provides `(*broker.Client).ServiceID() rendezvous.ServiceID`,
computed as `rendezvous.NewServiceID(a.Key)` from the broker address key.
Since one key serves relay and broker, `relay_id == broker_id`, and
RFC010's purpose strings keep relay and broker tokens apart.

| Item                              | Contract                                                                                                                                                                                                                                                                 |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Random broker tokens              | No `TOKEN_ASSIGNED`. Random tokens: `rendezvous.NewRandomToken()` on the listener, fresh on every call                                                                                                                                                                   |
| MATCHED                           | Carries no token and no key. Each `Registration` has one token; a match arrives on that registration's channel                                                                                                                                                         |
| Dedupe                            | None across registrations: no epochs, so one registration per (pair, role). This RFC's repeat suppression (§10.5) is per registration                                                                                                                                  |
| `Register`                        | `Endpoint.Register(ctx, tok rendezvous.Token, role Role) (*Registration, error)`. The zero token is refused (`rendezvous.ErrTokenZero`)                                                                                                                                |
| `ValidateUserToken`               | Deleted by RFC010; not used here                                                                                                                                                                                                                                         |
| Roles                             | The side that runs the p2p listener (RFC008's `ListenUDP`, or `kcp.ServeConn` before RFC008 lands) registers `RoleListen`; the side that dials registers `RoleDial`. LISTEN never matches LISTEN                                                                       |
| Static broker tokens              | **Directional**: `pk.ListenToken(rendezvous.Broker, svc)` for `RoleListen`, `pk.DialToken(rendezvous.Broker, svc)` for `RoleDial`, `svc = client.ServiceID()`. A's listen token for B equals B's dial token for A and differs from B's listen token, so a peer never matches itself and two listeners of one pair keep separate slots |
| `p2pListener.RegisterPair(id, pk)` | One registration per (listener, peer); the library refreshes it; no recomputation, no overlap                                                                                                                                                                          |
| bus `GenerateP2PToken`            | `GenerateP2PToken(peerPubB64)`; the listener's broker is implied (§11.4)                                                                                                                                                                                                 |
| bus `RegisterP2PDialer`           | Stays deleted; no frontend caller                                                                                                                                                                                                                                        |
| Expected peer                     | RFC010's client commits record the expected key per matched registration and wrap the KCP conns with `kamune.ExpectPeer`; this RFC's `Match` gives them `Peer`                                                                                                         |

RFC010's `pkg/rendezvous` lands before this RFC's codec, so the codec uses
`rendezvous.Token` from the start and needs no `[]byte` stand-in.

### 6.3 RFC008: UDP path layer and the punch socket

There is one socket arrangement. The Endpoint owns the read side of the
punch socket; RFC008's path layer and kcp-go sit on `ep.PacketConn()`:

```go
// listener
ep, _ := client.NewEndpoint(conn)
reg, _ := ep.Register(ctx, tok, broker.RoleListen)
ln, _ := kamune.ListenUDP(ep.PacketConn(), opts...)   // RFC008

// dialer
ep, _ := client.NewEndpoint(conn)
reg, _ := ep.Register(ctx, tok, broker.RoleDial)
m, _ := reg.Wait(ctx)
c, _ := kamune.DialUDP(ctx, ep.PacketConn(), m.Peer)  // RFC008
```

RFC008's `ListenUDP` and `DialUDP` take `ep.PacketConn()` and have no
foreign-packet handler: broker packets never reach them. The listener
receives `Match.Peer` and may use it for RFC008's `UDPWithSourceFilter`
(§18).

The `PacketConn` contract that RFC008 and kcp-go rely on is in §10.4. Close
semantics with RFC008's listener: it closes `pc` when its last path ends,
and `pc.Close()` closes the Endpoint. The daemon and the bus therefore
close a listener in this order: `Registration.Close()` for every
registration (WITHDRAW), then RFC008's listener; live paths keep the socket
until they end.

Broker datagrams start with `0x4B` (`'K'`), outside RFC008's reserved
first-byte range `0x01` to `0x0F`; `0x00` is the NAT kick. The Endpoint
consumes broker datagrams before RFC008's layer sees anything.

This RFC and RFC008 both edit `sendNATKick`, `HolePunch`, `directp2p.go`
and the DAEMON.md transport table. This RFC changes only signatures
(`sendNATKick(ctx, pc net.PacketConn, peer netip.AddrPort)`) and lands
first; RFC008 then removes the kicks its HELLO retransmissions replace.

### 6.4 RFC007: handshake

None. The broker says nothing about peer identity; the kamune handshake on
the punched connection authenticates the peer. A malicious broker can still
send a wrong `Match.Peer` (§13.2).

## 7. Wire Format

### 7.1 Header and addresses

All integers are big endian. All packets start with a 6-byte header:

```
offset size field
0      4    MAGIC  "KBRK" (0x4B 0x42 0x52 0x4B)
4      1    VER    0x02
5      1    TYPE   0x01 COOKIE    broker -> client
                   0x02 REGISTER  client -> broker
                   0x03 SEALED    broker -> client
```

The magic stays because clients demultiplex broker packets from the UDP
path layer on one socket (§10.4).

`ADDR (18) = IP (16, IPv4 as IPv4-mapped IPv6) | PORT (2)`. The v2 broker
listens on `udp4` only (§15); the 18-byte form keeps the format when IPv6
is added. Both sides normalise with `netip.AddrPort` and `Addr().Unmap()`
before comparing or encoding.

### 7.2 Cookie value (24 bytes)

```
0   8   CTS   cookie sequence: broker microseconds since process start,
              strictly increasing per broker process
8   16  MAC   HMAC-SHA256(cookie_secret,
                "kamune broker v2 cookie" || CTS || ADDR(src) || E_C_PUB)[:16]
```

Minting: `CTS = max(now_us, last_CTS + 1)`, where `now_us` is
`now().Sub(start)` in microseconds (Go's monotonic reading; never wall
time).

Validation, in order:

1. the cookie is not all zero;
2. `CTS` is not above the last minted `CTS` (`CTS <= last_CTS`);
3. the age `now_us - CTS` (0 if negative) is at most
   `CookieLifetime = 60 s`;
4. `hmac.Equal` against the current or the previous `cookie_secret`.

`cookie_secret` is 32 bytes from `crypto/rand`, replaced every 10 minutes,
the previous one kept until the next replacement. A broker restart
invalidates every cookie (new secret, new `start`); clients recover through
the cookie retry.

`CTS` doubles as the order of REGISTERs on a slot (§9.4): a cookie is bound
to one ephemeral, each ephemeral is used for one logical REGISTER, and the
broker mints a client's next cookie only when it answers its previous
REGISTER, so cookie order is send order.

### 7.3 COOKIE (broker to client), 68 bytes

```
0   6   header, TYPE=0x01
6   16  ECHO      E_C_PUB[0:16] of the REGISTER that caused this reply
22  24  COOKIE    for (source address of that REGISTER, its E_C_PUB)
46  18  OBSERVED  source address of that REGISTER
64  4   KEY_HINT  relayleg.KeyHint(S_pub)
```

Sent in reply to a REGISTER whose cookie is missing, expired or wrong (a
retry, as in DTLS HelloVerifyRequest). COOKIE is not authenticated. The
client:

- matches `ECHO` against its outstanding REGISTERs, which stops blind
  off-path forgery as a STUN transaction ID does;
- ignores a COOKIE whose `KEY_HINT` differs from the hint of its pinned
  key;
- adopts `OBSERVED` only under the rule of §10.6.

An injected COOKIE can delay a registration; it cannot move a slot (§13.2).

### 7.4 REGISTER (client to broker), 174 bytes

```
0   6   header, TYPE=0x02
6   32  E_C_PUB   client ephemeral X25519 public key
38  24  COOKIE    all zero in a cookieless REGISTER
62  112 CT        XChaCha20-Poly1305(K_UP, nonce = 24 zero bytes,
                  plaintext = P (96), aad = bytes 0..62)
```

A **cookieless REGISTER** has `COOKIE` and `CT` all zero; the client seals
nothing for it. It is the client's first packet for a new ephemeral and gets
a COOKIE back.

Plaintext `P`:

```
0   32  RID       rendezvous ID (§8.1)
32  1   ROLE      0x01 LISTEN, 0x02 DIAL
33  1   FLAGS     bit 0 WITHDRAW; other bits 0
34  18  OBSERVED  the source address the client claims (§10.6)
52  32  NEXT      public key of the client's next ephemeral for this
                  registration; not all zero, not equal to E_C_PUB
84  12  PAD       zero
```

Ephemeral use rule (the zero nonce depends on it): an ephemeral seals at
most one plaintext per cookie, and at most 3 times in all
(`MaxEphemeralSeals`). Retransmissions resend the stored bytes. `K_UP`
depends on `TH`, which covers the cookie, so sealing the same ephemeral
under a different cookie uses a different key. The `wire.Ephemeral` type
enforces the rule (§10.1).

### 7.5 SEALED (broker to client), 118 bytes

```
0   6   header, TYPE=0x03
6   8   REG_ID   identifies the REGISTER whose K_DOWN seals this packet
14  24  NONCE    random, from crypto/rand
38  80  CT       XChaCha20-Poly1305(K_DOWN, NONCE, plaintext = D (64),
                 aad = bytes 0..14)
```

Plaintext `D`, 64 bytes, zero padded after the used fields:

| `D[0]` kind       | Fields after the kind byte                                                                                                 | Used |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------- | ---- |
| `0x01` REGISTERED | `TTL_S (4)` slot lifetime in seconds, 0 after a WITHDRAW; `OBSERVED (18)` source of the REGISTER; `COOKIE (24)` for (that source, `P.NEXT`) | 47   |
| `0x02` MATCHED    | `PEER (18)` the other slot's address; `SELF (18)` this slot's address; `COOKIE (24)` for (`SELF`, this slot's `NEXT`)      | 61   |
| `0x03` REJECTED   | `REASON (1)`; `RETRY_S (2)`; `COOKIE (24)` for (source, `P.NEXT`), zero for `BAD_FIELDS`                                   | 28   |
| `0x04` REPLACED   | none: another registrant took this slot                                                                                    | 1    |

Reject reasons:

| Code   | Reason       | Meaning                                                                          |
| ------ | ------------ | -------------------------------------------------------------------------------- |
| `0x01` | `STALE`      | Cookie sequence not above the slot's                                             |
| `0x02` | `FULL`       | Registry at capacity                                                             |
| `0x03` | `IP_QUOTA`   | Too many live slots for this IP or its /24                                       |
| `0x04` | `BAD_FIELDS` | Unknown role, reserved flag bits, all-zero `RID`, bad `NEXT`, non-zero padding   |

All SEALED packets have the same size, so an observer cannot tell an
acknowledgement from a match by length.

### 7.6 Sizes and amplification

| Trigger                                                    | Request | Reply                                                       | Ratio                                    |
| ---------------------------------------------------------- | ------- | ----------------------------------------------------------- | ---------------------------------------- |
| Cookieless REGISTER (unverified source)                    | 174     | COOKIE 68                                                   | 0.39                                     |
| REGISTER, bad or expired cookie (unverified)               | 174     | COOKIE 68                                                   | 0.39                                     |
| Good cookie, recent-cache hit (retransmission or replay)   | 174     | stored reply, SEALED 118                                    | 0.68                                     |
| Good cookie, X25519 bucket empty                           | 174     | none                                                        | 0                                        |
| Good cookie, AEAD fails or `OBSERVED != src`               | 174     | none                                                        | 0                                        |
| Accepted, no peer                                          | 174     | SEALED 118                                                  | 0.68                                     |
| Accepted, match                                            | 174     | SEALED 118 to sender, SEALED 118 to holder                  | holder address passed its own cookie     |
| Accepted, replaces another registrant                      | 174     | SEALED 118 to sender, REPLACED 118 to previous holder       | as above                                 |

Rule, checked by `TestNoAmplification` (§14.2): one request causes at most
one packet, smaller than the request, to its source; any other packet goes
to an address that passed a cookie and an AEAD check on its own REGISTER
for a live or just-matched slot.

v1 sizes for comparison, from REL-15: ECHO 34 to 50 bytes on the wire,
REGISTER 88 to 127, a match pair 176 to 322.

## 8. Key Schedule

### 8.1 Rendezvous ID

```
S_pub = broker static X25519 public key (32 bytes, RFC009's relayleg.PublicKey)
PRK_r = HKDF-Extract(SHA-512, salt = "kamune broker v2 rid " || S_pub,
                     ikm = token)
RID   = ExpandLabel(PRK_r, "rendezvous", "", 32)
```

`RID` is one-way from the token, specific to the broker key, and 32 bytes.
The broker never sees the token. Peers configured with different broker keys
get different RIDs and never match; both peers must use the same broker
address, key included, as they must use the same broker address today.

### 8.2 Per-REGISTER keys

Modelled on the first message of Noise `NK` (`<- s ... -> e, es`), written
with HKDF-SHA512 (`crypto/hkdf`) because no Noise library is in the
dependency set.

```
TH     = SHA-512(REGISTER bytes 0..62)            header || E_C_PUB || COOKIE
PRK    = HKDF-Extract(SHA-512, salt = "kamune broker v2 dh " || S_pub,
                      ikm = X25519(e_c, S_pub))   client
       = key.ExtractShared("kamune broker v2 dh ", E_C_PUB)   broker (RFC009)
K_UP   = ExpandLabel(PRK, "upload key",      TH, 32)
K_DOWN = ExpandLabel(PRK, "download key",    TH, 32)
REG_ID = ExpandLabel(PRK, "registration id", TH, 8)
```

`crypto/ecdh` returns an error for a low-order point on either side; the
broker treats it as an AEAD failure.

### 8.3 ExpandLabel

TLS 1.3 `HKDF-Expand-Label` (RFC 8446 section 7.1) with this RFC's prefix:

```
ExpandLabel(PRK, label, ctx, n) = HKDF-Expand(SHA-512, PRK, info, n)
info = uint16(n) || uint8(len(L)) || L || uint8(len(ctx)) || ctx
L    = "kamune broker v2 " || label
```

### 8.4 Labels and key separation

Every string of this RFC that feeds a KDF or MAC starts with
`kamune broker v2 `:

| Use                                     | String                                                                                       |
| --------------------------------------- | -------------------------------------------------------------------------------------------- |
| DH extract domain (RFC009 `ExtractShared`) | `kamune broker v2 dh ` (salt = string \|\| `S_pub`)                                       |
| RID extract salt                        | `kamune broker v2 rid ` \|\| `S_pub`                                                         |
| Expand labels                           | `kamune broker v2 rendezvous`, `... upload key`, `... download key`, `... registration id`   |
| Cookie MAC prefix                       | `kamune broker v2 cookie`                                                                    |

Neither salt is a prefix of the other (`d` and `r` differ at byte 17), and
the RID extract never touches the private key. The key hint in COOKIE is
RFC009's `relayleg.KeyHint`, the same function and purpose (naming the
relay key) as in the relay leg.

Sharing the X25519 key with the relay leg is safe for the reason RFC009
gives: the relay leg feeds `X25519(sk_R, enc)` only into HPKE's
`LabeledExtract("", "eae_prk", dh)` (empty salt, suite id `KEM\x00\x20`,
HKDF-SHA256); the broker feeds it only into HKDF-Extract with SHA-512 and
the salt above. Submitting a recorded relay-leg `enc` as `E_C_PUB` gives a
broker PRK unrelated to the relay-leg secret, and the broker reveals only
whether an AEAD under its own derived key opened, which the submitter cannot
make true without `e_c`. Test in §14.1.

### 8.5 Properties

- Only a holder of `S_priv` or `e_c` can compute `K_DOWN`. A third party
  that knows every public value cannot make a SEALED packet the client
  accepts (RC-05).
- Only a holder of the token (or `RID`) can produce a REGISTER that does
  anything to that rendezvous. The REGISTER is bound by AEAD to its cookie,
  which is bound to its source address and ephemeral, and the REGISTER
  claims that same address inside the AEAD (REL-12).
- Each REGISTER uses a new client key, and the client's clock never reaches
  the wire, so neither the key nor a clock offset links two rendezvous of
  one process (DMN-12). What still links them: one listener socket carries
  all the RIDs that listener holds, so the broker sees them share a source
  address. That is inherent; the broker must send matches to that address.
  The broker links the refreshes of one rendezvous through `RID`, which it
  must do to match.
- No forward secrecy against later theft of `S_priv`: a recorded REGISTER
  then yields `RID`, and the matching SEALED yields the peer addresses. A
  broker ephemeral per SEALED (Noise `ee`) costs one X25519 key generation
  and one exchange per downlink and protects only the pairing, since
  `S_priv` theft exposes the REGISTER anyway. Deferred (§15).

### 8.6 Post-quantum

The broker stays on X25519, as v1 is. An ML-KEM-768 encapsulation adds 1,088
bytes to every REGISTER and needs the client to hold the broker's
1,184-byte encapsulation key; a cookieless REGISTER would then need padding
past the size of whatever reply carries that key. Deferred (§15).

What a recording gives an attacker with a quantum computer: it recovers
`S_priv` from `S_pub`, decrypts every recorded REGISTER and SEALED, and so
gets every `RID` and every matched address pair. `RID` is an HKDF output and
does not give the token back, but RFC010's static tokens are classical: such
an attacker computes the pair secret of any two identities whose public keys
it knows, derives their broker tokens and RIDs, and so maps identity pairs
to IP addresses and meeting times for the whole recording. Message content
stays protected by RFC007's hybrid handshake, so the protocol keeps the
hybrid post-quantum confidentiality it has today. RFC010's deferred
post-quantum pair secret would close the identity-to-address mapping; a
hybrid broker KEM would close the rest.

## 9. Broker Server

### 9.1 Package layout

- `pkg/relayconn/broker/brokerserver` (root module, new): the packet
  handler, registry, recent cache, cookie jar and buckets. No socket, no
  config file. One instance runs on one goroutine.
- `cmd/relay/internal/broker`: the socket loop (read, call `Handle`, call
  `Tick` every 500 ms), config mapping and logging.
- `pkg/relayconn/broker/brokertest`: the same core on a loopback socket with
  limits off, for tests in `cmd/daemon` and `cmd/bus` (which cannot import
  `cmd/relay/internal`). There is no second copy of the rules.

### 9.2 State

```go
type slot struct {
	addr      netip.AddrPort // source of the REGISTER that set the slot
	eph, next [32]byte       // its E_C_PUB and P.NEXT
	kDown     [32]byte
	regID     [8]byte
	seq       uint64         // CTS of the last REGISTER that changed the slot
	expires   time.Time
	live      bool           // counted in perIP/perNet while true
	matchedAt time.Time      // zero unless the slot ended in a match
	peer      netip.AddrPort // the other slot's address at the match
}

type entry struct {
	slots  [2]slot       // index ROLE-1
	retain time.Time     // purge after this once no slot is live
	idle   *list.Element // position in idleList while no slot is live
}

type recent struct { // recent-REGISTER cache, keyed by E_C_PUB
	th       [32]byte // first 32 bytes of TH
	keys     wire.DownKeys
	reply    [64]byte // plaintext D sent for this REGISTER
	hasReply bool
	fails    uint8    // AEAD failures for this E_C_PUB
	expires  time.Time
}

type Server struct {
	key      *relayleg.PrivateKey
	jar      *wire.CookieJar
	registry map[wire.RID]*entry
	idleList *list.List                 // entries with no live slot, by age
	floor    uint64                     // see 9.4, row 1
	perIP    map[netip.Addr]int         // live slots per source IP
	perNet   map[netip.Prefix]int       // live slots per source /24
	recent   map[[32]byte]*recent       // plus a FIFO ring for expiry
	dhPerIP  map[netip.Addr]*rate.Limiter
	dhGlobal *rate.Limiter
	cookies  *rate.Limiter              // nil: unlimited
	opts     Options
	stats    Stats
}
```

Every slot keeps every field until its entry is purged. `perIP` and
`perNet` keys are deleted when they reach zero.

### 9.3 Per-datagram processing

1. Drop if `len < 6`, the magic is wrong, `VER != 0x02`, or
   `TYPE != 0x02`. Drop sources that are not IPv4, have port 0, or have an
   unspecified, multicast or broadcast IP. Drop if `len != 174`.
2. **Cookie.** If the cookie does not validate for `(src, E_C_PUB)`: take a
   token from `cookies` (if configured; drop when empty) and send COOKIE.
   Stop.
3. **Recent cache**, keyed by `E_C_PUB`:
   - hit, same `th`, `hasReply`: re-seal `reply` under the stored keys with
     a new nonce, take a `cookies` token, send it to `src`. Stop. No X25519,
     no bucket charge. This answers client retransmissions and any replay of
     a processed REGISTER, whatever its CT bytes, because `K_UP` depends
     only on `TH`;
   - hit, same `th`, no reply (an earlier copy failed the source check):
     drop;
   - hit with `fails >= 2`: drop;
   - otherwise continue (a different `th` under the same ephemeral is the
     client's rebuild after a cookie retry).
4. **X25519 admission.** The per-IP bucket for `src.Addr()` (created if
   absent; if `dhPerIP` holds `MaxDHKeys` entries, drop) and the global
   bucket must both hold a token. When the global bucket is under
   `DHReserve`, only IPs with `perIP > 0` may use it (they hold live slots
   and are refreshing). Check both, then take both. Else drop.
5. **Open.** `PRK = key.ExtractShared("kamune broker v2 dh ", E_C_PUB)`;
   derive keys; open `CT`. On any error: `recent[E_C_PUB].fails++`
   (inserting the entry if needed), drop.
6. **Fields.** Role in {1, 2}, reserved flag bits 0, `RID` not all zero,
   `NEXT` not all zero and not `E_C_PUB`, pad zero. Else reply REJECTED
   `BAD_FIELDS` and record it in the cache.
7. **Source claim.** `P.OBSERVED != src`: record the cache entry without a
   reply, count `BadSource`, drop.
8. **Registry** (§9.4). Send the resulting packets; record the sender's
   reply in the cache with `expires = now + CookieLifetime + 1 s`.

No X25519, registry read or registry write happens before step 2 passes for
`(src, E_C_PUB)`, and no registry write before step 5 opens the AEAD.

The recent cache holds at most `MaxRecent` entries. When it is full, the
oldest is evicted even if unexpired; that only makes a later replay of it
cost one X25519, charged to the source IP, and then fail the sequence check
in §9.4.

### 9.4 Registry rules

`r = ROLE-1`, `o = 1-r`, `e = registry[RID]`, `cts` = `CTS` of the
REGISTER's cookie, `ip = src.Addr()`, `net` = the /24 of `ip`. "Live" means
`live` and `now < expires`. Rows are checked in order and the first that
applies wins.

| #   | Condition                                                                                                         | Action                                                                                                                                                                                                                                                                                                              | Reply to sender                                                                                                                                       |
| --- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `e` exists and `cts <= e.slots[r].seq`; or `e` missing and `cts <= floor`                                         | none                                                                                                                                                                                                                                                                                                                | REJECTED `STALE`, `RETRY_S = 0`                                                                                                                       |
| 2   | `WITHDRAW` set                                                                                                    | `e` missing: none. Else: if slot `r` is live, end it (`live = false`, decrement counters); `seq = cts`                                                                                                                                                                                                              | REGISTERED, `TTL_S = 0`                                                                                                                               |
| 3   | `ROLE = DIAL`, slot `r` has `matchedAt` within the last 30 s, and `E_C_PUB` is slot `r`'s `eph` or `next`          | `seq = cts`, `next = P.NEXT`                                                                                                                                                                                                                                                                                        | MATCHED again (`PEER` = slot `r`'s `peer`, `SELF = src`)                                                                                              |
| 4   | Slot `o` live                                                                                                     | Store slot `r` from this REGISTER with `live = false`; end slot `o` (decrement its counters); both get `matchedAt = now` and `peer` = the other's address; `retain = now + 61 s`; replace the holder's cached reply (key `o.eph`) with the holder's MATCHED. No quota or capacity check: the sender holds nothing   | MATCHED (`PEER` = slot `o` address, `SELF = src`); MATCHED to slot `o` under its `kDown`/`regID` (`PEER = src`, `SELF` = its address, cookie for its `next`) |
| 5   | `e` missing and `len(registry) >= MaxRegistrations` and `idleList` empty                                          | none                                                                                                                                                                                                                                                                                                                | REJECTED `FULL`, `RETRY_S = 5`                                                                                                                        |
| 6   | Not (slot `r` live with `addr.Addr() == ip`), and `perIP[ip] >= MaxPerIP` or `perNet[net] >= MaxPerNet`           | none                                                                                                                                                                                                                                                                                                                | REJECTED `IP_QUOTA`, `RETRY_S = 30`                                                                                                                   |
| 7   | Otherwise                                                                                                         | If `e` is missing and the registry is full, evict the head of `idleList` (set `floor = max(floor, its slot seqs)`); create `e` with both slot `seq = floor`. If slot `r` is live and `E_C_PUB` is neither its `eph` nor its `next`, send REPLACED to its holder. Set slot `r` from this REGISTER, `live = true`, `expires = now + TTL`; adjust counters (decrement the old address if the slot was live, increment the new one); `retain = max(expires, now + 61 s)`; remove `e` from `idleList` | REGISTERED (`TTL_S`, `OBSERVED = src`, cookie for `(src, P.NEXT)`)                                                                                   |

"Store/set slot from this REGISTER" means `addr = src`, `eph = E_C_PUB`,
`next = P.NEXT`, `kDown`, `regID`, `seq = cts`, and `matchedAt` zero (row 7)
or now (row 4).

Consequences:

- Same role, newer cookie: the slot moves at once. A restarted client, or a
  retry from a new socket or a new IP, takes the slot back on its next
  REGISTER. The v1 35 s `rebindAfter` quiet period and its stale-address
  window are deleted.
- `LISTEN` never matches `LISTEN`, and `DIAL` never matches `DIAL`.
- A displaced registrant learns it (REPLACED), unless the new REGISTER is
  its own chained refresh (`eph` or `next` match), so a client's own retry
  never reports itself as a squatter.
- A replay of a processed REGISTER from its own source within the cookie
  lifetime hits the recent cache (no state change, stored reply). A replay
  from another source fails the cookie. After the cookie lifetime, it fails
  the cookie. A REGISTER withheld by an on-path attacker and released later
  carries an older `cts` than whatever the client sent after it, so row 1
  rejects it, including after the entry was evicted (the `floor`).
- A lost MATCHED for a dialer that held the slot is repeated on the
  dialer's next chained REGISTER (row 3); dialers refresh every 5 s until
  matched (§10.7). A holder's retransmission of its last REGISTER gets its
  MATCHED from the cache.
- A WITHDRAW for an unknown `RID` creates nothing.
- Retained entries (no live slot) block no registration: when the registry
  is full they are evicted first (row 7), and `floor` keeps replay safety
  after eviction.

### 9.5 Tick (every 500 ms)

1. Rotate `cookie_secret` when 10 minutes have passed.
2. For every live slot with `expires <= now`: `live = false`, decrement
   counters; if the entry has no live slot, append it to `idleList`.
3. Delete entries at the head of `idleList` whose `retain <= now`.
4. Pop expired recent-cache entries from the FIFO ring.
5. Every 10 s: delete per-IP buckets that are full
   (`TokensAt(now) >= burst`).

Entries are kept for `CookieLifetime + 1 s` after their last change so a
withheld REGISTER cannot recreate a withdrawn or matched slot: its cookie
was minted no later than that change and expires before the entry goes. The
extra second covers the gap between the tick and a cookie that is still
valid at the boundary.

### 9.6 Limits

| Limit                       | Keyed by                 | Default                                               | Charged when                              |
| --------------------------- | ------------------------ | ----------------------------------------------------- | ----------------------------------------- |
| `cookie_rate`               | global token bucket      | unlimited                                             | before each COOKIE and each cached reply  |
| `x25519_per_ip`             | verified source IP       | 10/s, burst 60                                        | step 4, before X25519                     |
| `x25519_rate`               | global token bucket      | 4,000/s, burst 400, reserve 100 for IPs holding slots | step 4                                    |
| `max_registrations_per_ip`  | live slots per IP        | 256                                                   | rows 6, 7                                 |
| `max_registrations_per_net` | live slots per IPv4 /24  | 2,048                                                 | rows 6, 7                                 |
| `max_registrations`         | entries, live and retained | 100,000                                             | rows 5, 7                                 |
| `max_recent`                | recent-cache entries     | 200,000                                               | step 8                                    |
| per-IP bucket map           | entries                  | 100,000                                               | step 4                                    |

Buckets are `golang.org/x/time/rate.Limiter` driven by `AllowN(now, 1)` and
`TokensAt(now)` with the server's `Now`, so tests use a fake clock.
`golang.org/x/time` becomes a direct requirement of the root module (it is
already an indirect requirement there and in every sub-module, at v0.15.0).

Why these numbers: a daemon listener with 64 contacts holds 64 RIDs
(RFC010 has no epoch overlap) and refreshes each every 30 s, about 2.1
X25519 per second; a dial costs at most 7 (6 refreshes in 30 s plus the
first). 10/s with a burst of 60 covers that plus start-up. Users behind one
carrier-grade NAT address share the per-IP numbers; operators raise them.
The global cap bounds broker CPU at about 4,000 X25519 per second (REL-15
measured 116 µs per NOTIFY in v1, which included a key generation). These
are design values; a benchmark sets them before release (§4.3, §16).

Memory at the defaults: about 330 bytes per registry entry and 250 per
recent entry, so about 33 MB plus 50 MB when both are full.

The `cmd/relay/internal/ratelimit` package and `[rate_limit]` no longer
apply to the broker.

### 9.7 Server API

```go
package brokerserver // pkg/relayconn/broker/brokerserver

type Rate struct {
	PerSecond float64
	Burst     int
}

type Options struct {
	Key              *relayleg.PrivateKey // required
	TTL              time.Duration        // default 60s; 20s..1h
	MaxRegistrations int                  // default 100_000
	MaxPerIP         int                  // default 256
	MaxPerNet        int                  // default 2_048
	MaxRecent        int                  // default 200_000
	MaxDHKeys        int                  // default 100_000
	CookieRate       Rate                 // zero: unlimited
	DHPerIP          Rate                 // default {10, 60}
	DHGlobal         Rate                 // default {4000, 400}
	DHReserve        int                  // default DHGlobal.Burst / 4
	Now              func() time.Time     // default time.Now
	Rand             io.Reader            // default crypto/rand
	Logger           *slog.Logger         // default slog.Default()
}

type Sender func(pkt []byte, dst netip.AddrPort)

type Stats struct {
	Cookies, CacheHits, DHDenied, DH, AuthFail, BadSource, BadFields,
	Stale, Registered, Matched, Replaced, Withdrawn, Full, IPQuota,
	Evicted, RegistryWrites uint64
	Entries, Live, Recent int
}

var ErrNoKey = errors.New("brokerserver: options need a key")

func New(o Options) (*Server, error)
// Handle processes one datagram. Not safe for concurrent use; Handle and
// Tick must run on one goroutine.
func (s *Server) Handle(pkt []byte, src netip.AddrPort, send Sender)
func (s *Server) Tick()
func (s *Server) Stats() Stats
```

`Stats.DH` counts X25519 operations and `Stats.RegistryWrites` counts
registry mutations; tests use them as the counting hooks. `Server` logs a
`slog.Debug` summary of non-zero `Stats` deltas at most once a minute.

```go
package broker // cmd/relay/internal/broker

func New(addr string, opts brokerserver.Options) (*Broker, error) // udp4
func (b *Broker) Run(ctx context.Context) error
func (b *Broker) Close() error
func (b *Broker) Addr() netip.AddrPort
```

The loop reads into a 2,048-byte buffer with a 500 ms read deadline, calls
`Tick` when the deadline passes or 500 ms have elapsed, and keeps the v1
read-error backoff (see §18 on the buffer size).
`run.newBroker(cfg config.Broker, key *relayleg.PrivateKey)` maps the
config to `Options`; `run.Run` passes `svc.StaticKey()`, in RFC009's
start-up order (key, `services.New`, certificates, broker, listeners).

Today's `broker.New(cfg config.Broker, limits Limits)`, `Limits`,
`AllowFunc`, `Addr() *net.UDPAddr`, `run.newBroker(ctx, cfg)` and
`run.newBrokerLimits` are replaced.

## 10. Client Library

### 10.1 `pkg/relayconn/broker/wire`

Pure codec, no I/O. The server core, the client and the tests import it.
Golden vectors live in `wire/testdata/vectors.json`.

```go
package wire

const (
	Version           = 0x02
	HeaderSize        = 6
	AddrSize          = 18
	CookieSize        = 24
	CookieReplySize   = 68
	PlainRegisterSize = 96
	RegisterSize      = 174
	DownlinkSize      = 64
	SealedSize        = 118
	CookieLifetime    = 60 * time.Second
	MaxEphemeralSeals = 3
)

type Type uint8   // TypeCookie = 1, TypeRegister = 2, TypeSealed = 3
type Role uint8   // RoleListen = 1, RoleDial = 2
type Kind uint8   // KindRegistered = 1, KindMatched, KindRejected, KindReplaced
type Reason uint8 // ReasonStale = 1, ReasonFull, ReasonIPQuota, ReasonBadFields
type RID [32]byte
type Cookie [CookieSize]byte

func (c Cookie) IsZero() bool
func (c Cookie) Seq() uint64

var (
	ErrMagic, ErrVersion, ErrLength, ErrType, ErrAuth, ErrFields,
	ErrEphemeralReuse error
)

func ParseHeader(pkt []byte) (Type, error)
func PutAddr(dst []byte, ap netip.AddrPort)
func ParseAddr(b []byte) (netip.AddrPort, error)

func DeriveRID(sPub relayleg.PublicKey, tok rendezvous.Token) RID

// Cookies (broker side).
type CookieJar struct{ /* secrets, start, last CTS */ }
func NewCookieJar(rand io.Reader, start time.Time) (*CookieJar, error)
func (j *CookieJar) Mint(now time.Time, src netip.AddrPort, ePub [32]byte) Cookie
func (j *CookieJar) Check(now time.Time, c Cookie, src netip.AddrPort,
	ePub [32]byte) bool
func (j *CookieJar) Rotate() error

type CookieReply struct {
	Echo     [16]byte
	Cookie   Cookie
	Observed netip.AddrPort
	KeyHint  [4]byte
}
func AppendCookieReply(dst []byte, r CookieReply) []byte
func ParseCookieReply(pkt []byte) (CookieReply, error)

type Register struct {
	RID      RID
	Role     Role
	Withdraw bool
	Observed netip.AddrPort
	Next     [32]byte
}

type DownKeys struct {
	Down  [32]byte
	RegID [8]byte
}

// Client ephemeral. The private key never leaves the type.
type Ephemeral struct{ /* priv, cookies sealed under */ }
func NewEphemeral(rand io.Reader) (*Ephemeral, error)
func (e *Ephemeral) Public() [32]byte
func (e *Ephemeral) Cookieless() [RegisterSize]byte
// Seal returns ErrEphemeralReuse when c was sealed before or after
// MaxEphemeralSeals seals.
func (e *Ephemeral) Seal(sPub relayleg.PublicKey, c Cookie, r Register) (
	[RegisterSize]byte, DownKeys, error)
func (e *Ephemeral) Destroy()

// Broker side.
type RegisterHead struct {
	EPub   [32]byte
	Cookie Cookie
	TH     [64]byte
}
func ParseRegisterHead(pkt []byte) (RegisterHead, error) // SHA-512 only
func OpenRegister(k *relayleg.PrivateKey, h RegisterHead, pkt []byte) (
	Register, DownKeys, error)

type Downlink struct {
	Kind     Kind
	TTL      uint32
	Observed netip.AddrPort // REGISTERED
	Peer     netip.AddrPort // MATCHED
	Self     netip.AddrPort // MATCHED
	Reason   Reason
	RetryS   uint16
	Cookie   Cookie
}
func MarshalDownlink(d Downlink) [DownlinkSize]byte
func SealDownlink(k DownKeys, nonce [24]byte, plain [DownlinkSize]byte) [SealedSize]byte
func DownlinkRegID(pkt []byte) ([8]byte, error)
func OpenDownlink(k DownKeys, pkt []byte) (Downlink, error)
```

Golden vectors load a fixed broker key from `testdata/broker-key.pem` with
RFC009's `relayleg.LoadPrivateKeyFile` and feed `NewEphemeral`,
`NewCookieJar` and nonces from a fixed reader.

### 10.2 Broker address

```
address = ["udp://"] host ":" port "?rk=" relay-key
```

`host` is a DNS name or an IPv4 literal (RFC009's host rules for relay
addresses); the port is required; `rk` is required and parsed by
`relayleg.ParsePublicKey`; no other parameter, path, user info or fragment
is allowed. The scheme is case-insensitive. The canonical form is
`udp://host:port?rk=rk1-...`.

```go
package broker // pkg/relayconn/broker

type Address struct {
	Host string             // "host:port"
	Key  relayleg.PublicKey
}

var (
	ErrInvalidAddress    = errors.New("broker: invalid broker address")
	ErrBrokerKeyRequired = errors.New("broker: address has no rk= key")
)

func ParseAddress(s string) (Address, error)
func (a Address) String() string  // canonical
func (a Address) Display() string // "udp://host:port", for errors and logs
```

Carrying the key in the address keeps every daemon and bus signature that
takes `broker_addr` unchanged, survives `restart_server`, and puts the key
in share URLs.

### 10.3 Client API

```go
type Role = wire.Role

const (
	RoleListen = wire.RoleListen
	RoleDial   = wire.RoleDial
)

var (
	ErrClosed                = errors.New("broker: endpoint closed")
	ErrNoReply               = errors.New("broker: no reply from broker")
	ErrBrokerKeyMismatch     = errors.New("broker: broker does not hold the pinned key")
	ErrRegistryFull          = errors.New("broker: registry full")
	ErrIPQuota               = errors.New("broker: too many registrations from this address")
	ErrRejected              = errors.New("broker: registration rejected")
	ErrDuplicateRegistration = errors.New("broker: token already registered in this role")
	ErrSelfMatch             = errors.New("broker: token already registered in the other role")
	ErrEndpointFailed        = errors.New("broker: socket read failed")
)

// Client is immutable and safe for concurrent use. Construct one per use.
type Client struct{ /* addr netip.AddrPort; key relayleg.PublicKey */ }

func NewClient(a Address) (*Client, error) // resolves udp4
func (c *Client) ServiceID() rendezvous.ServiceID

// NewEndpoint takes ownership of pc (an unconnected UDP socket) and
// starts its reader goroutine. On error the caller keeps pc.
func (c *Client) NewEndpoint(pc net.PacketConn) (*Endpoint, error)

type Endpoint struct{ /* ... */ }

// PacketConn returns the non-broker datagrams of the socket (10.4).
func (e *Endpoint) PacketConn() net.PacketConn

// Register registers tok under role and returns once the broker answers
// with REGISTERED or MATCHED. The registration then refreshes itself
// until Close or, for RoleDial, until its first match.
// Errors: ErrNoReply (ctx done, or 5 s without a ctx deadline; wraps
// ErrBrokerKeyMismatch when only COOKIEs with another key hint came back),
// ErrRegistryFull, ErrIPQuota, ErrRejected, ErrDuplicateRegistration,
// ErrSelfMatch (same token in the other role on this Endpoint),
// rendezvous.ErrTokenZero, ErrClosed.
func (e *Endpoint) Register(ctx context.Context, tok rendezvous.Token,
	role Role) (*Registration, error)

// Close sends one WITHDRAW per live registration (10.7), stops the reader
// and closes the socket.
func (e *Endpoint) Close() error

type Match struct {
	Peer netip.AddrPort
	Self netip.AddrPort
}

type Status uint8

const (
	StatusPending   Status = iota // no reply yet
	StatusActive                  // last REGISTER acknowledged
	StatusContested               // another registrant took the slot
	StatusLost                    // no acknowledgement for a full TTL
	StatusDone                    // matched (RoleDial) or closed
)

type Registration struct{ /* ... */ }

// Matches delivers authenticated matches, buffer 4; a match is dropped
// (and logged at warn) if the buffer is full. Closed when the
// registration ends.
func (r *Registration) Matches() <-chan Match
func (r *Registration) Wait(ctx context.Context) (Match, error)
func (r *Registration) Status() Status
// StatusChanges sends after every Status change. Buffer 1, latest wins.
func (r *Registration) StatusChanges() <-chan Status
func (r *Registration) Observed() netip.AddrPort // last authenticated
func (r *Registration) ExpiresAt() time.Time      // last REGISTERED + TTL
func (r *Registration) Err() error                // after Matches is closed
func (r *Registration) Close() error              // WITHDRAW, stop refresh
```

Deleted from `pkg/relayconn/broker`: `Client.Echo`, `Client.Register`,
`Client.Listen`, `Client.PublicKey`, `NewClientWithKey`, `EchoOn`,
`RegisterOn`, `ReadNotify`, `Payload`, `NotifyPayload`, `NotifyType`,
`Opcode`, `WireToken`, `TokenMatches`, `TokenSize`, `BuildRegister`,
`ParseRegister`, `BuildEchoResponse`, `ParseEchoRequest`, `SealNotify`,
`OpenNotify`, `BuildNotifyPeerMatched`, `BuildNotifyTokenAssigned`,
`ParseNotify`, `ParseNotifyPayload`, `PeerMatchedPlaintext`,
`TokenAssignedPlaintext`, `ErrShortPacket`, `ErrBadMagic`, `ErrBadVersion`,
`ErrBadOpcode`, `DefaultEchoTimeout`, `DefaultRegisterTimeout`, and the
rest of `socket.go`.

| v1                                       | v2                                                                  |
| ---------------------------------------- | ------------------------------------------------------------------- |
| `EchoOn(ctx, conn)`                      | none; `Registration.Observed()` (authenticated)                     |
| `RegisterOn(ctx, conn, token, ip, port)` | `Endpoint.Register(ctx, tok, role)`                                 |
| `ReadNotify(ctx, conn)`                  | `Registration.Matches()` or `Registration.Wait(ctx)`                |
| `TokenMatches(notified, token)`          | none; a SEALED packet belongs to one registration through `REG_ID`  |

### 10.4 Endpoint socket and `PacketConn` contract

Reader: one goroutine reads `pc` into a 65,536-byte buffer
(`ReadFromUDPAddrPort` when `pc` is a `*net.UDPConn`), so an oversize
datagram is read whole instead of becoming a read error on Windows
(RFC008's rule). A datagram from the broker address that starts with
`"KBRK" 0x02` is handled by the Endpoint and never forwarded, whether or not
it authenticates. Any other datagram longer than 1,500 bytes is dropped
(RFC008's largest packet is 1,232 bytes; kcp-go reads at most 1,500). The
rest is copied into a right-sized buffer and queued for `PacketConn` (256
entries; the newest is dropped when the queue is full, and counted).

Read errors follow RFC008's rule: every error other than `net.ErrClosed` is
transient (Windows `WSAECONNRESET` after a kick to a closed port,
`WSAEMSGSIZE`, `ENOBUFS`). It is counted and skipped; after 64 in a row the
reader sleeps 5 ms, doubling to 1 s, until a read succeeds. A fixed error
budget would let anyone who can send datagrams to the socket end every
registration. `net.ErrClosed` (the socket closed under the Endpoint) ends
every registration with `ErrEndpointFailed` (wrapping it) and makes
`PacketConn().ReadFrom` return an error wrapping `net.ErrClosed`.

`PacketConn()`:

- `ReadFrom(b)` returns the next queued datagram, its source as a
  `*net.UDPAddr` built with `net.UDPAddrFromAddrPort(ap.Unmap())`, and
  copies `min(n, len(b))` bytes, returning that count (UDP truncation, never
  an error). It never returns a per-datagram error.
- It returns `os.ErrDeadlineExceeded` after the read deadline, including a
  deadline set in the past while a read is blocked, and `net.ErrClosed`
  after `Close`.
- `SetDeadline` and `SetReadDeadline` act on the queue; `SetWriteDeadline`
  passes to the socket. Zero clears.
- `WriteTo` writes to the socket and is safe for concurrent use with the
  Endpoint's own writes.
- `LocalAddr` is the socket's.
- `Close` closes the Endpoint (`Endpoint.Close`).

### 10.5 Downlink acceptance

Checks, in order: the source equals the broker address; the length is 118;
`REG_ID` is known (each registration keeps the keys of its two most recent
REGISTERs; entries leave when superseded twice, when the registration ends,
or 30 s after a MATCHED); the AEAD opens; the kind is known; the padding is
zero. Then:

- **REGISTERED** for the latest REGISTER: `Status = Active`; update `TTL`,
  `Observed` and the next cookie; schedule the refresh. For an older
  REGISTER: ignore.
- **MATCHED**: accepted at most once per `REG_ID`, and not if `Peer` equals
  a peer delivered on this registration in the last 60 s (row 3 repeats).
  Address filter below. Deliver to `Matches`. `RoleDial`: `Status = Done`,
  stop refreshing. `RoleListen`: register again at once with the cookie
  from the MATCHED.
- **REJECTED**: `STALE`: retry at once with the reply's cookie, at most 3
  in a row, then treat as REPLACED. `FULL` and `IP_QUOTA`: the first
  `Register` call returns `ErrRegistryFull` or `ErrIPQuota` and creates
  nothing; later, back off `RETRY_S` seconds and keep the status.
  `BAD_FIELDS`: end the registration with `ErrRejected`.
- **REPLACED**: counts only when its `REG_ID` is the latest acknowledged
  REGISTER and no later REGISTER of this registration is outstanding; one
  that arrives while a REGISTER is outstanding is held and dropped if that
  REGISTER is answered. Then `Status = Contested`, a warn log with the
  token handle (`Token.Handle()`), and the next REGISTER waits one refresh
  interval, so two of the user's own devices on one token do not take the
  slot from each other every second.

Match address filter, so that a malicious broker gets no UDP
request-forgery primitive into the client's network. Drop, with a debug
log, a MATCHED whose `Peer`:

- is not IPv4, has port 0, equals `Self`, or equals the broker address;
- is in `0.0.0.0/8`, `127.0.0.0/8` (unless the broker address is loopback,
  for tests), `169.254.0.0/16`, `224.0.0.0/4` or `240.0.0.0/4` (which
  includes `255.255.255.255`);
- is in `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` or `100.64.0.0/10`
  while `Self` is not in one of those ranges. Two peers behind one NAT are
  matched on the NAT's public address; a private `Peer` is legitimate only
  when the broker itself sits on the private network.

### 10.6 Cookie adoption and the claimed address

Each registration keeps `auth`, the last authenticated address (REGISTERED
`OBSERVED` or MATCHED `SELF`), and when it arrived. A REGISTER's
`P.OBSERVED` is `auth` when the registration has one younger than one TTL;
otherwise the `OBSERVED` of the COOKIE it adopted.

A COOKIE whose `ECHO` matches the outstanding REGISTER and whose `KEY_HINT`
matches is handled as follows:

1. no `auth` younger than one TTL (first contact, or after `Lost`): adopt;
2. `OBSERVED == auth`: adopt;
3. otherwise (the broker says the address changed): hold it; adopt it only
   when the outstanding REGISTER has had no SEALED reply through its whole
   retransmission schedule (2.1 s), and log at warn with both addresses.

Two COOKIEs with the same `ECHO` and different `OBSERVED` in one attempt:
log at warn ("conflicting broker cookies") and prefer the one equal to
`auth`; if neither is, adopt neither and start a new attempt at the 2.1 s
mark.

Adopting means sealing the same ephemeral under the new cookie (at most
twice per ephemeral after its first seal, by `MaxEphemeralSeals`). A
man-on-the-side that injects a COOKIE carrying a cookie for its own address
must also make the client claim that address inside the AEAD, which rule 3
refuses while `auth` is fresh; the broker drops a REGISTER whose claim
differs from its source. NAT rebinding costs one 2.1 s delay: the refresh
fails the cookie check from the new address, the broker's COOKIE reports
the new address, and the client adopts it after its retransmissions go
unanswered.

### 10.7 Client state machine and timers

Per registration:

```
start: e0 = NewEphemeral; send e0.Cookieless(); Pending
COOKIE (10.6 adopt) -> seal(eph, cookie, P{NEXT = new ephemeral}); send
SEALED (10.5)       -> Active / Done / Contested / ended
refresh timer       -> seal(next, cookie from last reply, P{NEXT = new}); send
                       (cookieless first when that cookie is 50 s old or more)
attempt timeout     -> new attempt with the announced next ephemeral,
                       cookieless; exponential backoff
Close               -> WITHDRAW (once, no retry, no wait), Done
```

Each REGISTER uses the ephemeral announced as `NEXT` in the previous one
(the first uses a fresh one), so the broker recognises the client's own
refreshes and retries (rows 3 and 7). The private key of an ephemeral is
destroyed after its last allowed seal or when the registration ends.

| Event                                | Action                                                                                                                       |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| No reply after 300 ms, 600 ms, 1.2 s | Resend the same bytes                                                                                                        |
| No reply 2.1 s after the first send  | New attempt; next attempts after 2 s, 4 s, 8 s, ... capped at 60 s, ±20 % jitter; reset by any SEALED reply                  |
| Silent drop at the broker (bucket empty) | Seen as no reply; same backoff                                                                                           |
| Initial `Register`                   | Returns on REGISTERED or MATCHED; `ErrNoReply` when ctx ends, or after 5 s without a ctx deadline                            |
| Refresh, `RoleListen`                | `min(TTL/2, 30 s)` after the last REGISTERED, ±10 % jitter                                                                   |
| Refresh, `RoleDial`                  | Every 5 s ±10 % until matched (repeats a lost MATCHED, row 3)                                                               |
| No REGISTERED for `TTL`              | `Status = Lost`; keep retrying with backoff; `Active` again on the next REGISTERED                                           |
| REPLACED                             | `Contested`; next REGISTER after one refresh interval                                                                        |
| WITHDRAW on `Close`                  | Sent only with a cookie younger than 50 s; otherwise the slot expires within `TTL`                                           |

Registering the same token in the same role twice on one Endpoint returns
`ErrDuplicateRegistration`; in the other role, `ErrSelfMatch`.

Timers use an unexported `clockSource` (`Now`, `AfterFunc`) so in-package
tests drive them with a fake; the root `internal/clock.Clock` has only
`Now`.

## 11. Client Changes

### 11.1 Common to the daemon and the bus

Both clients delete `BrokerClient` (`NewBrokerClient`, the daemon's
per-token key store, the bus's process-wide X25519 key, and the
`os.Exit(1)` path in the bus's `NewApp` that exists only because key
generation can fail) and every hand-written copy of the codec (the daemon's
`echoRequest`, `echoFrom`, `parseEchoResponse` and `brokerID.openNotify`;
the bus's `BrokerClient.parseNotify` and `readTokenAssigned`). A
`broker.Client` is built per use from the parsed address. The p2p listener
has no token of its own: every token, the one registered at server start
included, goes through `RegisterToken`.

### 11.2 Inputs and errors

| Client                                 | Input                                    | Format                                                                 |
| -------------------------------------- | ---------------------------------------- | ---------------------------------------------------------------------- |
| daemon `start_server`, `dial`          | `broker_addr` (unchanged name)           | `udp://host:port?rk=rk1-...`, scheme optional                          |
| daemon `generate_p2p_token`            | `broker_addr` removed                    | the running p2p listener's broker                                      |
| bus server and connect forms           | broker address field (unchanged)         | same; placeholder `udp://host:4788?rk=rk1-...`                         |

New daemon error codes: `invalid_broker_address`, `broker_key_required`,
`broker_key_mismatch`, `p2p_listener_required`, `p2p_self_dial`;
`p2p_match_failed` (existing) now carries the reason. The bus maps the same
sentinels to its `ConnectResult.ErrorCode` values.

### 11.3 `cmd/daemon`

- `broker.go`: delete `BrokerClient`. Add
  `WaitMatch(ctx context.Context, a broker.Address, toks []rendezvous.Token)
  (*broker.Endpoint, broker.Match, error)`: `NewClient`,
  `net.ListenUDP("udp4", :0)`, `NewEndpoint`, one `RoleDial` registration
  per token; the first `Match` wins and the others are closed. Callers pass
  a 30 s context (DMN-14). `HolePunch` takes the Endpoint and the match:
  until RFC008 lands, `kcp.NewConn4(conv, peer, nil, 0, 0, true,
  ep.PacketConn())`, so closing the KCP session closes the Endpoint; after
  RFC008, `kamune.DialUDP(ctx, ep.PacketConn(), m.Peer)`.
- `sendNATKick(ctx, pc net.PacketConn, peer netip.AddrPort)` (was
  `*net.UDPConn`, `*net.UDPAddr`); the two call sites in `directp2p.go`
  convert.
- `p2plistener.go`: `newP2PListener(a broker.Address, bindAddr string)`
  binds the socket, makes the Endpoint and starts `kcp.ServeConn(nil, 0, 0,
  ep.PacketConn())` (RFC008: `kamune.ListenUDP`). `RegisterToken(tok)
  error` calls `ep.Register(ctx, tok, RoleListen)` and starts one goroutine
  that reads `Matches()`, sends `sendNATKick` to `Match.Peer` (DMN-21) and
  logs the match by token handle. `Unregister(tok)` (renamed from
  `UnregisterToken`) closes that registration. `Holds(tok) bool`. `Close`:
  close every registration, then the KCP or RFC008 listener (which closes
  the Endpoint at zero paths). The
  broker packet handling (`handleBroker`, `fromBroker`), the deadline reset
  before `kcp.ServeConn`, `refreshLoop` and `refreshRegistration` are
  deleted; the first token is no longer special. Transition: the current
  `punchConn` wrapper also admits KCP packets only from hosts a match named
  (`admitted`). Until RFC008's `ListenUDP` replaces `kcp.ServeConn`, that
  filter stays between `ep.PacketConn()` and kcp-go and takes its hosts
  from `Match.Peer`; after that, see §18.
- `p2p.go`: `GenerateP2PToken(peerPubB64)` needs a running p2p listener and
  returns `p2p_listener_required` otherwise (DMN-18). Random mode:
  `rendezvous.NewRandomToken()` on every call; the `existingToken` early
  return is deleted (BUS-41's daemon counterpart). Static mode: RFC010's
  listen tokens (§6.2). `p2pRefreshed` and `getOrCreateBrokerClient` are
  deleted. `p2pToken` gains `status` (`pending`, `active`, `contested`,
  `lost`) fed from `StatusChanges()`; `ExpiresAt` is
  `Registration.ExpiresAt()`; `EvtP2PTokens` is emitted on every status
  change. `RemoveP2PToken` calls `Unregister`, which sends WITHDRAW
  (DMN-07). `stopP2PResources` closes the listener as above.
- `network.go`: the p2p dial refuses a token that the local listener
  `Holds` (`p2p_self_dial`); with RFC010's directional tokens a static dial
  never computes a token its own listener holds, so this catches random
  tokens and misconfiguration. `handleRestartServer` keeps `broker_addr` as
  given (the key travels with it). `handleGetShareInfo` builds the p2p URL
  with `net/url` as `p2p://host:port?rk=rk1-...&token=<64 hex>` (RFC010
  decides which token may appear: random only).
- `param.go`: `StartServerParams.BrokerAddr` and `DialParams.BrokerAddr`
  parse with `broker.ParseAddress` in validation; `GenerateP2PTokenParams`
  loses `BrokerAddr`.
- Schemas: `schema/commands/start_server.schema.json`, `dial.schema.json`,
  `restart_server.schema.json` (`broker_addr` pattern and description),
  `generate_p2p_token.schema.json` (`broker_addr` removed),
  `schema/events/p2p_tokens.schema.json` and
  `schema/commands/list_p2p_tokens.schema.json` (`status`).
- Tests: `broker_test.go` and `p2plistener_test.go`, which fake the v1
  broker with the v1 codec, move to `brokertest`. `integration_test.go`
  gains a two-daemon p2p case through the JSON API against `brokertest`
  (§14.4).

### 11.4 `cmd/bus`

- `broker.go`, `p2plistener.go`, `p2p.go`, `directp2p.go`: the same changes
  as the daemon, including `sendNATKick` (its call sites in `directp2p.go`
  and `punchfilter.go`) and `HolePunch`. `punchFilter` loses its broker
  handling (`onBroker`, `handleBroker`, `registers`); under the same
  transition rule as the daemon, its matched-host filter stays in front of
  kcp-go until RFC008 lands and takes its hosts from `Match.Peer`.
- `app.go`: `p2pListenerI` gains `Holds(rendezvous.Token) bool`;
  `p2pListener.RegisterToken` and `Unregister` (renamed from
  `UnregisterToken`) take the new types;
  `p2pListener.Token()` is deleted (the listener has no primary token).
- `p2p.go`: `GenerateP2PToken(peerPubB64 string)` (was `(brokerAddr,
  peerPubB64)`). `RegisterP2PDialer` stays deleted (BUS-27 part).
- `network.go`: `StartServer` no longer passes a token to `newP2PListener`
  and no longer reads `listener.Token()`; the dial path keeps its 30 s match
  timeout and calls `WaitMatch` with the parsed address. `StartServer` and
  `ConnectToServer` keep their `brokerAddr` argument, which now carries
  `?rk=`; this RFC does not change them otherwise (RFC009 replaces their
  relay arguments with `RelayOptions`).
- Frontend: placeholder and help text of the broker address inputs
  (`App.svelte` server and connect forms). `SignalingTokens.svelte` calls
  `GenerateP2PToken(peerPubB64)` and has no address or key input (it is
  mounted only with `locked` today, in `Sidebar.svelte`). The token list
  keeps showing `expiresAt`; a status badge is deferred. Regenerate the
  Wails bindings.
- Tests: `p2p_test.go` (its `fakeBroker` uses `SealNotify`,
  `BuildNotify*` and `ParseRegister`) and `p2plistener_test.go` move to
  `brokertest`.

### 11.5 `cmd/tui`

No change; it has no broker code.

## 12. Relay Configuration

```toml
[broker]
enabled = false
address = "0.0.0.0:4788"
# The broker uses the relay static key (server.data_dir/relay-static-key.pem).
# registration_ttl = "60s"           # 20s .. 1h
# max_registrations = 100000         # entries, live and recently ended
# max_registrations_per_ip = 256     # live slots per source IP
# max_registrations_per_net = 2048   # live slots per source IPv4 /24
# max_recent = 200000                # recent-REGISTER cache entries
# x25519_per_ip = 10                 # per verified source IP, per second
# x25519_per_ip_burst = 60
# x25519_rate = 4000                 # all sources, per second
# x25519_burst = 400
# cookie_rate = 0                    # COOKIE replies per second; 0 = unlimited
```

A value of 0 means the default (for `cookie_rate`, unlimited).
`[rate_limit]` no longer applies to the broker, and
`rate_limit.disabled` does not turn broker limits off. Validation rejects
negative values, a `registration_ttl` outside 20 s to 1 h (the client
refreshes at `TTL/2` capped at 30 s; `TTL_S` is a uint32), and
`max_registrations_per_ip > max_registrations_per_net`. The v1 comment
about the 35 s rebind rule goes.

## 13. Security Considerations

### 13.1 What the broker learns

The broker sees each REGISTER's source address, `E_C_PUB`, and, after the
AEAD opens, `RID`, role, flags and the claimed address. It never sees a
token or an identity key. It links the refreshes of one rendezvous through
`RID`, and all RIDs of one listener through their shared source address
(§8.5). Matched address pairs pass through it, as in v1.

### 13.2 Residual risks

- A malicious or compromised broker (holder of `S_priv`) can send wrong
  addresses (limited by the filter in §10.5), refuse matches, and link
  rendezvous by `RID`. The kamune handshake still authenticates the peer;
  RFC008's path layer stops KCP from anyone who does not complete its
  handshake.
- First contact against a man-on-the-side. With no authenticated address
  yet, a client adopts the first COOKIE that echoes its ephemeral; an
  attacker that sees the client's packet and answers first can make the
  client claim the attacker's address, then forward the sealed REGISTER
  from there, and becomes an on-path relay for that registration until the
  client's next refresh (which claims the authenticated address and moves
  the slot back). The kamune handshake still stops impersonation.
  Steady-state refreshes are not affected (§10.6). This is the DTLS and
  QUIC limit: a retry token proves reachability, not identity.
- An on-path or man-on-the-side attacker that injects garbage under a
  client's ephemeral and cookie before the client's own copy arrives costs
  the client's IP at most two X25519 tokens per ephemeral, and can make the
  broker drop that ephemeral (the client's next attempt uses a new one).
  Such an attacker can deny service anyway.
- Anyone holding the token (the two peers, or anyone RFC010's derivation
  lets compute it) can take its role. The displaced side sees `Contested`.
  RFC010's token design bounds who holds it.
- AEAD success proves knowledge of `S_pub`, not of any token: anyone can
  register random RIDs. Filling the registry takes about
  100,000 / 256 = 391 real IPs (49 /24s at the per-/24 cap of 2,048); under
  that pressure the broker evicts idle entries first and only then answers
  `FULL`.
- The global X25519 cap (4,000/s) is reached by 400 real IPs at the per-IP
  rate. The reserve keeps refreshes from IPs that already hold slots going
  for a while; new registrations from new IPs wait.
- While `cookie_rate` (if configured) is spent by spoofed traffic, new
  clients and clients whose NAT rebinds get no COOKIE; clients in steady
  state are unaffected because every SEALED reply carries their next
  cookie.
- Under recent-cache pressure (more than 200,000 REGISTERs in 61 s),
  replays of evicted entries cost one X25519 each, charged to the source
  IP's bucket, and are then rejected as `STALE`.
- No forward secrecy for `RID` and address pairing against later theft of
  `S_priv` (§8.5); a quantum attacker gets identity-to-address mapping for
  static tokens (§8.6).
- The broker has no access control (§4.2): anyone who knows its address and
  key can use it, within the limits of §9.6.

## 14. Testing Strategy

All tests use `a := require.New(t)`, table-driven where there are cases.
Run `go test -race` for `wire`, `brokerserver`, `broker` and
`cmd/relay/internal/broker`.

### 14.1 `pkg/relayconn/broker/wire`

- Golden vectors: a fixed broker key, ephemerals, token, cookie secret,
  start time and nonces produce the committed bytes for COOKIE, cookieless
  REGISTER, REGISTER, each SEALED kind, and `RID`.
- Round trip `Ephemeral.Seal`/`OpenRegister` and
  `SealDownlink`/`OpenDownlink`; the client PRK equals the
  `relayleg.PrivateKey.ExtractShared` output.
- Negative: every single-bit flip in REGISTER bytes 0..174 and SEALED bytes
  0..118 fails to open; wrong `S_pub`; low-order `E_C_PUB` (all zero and
  the order-8 points) rejected; wrong length; `VER=0x01`.
- `Ephemeral`: sealing twice under one cookie returns `ErrEphemeralReuse`;
  a fourth seal returns it; two `NewEphemeral` calls never share a public
  key; `Cookieless()` has a zero cookie and CT.
- Cookie: valid at age 0 and 60 s; rejected at 60 s + 1 µs, with `CTS`
  above the last minted, for a different IP, port or ephemeral, after two
  rotations, and all zero; accepted under the previous secret after one
  rotation; consecutive mints strictly increase, also when `Now` returns
  the same instant twice or steps back (the jar never mints below its last
  `CTS`). Age is `now.Sub(start)`; with the default `time.Now` that uses
  Go's monotonic reading, so wall-clock steps do not affect it.
- `DeriveRID` differs for different `S_pub` and tokens.
- Cross-protocol: a relay-leg ClientHello `enc` from RFC009's test vectors
  used as `E_C_PUB` with a valid cookie and the relay-leg ciphertext as
  `CT`: `OpenRegister` fails.
- `ParseAddress` (in `broker`): canonical round trip; missing `rk`
  (`ErrBrokerKeyRequired`); missing port, IPv6 literal, unknown parameter,
  duplicate `rk`, path, and `cert=` all return `ErrInvalidAddress`.

### 14.2 `pkg/relayconn/broker/brokerserver` (fake clock, `Stats` as hooks)

- `TestNoAmplification`: for each row of §7.6, bytes and packet count to
  an unverified source are below the request; extra packets go only to
  verified holders.
- REGISTER with no cookie, a forged cookie, an expired cookie, another
  port, another ephemeral: COOKIE reply, `DH == 0`, `RegistryWrites == 0`.
- 10,000 REGISTERs from 10,000 spoofed sources: registry 0, `DH == 0`, no
  per-IP buckets (REL-06, REL-07).
- Passive observer: 1,000 REGISTERs spoofed from a client's address with
  its captured cookie and random `E_C_PUB`: `DH == 0` (the cookie is bound
  to the ephemeral). 1,000 copies of the client's processed REGISTER, and
  1,000 with the same head and random CT: `DH == 0`, each answered from the
  cache, the client's bucket unchanged. Garbage CT under the client's
  ephemeral before the real one: at most 2 X25519.
- Budgets: per-IP bucket empty: valid REGISTERs dropped with no X25519 past
  the bucket; global bucket under the reserve: an IP with no live slot is
  dropped, an IP with one is served; neither bucket is charged when the
  other refuses.
- Registry table §9.4, one case per row: LISTEN then DIAL and DIAL then
  LISTEN match and both get MATCHED with each other's address; LISTEN then
  LISTEN from another address moves the slot at once and the first gets
  REPLACED; a chained refresh gets no REPLACED; an older `cts` gets
  `STALE`; WITHDRAW clears; WITHDRAW for a missing RID with the registry
  full creates nothing; `FULL` only when no idle entry exists; an idle entry
  is evicted and `floor` raised, then a withheld older REGISTER for that RID
  is `STALE` (both roles); `IP_QUOTA` on creation, on a move from IP X to
  IP Y past the cap, and per /24; an immediate match from an IP at its cap
  succeeds; `BAD_FIELDS` for role 0, role 3, a reserved flag, zero RID, zero
  `NEXT`, `NEXT == E_C_PUB`, non-zero pad; `OBSERVED != src` dropped with
  no state.
- Dialer as holder: the holder's MATCHED is dropped; its next chained
  REGISTER within 30 s gets MATCHED again; one after 30 s registers
  normally. A holder retransmission of its last REGISTER after the match
  gets MATCHED from the cache.
- REL-12 replays: a REGISTER from A replayed from B's address: COOKIE, slot
  unchanged. From A's address within 60 s: cached reply, no state change.
  After 61 s: COOKIE. A withheld REGISTER released after the client's next
  one: `STALE`.
- Purge: a slot not refreshed for TTL does not match; entries go 61 s after
  their last change; `perIP`/`perNet` exact across move, match, withdraw,
  expiry and eviction (property test with random operation sequences,
  including WITHDRAW and self-match, checked against a recount; registry
  size never exceeds `max_registrations`; no zero-valued map keys remain).
- Cookie boundary with sub-second offsets: a cookie valid at the purge tick
  never meets a purged entry.
- Fuzz target over `Handle` with a fake clock, asserting no X25519 before a
  valid cookie and no registry write before an opened AEAD.

### 14.3 `pkg/relayconn/broker` client (against `brokertest`, fake timers)

- RC-05 regression (after the review's
  `TestRT_ForgeNotifyFromPublicKeyOnly`): an attacker that knows `S_pub`,
  every REGISTER byte and the `REG_ID` seals a MATCHED with a key of its own
  and sends it from the broker address: not delivered.
- A captured MATCHED replayed: delivered once.
- MATCHED with peer `0.0.0.0:1`, `127.0.0.1:1` (non-loopback broker),
  `169.254.169.254:80`, `224.0.0.1:1`, `240.0.0.1:1`,
  `255.255.255.255:1`, `1.2.3.4:0`, the broker address, `Self`, and
  `10.0.0.1:1` with a public `Self`: not delivered.
- Man-on-the-side: after the first REGISTERED, inject a COOKIE with the
  right `ECHO` and a cookie and `OBSERVED` for a second socket, and forward
  every REGISTER the client sends from that socket: the slot never moves,
  and the client logs the conflict. The same injection with `OBSERVED` set
  to the client's real address: the slot never moves.
- COOKIE with a wrong `KEY_HINT` only: `Register` fails with `ErrNoReply`
  wrapping `ErrBrokerKeyMismatch`.
- A SEALED from a non-broker source with valid bytes goes to `PacketConn`
  as a normal datagram.
- `PacketConn` contract: a past deadline unblocks a blocked read;
  `net.ErrClosed` after `Close`; a 1,501-byte datagram is dropped and a
  1,500-byte one delivered; a short `b` truncates without error; 100
  transient read errors in a row are not surfaced and registrations keep
  refreshing afterwards; a socket `net.ErrClosed` ends registrations with
  `ErrEndpointFailed`; a full queue drops without blocking the reader.
- Immediate match (RC-12): DIAL registers while LISTEN holds; `Register`
  returns with the match already in `Matches()`.
- Listener rearm: after a match, a second DIAL matches without waiting for
  the refresh timer.
- Dialer holds the slot and `brokertest` drops the holder MATCHED: the
  dialer's match arrives within 5 s.
- Retransmission: drop the first two REGISTERs; `Register` succeeds on the
  third copy.
- NAT rebinding: move the client socket behind a fake rebinding relay; the
  next refresh gets COOKIE, the client adopts it after 2.1 s with a warn
  log, and the slot moves.
- `STALE` recovery: preset the slot `seq` above the client's cookie; one
  rejection, then success. Three in a row: `Contested`.
- REPLACED: a second registrant takes the slot; the first reports
  `Contested` and re-registers after one refresh interval.
- `Status` goes Pending, Active, Lost (server paused for TTL), Active.
- `Close` sends WITHDRAW; the server slot is cleared. `Endpoint.Close`
  while `Register` is in flight returns `ErrClosed`; a ctx cancel inside
  `Register` returns `ErrNoReply` wrapping `ctx.Err()`.
- Two `RoleDial` registrations on one Endpoint for two tokens (`WaitMatch`
  with several tokens): the first match wins, the other is withdrawn. The
  same token twice: `ErrDuplicateRegistration`; the other role:
  `ErrSelfMatch`.

### 14.4 `cmd/daemon` and `cmd/bus` (against `brokertest`)

- Static tokens (RFC010's directional tokens): listener and dialer in two
  daemons match and complete KCP plus the kamune handshake on loopback; A
  dialing B while A also listens for B and B is offline does not match A
  with itself.
- A random token from `generate_p2p_token` given to a dialer: match. A
  second call returns a different token.
- `generate_p2p_token` without a running listener: `p2p_listener_required`.
- `broker_addr` without `rk`: `broker_key_required`; malformed:
  `invalid_broker_address`; wrong key: `p2p_match_failed` with
  `broker_key_mismatch`.
- Dialing a token the local listener holds: `p2p_self_dial`.
- Listener restart under the same token: stop and start within 1 s; a
  dialer 2 s later matches the new socket.
- `restart_server` keeps the broker key; the `get_share_info` URL carries
  `rk`.
- `remove_p2p_token`: the `brokertest` slot is cleared (DMN-07).
- Token status events go `pending`, `active`, and `lost` when `brokertest`
  pauses.
- Two-daemon test through the JSON API, using the `integration_test.go`
  subprocess pattern.

### 14.5 End-to-end

`cmd/relay/internal/broker/e2e_test.go`, in the relay module (it imports
the root module through `replace`; add `github.com/xtaci/kcp-go/v5` as a
direct test requirement unless RFC008 has landed):

1. `relayleg.GenerateKey()`; start the real `Broker` on `127.0.0.1:0` with
   default limits and real time.
2. Two `broker.Client`s from `Address{Host, Key.PublicKey()}`; two `udp4`
   sockets; two Endpoints.
3. Peer L: `Register(tok, RoleListen)`; `kcp.ServeConn` (or RFC008's
   `ListenUDP`) on its `PacketConn`; a kamune server on that listener with
   a temporary store.
4. Peer D: `Register(tok, RoleDial)`, `Wait`; check that `Match.Peer`
   equals L's socket address and that L's `Matches()` reports D's address.
5. D: `kcp.NewConn4` (or `DialUDP`) on its `PacketConn` to `Match.Peer`;
   kamune dial; one message each way.
6. Close L's registration; poll `Stats().Live` until 0 (WITHDRAW).

Second case: L's Endpoint is built on a tap around its `net.PacketConn`
that copies every datagram L writes to an attacker socket, which sends each
copy to the broker from its own address. Assert that D's match names L's
socket, that the attacker receives only COOKIEs, and that
`Stats().RegistryWrites` counts no write caused by the attacker's packets.

RFC006's cross-RFC run adds a broker case on top: `brokertest`, RFC010's
directional broker tokens, RFC008's `ListenUDP`/`DialUDP` on
`ep.PacketConn()`, and a third identity holding a leaked listen token.

## 15. Out of Scope (Deferred)

| Item                                                                 | Reason                                                                                                                                                       |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| IPv6 listening                                                       | The wire format carries 18-byte addresses already. Peers on different families cannot punch to each other, and dual-stack needs per-family cookies and limits |
| Hybrid post-quantum broker traffic (X-Wing, or X25519 plus ML-KEM-768) | Adds over 1 KB per REGISTER and the padding to match; protects RIDs and address pairing only (§8.6)                                                         |
| Forward secrecy for SEALED (Noise `ee`)                              | One extra X25519 key generation and exchange per downlink for metadata that `S_priv` theft exposes through REGISTER anyway                                  |
| Several RIDs in one REGISTER                                         | Would cut X25519 cost for listeners with many tokens; the per-IP rate of 10/s covers 64 contacts                                                            |
| Retransmission timer for a lost MATCHED to a listener holder         | The listener loses only its NAT kick; the dialer still punches. Dialer holders are covered by row 3                                                          |
| Token status badge in the bus frontend                               | The daemon needs `status` for its event stream; the bus keeps showing `expiresAt`                                                                            |
| Hiding the magic                                                     | Clients need it to demultiplex from the UDP path layer on one socket                                                                                         |

## 16. Implementation Plan

Each commit builds and passes `go test ./...` in every module. Commit
prefixes follow AGENTS.md: `relayconn:` for `pkg/relayconn/broker` (its
own commits), `relay:`, `daemon:`, `bus:`, `docs:`.

### 16.1 Commit groups

| #   | Commit                                                 | Module | Content                                                                                                                                                                                                                                      | Needs                                                                                     |
| --- | ------------------------------------------------------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| 1   | `relayconn: add broker v2 wire codec`                  | root   | `wire` package, golden vectors, cookie jar, `Ephemeral`, address parser                                                                                                                                                                      | RFC010 `pkg/rendezvous`; RFC009 `relayleg` key types (`PublicKey`, `KeyHint`, `LoadPrivateKeyFile`) |
| 2   | `relayconn: add broker v2 server core`                 | root   | `brokerserver`, `brokertest`, tests of §14.2; `golang.org/x/time` direct in the root `go.mod`                                                                                                                                                | 1; RFC009 `PrivateKey.ExtractShared`                                                      |
| 3   | `relayconn: add broker v2 endpoint and registration`   | root   | `Client`, `Endpoint`, `Registration` beside the v1 API; tests of §14.3                                                                                                                                                                      | 2                                                                                         |
| 4   | `relay: switch broker to v2 server core`               | relay  | `cmd/relay/internal/broker` loop, config and validation, `assets/config.toml`, `run.newBroker`; rewrite of `broker_test.go` (1,411 lines, mostly deleted), of `run_test.go` `TestNewBroker_DoesNotShareHubLimiter` and `TestNewBrokerLimits`, and of `config_test.go` | 2; RFC009 `services.Service.StaticKey` and its relay start-up commits                     |
| 5   | `daemon: use broker v2 endpoints for p2p`              | daemon | §11.3, schemas, tests                                                                                                                                                                                                                        | 3; RFC009's daemon commit                                                                 |
| 6   | `bus: use broker v2 endpoints for p2p`                 | bus    | §11.4, frontend, Wails bindings, tests                                                                                                                                                                                                       | 3; RFC009's bus commit                                                                    |
| 7   | `relayconn: remove broker v1 api`                      | root   | v1 client, codec and helpers                                                                                                                                                                                                                 | 4, 5, 6                                                                                   |
| 8   | `relay: add broker v2 end-to-end test`                 | relay  | §14.5                                                                                                                                                                                                                                        | 4; the `DialUDP` variant after RFC008's UDP root commits                                  |
| 9   | `docs: describe broker v2 protocol`                    | docs   | §17                                                                                                                                                                                                                                          | the code above; RELAY.md after RFC009's and RFC010's edits                                |

Before release, a benchmark of `brokerserver.Handle` on the reference relay
host sets the §9.6 limits.

### 16.2 Place in the overall order (RFC006)

- Commits 1 to 3 are new packages and land with the other new packages of
  the rework; they change no existing behaviour.
- Commit 4 lands in the relay module after RFC009's relay commits and
  RFC010's relay-session commits. From then on v1 broker clients fail at
  runtime against the relay, as expected.
- Commits 5 and 6 sit in each client's order: RFC009, then this RFC, then
  RFC010 (token source, ids and `RegisterPair` on top of these commits),
  then RFC008 (`ListenUDP`/`DialUDP` on `ep.PacketConn()`, `HolePunch`,
  `directp2p.go`), then RFC007. Each area's daemon schema edits sit in its
  own client commit; RFC010 rebases onto this RFC's schema edits.
- Commit 7 lands after 5 and 6. The final `kamune: delete pkg/exchange`
  commit (RFC006) waits for commits 4 and 7, since the v1 broker server
  seals NOTIFYs with `exchange.NewECDH`.
- RFC008 is not a dependency: until it lands, the clients run kcp-go
  directly on `ep.PacketConn()`.

### 16.3 Shared files

| File                                                                                   | Order                                   | This RFC's part                                                                             |
| -------------------------------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------- |
| root `go.mod`                                                                           | this RFC                                | `golang.org/x/time` direct                                                                  |
| `cmd/relay/run/run.go`                                                                  | RFC009, then this RFC                   | `newBroker(cfg, key)` from `svc.StaticKey()`                                                |
| `cmd/relay/internal/config/config.go`, `config_test.go`                                  | RFC009, then this RFC                   | the `[broker]` section of §12 and its validation                                            |
| `cmd/relay/assets/config.toml`                                                          | RFC009, then this RFC                   | the `[broker]` block of §12, the `[rate_limit]` comment about broker limiters               |
| `cmd/relay/README.md`                                                                   | RFC009, then this RFC                   | broker section and config row                                                               |
| daemon `network.go`, `param.go`, `p2p.go`, `p2plistener.go`, `broker.go`, schemas        | RFC009, this RFC, RFC010, RFC008, RFC007 | §11.3                                                                                       |
| `directp2p.go` (daemon and bus)                                                         | this RFC, then RFC008                   | `sendNATKick` signature only                                                                |
| bus `network.go`, `app.go`, `p2p.go`, `p2plistener.go`, `broker.go`, `punchfilter.go`, frontend, bindings | RFC009, this RFC, RFC010, RFC008, RFC007 | §11.4                                                                                       |

### 16.4 Scope reduction

If the work must shrink, the REPLACED notice with the `Contested` status,
and the per-/24 cap, can move to a follow-up without changing the wire
format. Nothing else is optional for the findings.

## 17. Documentation Updates

- `docs/RELAY.md`: replace all of "Broker: STUN-Echo and Signal
  Introduction" (Wire Format, Static Tokens, Server Behavior, Rate Limits
  and Registry Size, Anti-Fingerprint, Threat Model, Replay Considerations)
  with §7 to §9 and §13 of this RFC; rewrite the "Broker matching" text
  under the relay's Static Tokens section (no 16-byte cut; passive
  observers no longer read the value; directional tokens per RFC010); the
  broker rows of the Configuration Reference; "Direct UDP Broker (single
  host)" under Deployment Patterns (the address now carries `?rk=`); the
  broker registry item in Known Limits; the residual risks of §13.2 in the
  threat model (DOC-02). RFC008 adds the first-byte rule and the Endpoint
  socket arrangement to the broker section after this RFC's rewrite.
- `cmd/relay/README.md`: the `broker` row of the config table and the
  "Broker (UDP signaling)" section (sizes, crypto, shared relay key, address
  format).
- `cmd/relay/assets/config.toml` (in commit 4, not the docs commit): the
  `[rate_limit]` comment about broker limiters, and the `[broker]` block of
  §12 (drop the 35 s rebind text).
- `docs/DAEMON.md`: `start_server` and `dial` p2p inputs (`broker_addr` as
  `udp://host:port?rk=...`; the `wss://broker.example.com` examples under
  `start_server`, `dial`, `generate_p2p_token`, `list_p2p_tokens` and the
  `p2p_tokens` event are wrong today, DOC-10), `generate_p2p_token` (no
  `broker_addr`; requires a running p2p listener; random tokens fresh per
  call), the token `status` field and events, the new error codes, the
  `get_share_info` p2p URL, and the `p2p` row of the Transports table,
  co-edited with RFC008 ("`newP2PListener` + `ServeWithListener`").
- The daemon JSON schemas listed in §11.3 (in commit 5).
- `docs/SPEC.md`: no broker content today, and this RFC adds none. RFC008
  writes the first-byte rule into §9.2.
- `CHANGELOG.md`: untouched unless the maintainer asks.

## 18. Open Questions

1. **Source filter on the broker p2p listener.** Should the listener
   restrict accepted UDP paths to the IP of a `Match.Peer` it has received,
   through RFC008's `UDPWithSourceFilter`? The current clients filter this
   way (daemon `p2pListener.admitted`, bus `punchFilter`); RFC008 applies
   the filter to direct P2P only. This RFC delivers `Match.Peer` to the
   listener either way; the decision is RFC008's open question 1.
2. **Server read buffer.** The v2 socket loop (§9.7) reads into a 2,048-byte
   buffer and keeps the v1 read-error backoff (after 16 failed reads in a
   row, 100 ms before each further read). On Windows a larger datagram
   fails the read with `WSAEMSGSIZE` (the REL-01 pattern), so a stream of
   oversize datagrams would hold the loop at one read per 100 ms. Should the
   loop read into 65,536 bytes, as the Endpoint does (§10.4), or treat
   `WSAEMSGSIZE` as a dropped packet without backoff?
