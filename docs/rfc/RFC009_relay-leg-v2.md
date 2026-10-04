# RFC: Relay Leg v2: Pinned Relay Keys and Access Keys

**Status:** Draft

**Target:** Kamune Protocol Specification before v1.0 (not scheduled)

**Relates to:** §9.3 (Relay), §9.4 (Connection Contract), §13 (Constants and
Limits); `docs/RELAY.md` (Design Goals, Threat Model, Protocol, Authentication
Modes, Rate Limiting, Transports, Go Client, Configuration Reference,
Deployment Patterns, Known Limits); RFC006 (overview), RFC007 (handshake),
RFC010 (tokens), RFC011 (broker)

---

## 1. Summary

The relay gets a long-term static X25519 key, kept in `server.data_dir` next
to its self-signed certificate and logged at startup as
`rk1-<52 base32 chars>`. Clients carry it in the relay address
(`wss://relay.example:8891?rk=rk1-...`) or in a local key store (SSH
`known_hosts` style). On the relay leg, the ephemeral, unauthenticated HPKE
exchange of `pkg/exchange` is replaced by a new two-message handshake,
**relayleg v2**:

```
client                                              relay
  ClientHello = flags, key_hint, enc_s, eph_pk_c, binder  ->
                    (relay checks binder first: one HMAC, no KEM work)
                                                 <-  ServerHello = enc_e, finished_r
  verify finished_r (proves sk_R and the PSK)
  [Register]  (record 0, AEAD)                   ->
                                                 <-  [Registered]
```

- `enc_s` is an HPKE (RFC 9180) DHKEM(X25519) encapsulation to the relay
  static key. Only the holder of the static private key can derive the
  handshake secret. This is the relay authentication.
- `eph_pk_c`/`enc_e` is an HPKE MLKEM768-X25519 (X-Wing) ephemeral
  encapsulation. It gives forward secrecy and the hybrid post-quantum
  confidentiality the relay leg has today.
- The relay PSK (shown to users as the "relay access key") is never sent. It
  is the input of the first extract step of a TLS 1.3 style key schedule. The
  client proves PSK knowledge with a TLS 1.3 style **PSK binder** in
  ClientHello; the relay proves it (and `sk_R`) with `finished_r`.
- A relay with a PSK is **silent** toward anyone without it: no key response,
  no alerts, a delayed close. A wrong PSK therefore reads as "rejected", never
  as "relay key changed".
- The token (and anything else secret) is sent only in record 0, after the
  client has checked `finished_r`.
- First contact (no key known) fetches the key in-band. Over verified TLS
  (system roots or a `cert=` pin) the key is accepted and stored; over ws, tcp
  or `tls=skip` the client stops and shows the key to the user.

Patterns: Noise **NKpsk0** (responder static key known in advance, PSK mixed
first) built from KEMs as in PQNoise and KEMTLS; the TLS 1.3 key schedule
(`HKDF-Extract` chain, `HkdfLabel`, PSK binder, server `Finished` over a
transcript hash, per-record nonce); SSH `known_hosts` for pin storage (a pin
is never replaced silently); probe resistance in the style of obfs4 and
Shadowsocks AEAD servers (no reply to unauthenticated input).

Round trips after the TCP, TLS or WebSocket connect: the client waits for two
relay replies with a known key (ServerHello, `Registered`) and three on first
contact over verified TLS (KeyResponse, ServerHello, `Registered`). Today it
waits for three with a password (the merged exchange message, the `Auth`
acknowledgement, `Registered`) and two without.

The change ships as a wire-incompatible hard cut, as RFC004 does: the
relay-leg wire protocol, `pb.Frame`, the relay configuration, the `relayconn`
Go API and the client JSON and GUI fields all change, and no backward
compatibility is kept. A v1 client gets alert 1 or silence from a v2 relay; a
v2 client gets `ErrHandshakeRejected` from a v1 relay, whose text says the
relay closed the connection during the relay-leg handshake. This RFC is one
part of the pre-v1.0 protocol rework that RFC006 describes; the rework is not
implemented now.

## 2. Current Behavior

These statements describe `main` (with the bus fixes merged).

Relay leg (`pkg/exchange`, `pkg/relayconn`):

- `relayHandshake` (`dial.go`) and `listenHandshake` (`listener.go`) run
  `exchange.Initiate` with whatever endpoint answers. `Initiate` sends a fresh
  MLKEM768-X25519 HPKE public key, reads the relay's merged reply (an
  encapsulation to that key plus the relay's own fresh public key) and sends
  an encapsulation back; `exchange.Accept` is the relay side. Both key pairs
  are ephemeral, so the channel authenticates neither end. Each frame is
  sealed with HPKE ChaCha20-Poly1305 (`exchange.Overhead`, 16 bytes).
- With `WithPassword`, `sendAuth` (`auth.go`) sends `pb.Auth{psk}` with the
  raw password inside that channel and treats any `Auth` frame as success.
  The relay (`handleRelayConn` in
  `cmd/relay/internal/handlers/ws_handler.go`) compares it with
  `subtle.ConstantTimeCompare` against `Hub.Password()` and answers with an
  empty `Auth`; the reply proves nothing about the relay.
- The client then sends `Register` with the token. Over ws or tcp, or TLS
  without a verified or pinned certificate, an active on-path attacker that
  runs `exchange.Accept` toward the client receives the password and the
  token (RC-03). `docs/RELAY.md` (Threat Model, Authentication Modes, TLS)
  documents this.
- `checkRegisteredToken` (`token.go`) checks the token echoed in `Registered`
  (`ErrRelayTokenMismatch`, `ErrInvalidRelayToken`). The context passed to
  the helpers bounds only the handshake (`context.WithoutCancel` in
  `relayHandshake`, `listenHandshake` and `newWSAdapter`).
- The client API is eight helpers: `DialRelay`, `DialRelayWSS`,
  `DialRelayTCP`, `DialRelayTLS`, `ListenRelay`, `ListenRelayWSS`,
  `ListenRelayTCP`, `ListenRelayTLS`. The WebSocket helpers hard-code the path
  `/ws`; the wss and tls helpers take a `*tls.Config`. `PinnedTLSConfig`
  (`pin.go`) trusts exactly one certificate by SHA-256 fingerprint, with
  `MinVersion: tls.VersionTLS12`.

Relay (`cmd/relay`):

- `[server] password` (`config.Server.Password`), empty for open mode.
  `services.New` logs `psk auth on: clients must send server.password`. The
  config loader rejects unknown keys (`ErrUnknownKey`).
- A `[tls]` or `[wss]` listener without certificate files uses a self-signed
  certificate that `certStore` (`run/tls.go`) creates once in
  `server.data_dir` (`relay-cert.pem`, `relay-key.pem`, written with
  `writeNewFile`) and logs as `tls certificate listener=... sha256=...`.
  `newServerTLSConfig` requires TLS 1.3. The relay has no long-term key for
  the relay leg.
- Before the exchange, the WebSocket handler sets the read limit to
  `max_message_size` (65,536 to 131,072 bytes) and the TCP and TLS framing
  accepts frames up to the same limit, so an unauthenticated connection can
  make the relay buffer that much.
- The per-address rate limiter runs before the exchange.
  `session.handshake_timeout` (default 30 s) bounds accept to `Registered`,
  through the connection deadline on tcp and tls and a timer on ws and wss.

Clients:

- bus (`cmd/bus/relay.go`): `parseRelayAddr` reads
  `[scheme://]host:port[?insecure=true|false][&pin=<sha256>]` with `wss` as
  the default scheme. `relayAddress.tlsConfig` uses `PinnedTLSConfig` for a
  pin and otherwise TLS 1.2 minimum with `InsecureSkipVerify` from the caller
  or from `?insecure=`. The frontend builds the address from scheme buttons, a
  host, a pin field and a "Skip TLS verification" checkbox
  (`lib/relayaddr.ts`), and has a "Relay password" field. Imported URLs never
  turn verification off and default to `wss` (`lib/importurl.ts`). The share
  card is `relay://<host>?token=<hex>&scheme=<scheme>[&password=1]`, without
  pin or `insecure`.
- daemon (`cmd/daemon/relay.go`): `parseRelayAddr` and `parseInsecureFlag`
  read `[scheme://]host:port[?insecure=true|false]` with `wss` as the
  default; a separate `relay_pin` parameter (`parseRelayPin`) pins the
  certificate; `start_server` and `dial` take `password`. `relayAddrWarning`
  logs a warning for ws, tcp or `insecure=true`, and `wrapRelayError` guesses
  "wrong password?" from a WebSocket close frame. `relayShareInfo` has
  `address`, `scheme`, `token`, `password` and `pin`.
- tui (`cmd/tui/relayaddr.go`): `relayTarget` parses `scheme://host:port`
  with `wss` as the default, next to a "Relay certificate SHA-256
  fingerprint" input and a "Relay password" input. Without a pin it checks
  the system roots with TLS 1.2 minimum.

Each client has its own parser and its own pin field, and none of them can
authenticate the relay over ws, tcp or unverified TLS.

## 3. Findings Addressed

Finding IDs are those of `docs/RED_TEAM_REVIEW.md`.

| ID     | Status after this RFC |
| ------ | --------------------- |
| RC-03  | Closed. The relay is authenticated by its static key on every transport, independent of TLS. The PSK is never transmitted; the client proves it with a binder and the relay proves it in `finished_r`. The token is sent only after relay authentication. `?insecure=true` is removed. Pins are never replaced by an address or a share card (section 13.2), so an attacker cannot make the user drop or overwrite a pin through routine-looking errors. The RELAY.md text on PSK exposure is rewritten (section 17). |
| REL-02 | Closed. Interim fixes on `main`: the certificate is persisted and logged since 10820a7 (`certStore` in `cmd/relay/run/tls.go`), and each client gained its own pin option (bus `?pin=`, daemon `relay_pin`, tui fingerprint input). This RFC puts the `cert=` pin in the shared address parser used by bus, daemon and tui, moves `PinnedTLSConfig` and every client TLS config to TLS 1.3 minimum, and makes `tls=skip` safe: an unverified TLS channel never yields a key without the user (section 13.3). |
| DMN-10 | Closed. Interim fix on `main`: a scheme-less address means `wss` and the daemon warns on plaintext (`relayAddrWarning`). This RFC makes `wss` the default in all three clients through `relayconn.ParseAddress`, and with a pinned key the scheme no longer decides whether the relay is authenticated. |
| BUS-36 | Closed. Interim fix on `main`: imported URLs never turn TLS verification off and default to `wss`. This RFC removes `insecure` (an unknown parameter; import ignores it), carries the relay address in one `addr` share parameter parsed in Go, and lets an imported `rk` seed a pin only when none exists; it never overwrites one. An imported `tls=skip` ends in a key prompt, never in a silent connection. |
| BUS-29 | Closed. Fixed on `main` (the relay fallback after a failed hole punch); this RFC rewrites `P2PFallbackDialog.svelte` to the new call (section 15.2), with an address field and an access-key field. |
| RC-17  | Already fixed by e99ea89 (`checkRegisteredToken`, `ErrRelayTokenMismatch`, `ErrInvalidRelayToken`). The new `Dial` and `Listen` keep the check; the key store is written only after it passes (section 13.2). The tests in `handshake_test.go` are ported (section 16, test 23). |
| RC-14  | Already fixed by e8805a4 (`context.WithoutCancel` in `relayHandshake`, `listenHandshake`, `newWSAdapter`). The new `Dial` and `Listen` keep "ctx bounds only the handshake"; `context_test.go` is ported (test 24). |
| TUI-08 | Not claimed. Fixed on `main` (scheme in the address, `wss` default, password and pin inputs). This RFC replaces tui's parser with `relayconn.ParseAddress` and its inputs with a relay key and an access key (section 15.4); the implementer re-checks the finding afterwards. |

No finding is left partly closed by this RFC. The relay itself still reads the
token and sees message sizes and timing, by design: it is the endpoint of this
leg. What a relay can learn about the peers through the peer handshake
(KAM-02, KAM-10) is RFC007's subject.

## 4. Goals and Non-goals

Goals:

1. Only the real relay (holder of `sk_R`) can read the token and any frame the
   client sends, on ws, tcp, tls and wss, with or without TLS verification,
   and through a CDN that terminates TLS.
2. The PSK is never sent. A client that holds the PSK also authenticates the
   relay by it.
3. No secret leaves the client before the relay is authenticated.
4. Forward secrecy and hybrid PQ confidentiality of the relay leg (X-Wing
   ephemeral), as today.
5. One address format (`relayconn.ParseAddress`) for all clients and share
   cards, carrying the relay key, an optional certificate pin and a WebSocket
   path.
6. One source of truth for pins (the key store); errors that tell "wrong
   access key", "relay could not prove the pinned key" and "you supplied a
   different key" apart.
7. A relay with a PSK does not reveal itself to unauthenticated probes.

Non-goals (section 19 lists the deferrals): client authentication beyond the
PSK, low-entropy passwords (PAKE), relay key rotation with overlap,
post-quantum authentication of the relay, end-to-end protection of peer
traffic (RFC007), traffic-analysis resistance on ws and tcp (sizes, magic
bytes).

## 5. Decisions

### 5.1 Maintainer decisions

| Question | Decision |
| -------- | -------- |
| Schedule | Not implemented now. Draft, targeting the specification before v1.0, not scheduled. |
| Compatibility | Wire-incompatible hard cut, as RFC004 is. No backward compatibility: wire format, `pb.Frame`, relay config, Go API and client fields all change. |
| Relay access secret | Generated access keys only: `psk1-` plus base32 of 32 random bytes (section 6.3). Passwords are not supported, so no PAKE is scheduled (section 19). |

### 5.2 Proposed defaults

| Question | Proposed default |
| -------- | ---------------- |
| Relay authentication | A static X25519 relay key that clients pin, used on every transport, independent of TLS. |
| Probe behaviour of a PSK relay | Always silent toward unauthenticated input (section 7.2). No `server.silent` option. |
| Probe behaviour of a relay without a PSK | Answers KeyRequest and sends alerts. Its key is in its published address anyway; silence would only cost its users the first-contact path. |
| First contact over verified TLS | Key accepted and stored without a prompt (behind a TLS-terminating CDN this trusts the CDN for the first contact only). |
| First contact over ws, tcp or unverified TLS | The client stops and returns the key for a human to confirm. No policy option changes this. |
| Pin authority | The key store. An address `rk` never replaces a stored pin unless the caller passes `WithReplaceStoredKey()` after a user confirmed both keys. |
| Daemon trust step | The app re-sends the command with `rk` in `relay_addr`; there is no separate trust command. |
| Default scheme | `wss`, in every client. |
| Keys per relay | One. `key_hint` is on the wire and in the transcript so that a later relay can hold two keys without a version change. |
| 0-RTT | None. Register is sent only after `finished_r` verifies. |
| TLS exporter binding | None. |
| Silent close delay | Uniform in [2 s, 8 s], capped by the handshake deadline. |
| Per-client pins on `main` | Bus `?pin=`, daemon `relay_pin` and the tui fingerprint input are replaced by `cert=` in the relay address. |

## 6. Keys and Encodings

### 6.1 Relay static key

- Algorithm: X25519 (`crypto/ecdh.X25519()`), used through HPKE as
  `DHKEM(X25519, HKDF-SHA256)` (KEM id 0x0020), via
  `hpke.NewDHKEMPrivateKey(ecdhKey)`.
- Public key: 32 bytes. Because it is short, the pin is the key itself, not a
  hash of it: the client needs the full key to encapsulate to it. RFC011 pins
  the broker by the same key in the same form.
- Text form (`relayleg.PublicKey.String`): `rk1-` followed by the 32 bytes in
  RFC 4648 base32, lowercase alphabet `a-z2-7`, no padding (52 chars). Total
  56 chars.
- Parsing (`relayleg.ParsePublicKey`):
  - trims surrounding spaces, accepts upper or lower case, ignores `-` and
    spaces inside the base32 part (so a grouped display form
    `rk1-abcd-efgh-...` parses);
  - rejects any other prefix or length, any non-base32 character, a final
    character whose 4 unused low bits are not zero (so each key has exactly
    one spelling, and `ParsePublicKey(k.String()) == k` and
    `ParsePublicKey(s).String() == canonical(s)` hold for every accepted
    `s`), and the all-zero key;
  - all errors wrap `ErrInvalidRelayKey`.

  Other low-order points parse; `Initiate` maps the `crypto/ecdh` error that
  `hpke.NewSender` returns for them to `ErrInvalidRelayKey` before anything is
  sent.
- Display form (`relayleg.PublicKey.Display`): `rk1-` plus the base32 in
  groups of 4 separated by `-`, for dialogs and logs that humans compare.
- Key hint (`relayleg.KeyHint(pk)`): first 4 bytes of
  `SHA-256("kamune relayleg v2 key hint" || pk)`. Public. Lets a relay say "I
  do not hold that key" (alert 3) and keeps the v1.0 wire format ready for a
  relay that holds two keys during a rotation (section 19), without a version
  bump. RFC011 uses the same function for the same purpose.

### 6.2 Key file

- File: `<data_dir>/relay-static-key.pem`, mode 0600, data dir 0700 (the same
  directory as `relay-cert.pem` and `relay-key.pem`).
- Content: one PEM block, type `KAMUNE RELAY STATIC KEY`, body the 32-byte
  X25519 private scalar (`ecdh.PrivateKey.Bytes()`), no headers. Any other
  block type, a second block, trailing non-whitespace data, or a body that is
  not 32 bytes is a startup error.
- File helpers live in `relayleg` (RFC011's golden vectors load a test key
  with them; the broker has no key file option of its own):
  `CreatePrivateKeyFile(path)` (`O_CREATE|O_EXCL`, mode 0600, fsync of file
  and directory, as `writeNewFile` in `cmd/relay/run/tls.go`) and
  `LoadPrivateKeyFile(path)`.
- Created on first start. Never replaced: a file that does not parse stops
  the relay with an error that names the path and tells the operator to
  restore it, or to move it away knowing every client pin breaks (section 17,
  "Replacing the relay key").
- Loaded first in `run.Run`, before `services.New` and before any listener
  (startup stays atomic, as for certificates), even when only `[broker]` is
  enabled, because the broker (RFC011) uses it.
- `data_dir` empty: the path comes from `config.DefaultDataDir()`, as for the
  certificate. If that fails (no `$HOME`, systemd `DynamicUser`), the startup
  error says `set server.data_dir: <cause>`. The Dockerfile comment that
  describes the `/var/lib/kamune-relay` volume mentions the key file; the
  existing `VOLUME ["/var/lib/kamune-relay"]` keeps it.
- Logged at startup at info level:

  ```
  INFO relay key rk=rk1-<52 chars> file=<path>
  INFO relay address listener=wss address=wss://<public-host>:8891?rk=rk1-...
  ```

  One `relay address` line per enabled ws, wss, tcp or tls listener, with the
  bind port and the literal placeholder `<public-host>`; for a listener that
  serves the self-signed certificate it also appends `&cert=<sha256 hex>`.
  The lines are `Address.String()` output, so they parse.

### 6.3 Access key

The access key is the relay PSK; the config and the Go API call it `psk`.

The relay `password` becomes a generated 32-byte key: the binder in every
ClientHello and `finished_r` in every ServerHello let an observer test PSK
guesses offline (section 11.3), so a low-entropy password would fall to a
dictionary attack.

- Type: `relayleg.PSK [32]byte`.
- Text form: `psk1-` + 52 lowercase base32 chars, with the same alphabet and
  parsing rules as the relay key, including the canonical last character
  (`relayleg.ParsePSK`, `ErrInvalidPSK`). The all-zero PSK is rejected: its
  early secret would equal the published no-PSK early secret.
- Generated by `kamune-relay -gen-psk` (prints one value, exits, needs no
  config) or `relayleg.GeneratePSK()`. This is the only documented source.
- Config key `[server] psk = ""`. `password` is removed; because the config
  loader rejects unknown keys (`ErrUnknownKey`), an old config with
  `password` stops the relay instead of starting it open. `Validate` rejects
  a non-empty `psk` that `ParsePSK` refuses (so `internal/config` imports
  `relayleg`).
- Clients: the "relay password" field becomes "relay access key" and must
  parse as `psk1-...`.
- A PSK relay requires clients to know its key in advance (section 13.3), so
  the operator hands out the access key together with an address that
  carries `rk`.

## 7. Wire Format

The relay leg keeps today's framing: one WebSocket binary message per frame
(ws, wss), or a 2-byte big-endian length prefix per frame (tcp, tls). Every
handshake message is exactly one frame. All integers are big-endian.

### 7.1 Handshake messages

Common 4-byte header:

| Offset | Size | Field   | Value              |
| ------ | ---- | ------- | ------------------ |
| 0      | 2    | magic   | `0x4B 0x52` ("KR") |
| 2      | 1    | version | `0x02`             |
| 3      | 1    | type    | see below          |

| Type   | Name        | Direction | Total size | Layout after header |
| ------ | ----------- | --------- | ---------- | ------------------- |
| `0x01` | KeyRequest  | C→R       | 4          | nothing |
| `0x02` | KeyResponse | R→C       | 36         | `relay_pk[32]` |
| `0x03` | ClientHello | C→R       | 1289       | `flags[1]` `key_hint[4]` `enc_s[32]` `eph_pk_c[1216]` `binder[32]` |
| `0x04` | ServerHello | R→C       | 1156       | `enc_e[1120]` `finished_r[32]` |
| `0x05` | Alert       | R→C       | 5          | `code[1]` |

- `flags`: bit 0 (`0x01`) = client uses a PSK. Bits 1-7 must be 0.
- `key_hint`: `KeyHint(relay_pk)` of the key the client encapsulated to.
- `enc_s`: HPKE DHKEM(X25519) encapsulated key (32 bytes) toward `relay_pk`.
- `eph_pk_c`: fresh HPKE MLKEM768-X25519 public key (1184 + 32 = 1216
  bytes).
- `binder`: section 8 when flag bit 0 is set; 32 zero bytes otherwise.
- `enc_e`: HPKE MLKEM768-X25519 encapsulated key toward `eph_pk_c` (1088 + 32
  = 1120 bytes).
- `finished_r`: section 8.
- `relayleg.MaxHandshakeFrame = 1289`, the largest frame either side accepts
  before ServerHello.

The sizes match Go 1.26.6 `crypto/hpke`. A message of any other length for
its type is malformed.

A client that reads any relay frame whose magic is `KR` but whose version
byte is not 2 returns `ErrUnsupportedVersion`. This is the general header
check, not a special case for alerts.

### 7.2 Alerts and silence

Alerts are plaintext and unauthenticated and are sent only before
ServerHello. A relay without a PSK sends them for any error; a relay with a
PSK sends one only after a valid binder (from S2). After an alert the relay
closes.

| Code | Name             | Sent when | Client error |
| ---- | ---------------- | --------- | ------------ |
| 1    | `bad_message`    | wrong magic, type, length or reserved flags; bad `enc_s` or `eph_pk_c`; a second KeyRequest; flag bit 0 clear with a non-zero binder | `ErrBadMessage` |
| 2    | `psk_unexpected` | relay has no PSK and flag bit 0 is set | `ErrPSKUnexpected` |
| 3    | `unknown_key`    | `key_hint` matches no key the relay holds | `ErrRelayKeyNotHeld` |

**Silent rejection** (relay with a PSK): any first frame that is not a
well-formed ClientHello with flag bit 0 set and a valid binder (a KeyRequest,
garbage, a ClientHello without PSK, a wrong binder, an oversize frame) gets
no bytes back. `relayleg.Accept` returns `ErrSilentReject`; the handler stops
reading, waits a uniformly random delay in [2 s, 8 s] (capped by the
handshake deadline), then closes. A probe sees a server that accepts bytes
and hangs up, as many non-kamune servers do. A relay without a PSK is public
and answers KeyRequest; its key is in its published address anyway.

The client never changes its flags, key or PSK and retries in response to an
alert or a silent close. A connection that closes before ServerHello with no
alert returns `ErrHandshakeRejected` ("the relay closed the connection during
the relay-leg handshake: wrong or missing access key, or not a kamune v2
relay").

### 7.3 Records

After ServerHello both directions carry **records**: the AEAD ciphertext of
one serialized `pb.Frame` (section 9), one record per transport frame, no
header.

`pb.Frame` changes (`pkg/relayconn/pb/relay.proto`): `Auth auth = 6` and
`message Auth` are deleted, with `reserved 6; reserved "auth";` in `Frame`.
RFC010 adds `Refused refused = 7`. The client's record 0 must be `Register`;
the relay's record 0 is `Registered` or, once RFC010 lands, `Refused`.
`Message`, `Ping` and `Pong` are unchanged.

```protobuf
message Frame {
  reserved 6;
  reserved "auth";
  oneof kind {
    Register   register   = 1;
    Registered registered = 2;
    Message    msg        = 3;
    Ping       ping       = 4;
    Pong       pong       = 5;
    // Refused refused    = 7;  added by RFC010
  }
}
```

## 8. Key Schedule

Hash and KDF: SHA-512 and HKDF-SHA512 (`crypto/hkdf`, `crypto/sha512`). HMAC
is HMAC-SHA512 (`crypto/hmac`).

```
ExpandLabel(Secret, Label, Context, L) =
    HKDF-Expand(Secret, HkdfLabel, L)
HkdfLabel = uint16(L) || uint8(len(FullLabel)) || FullLabel
                      || uint8(len(Context))   || Context
FullLabel = "kamune relayleg v2 " || Label           (ASCII)
```

This is the TLS 1.3 `HkdfLabel` structure with a kamune prefix.

HPKE shared secrets (both through the HPKE exporter, AEAD `ExportOnly`, KDF
HKDF-SHA512, base mode):

```
ss_s:  client  enc_s, ctx = hpke.NewSender(relay_pk_hpke, HKDFSHA512, ExportOnly,
                                           info = "kamune relayleg v2 static")
       relay   ctx = hpke.NewRecipient(enc_s, sk_R_hpke, HKDFSHA512, ExportOnly,
                                       info = "kamune relayleg v2 static")
       ss_s = ctx.Export("kamune relayleg v2 ss", 32)

ss_e:  relay   enc_e, ctx = hpke.NewSender(eph_pk_c, HKDFSHA512, ExportOnly,
                                           info = "kamune relayleg v2 ephemeral")
       client  ctx = hpke.NewRecipient(enc_e, eph_sk_c, HKDFSHA512, ExportOnly,
                                       info = "kamune relayleg v2 ephemeral")
       ss_e = ctx.Export("kamune relayleg v2 ss", 32)
```

Transcript:

```
TH0 = SHA-512("kamune relayleg v2 prologue" || relay_pk)
TH1 = SHA-512(ClientHello[0:1257])                       // CH without binder
TH2 = SHA-512(TH0 || ClientHello || ServerHello[0:1124]) // SH without finished_r
TH3 = SHA-512(TH0 || ClientHello || ServerHello)
```

`ClientHello` and `ServerHello` are the full frames, headers included, so the
version, the PSK flag, the key hint and the binder are bound. KeyRequest and
KeyResponse are not in the transcript; `relay_pk` enters through TH0. TH1
leaves `relay_pk` out on purpose: a relay checks the binder before it looks
at the key, so a client with the right PSK and a wrong key gets alert 3 or
`ErrRelayAuthFailed`, never a silent close that would look like a PSK
problem.

Schedule (TLS 1.3 shape: early secret from the PSK, binder from the early
secret, then one extract per KEM secret):

```
psk_ikm = PSK (32 bytes) if flags bit 0 else 32 zero bytes
ES = HKDF-Extract(salt = 64 zero bytes,                      ikm = psk_ikm)

binder_key = ExpandLabel(ES, "binder", "", 64)
binder     = HMAC-SHA512(binder_key, TH1)[0:32]              // flag bit 0 only

SS = HKDF-Extract(salt = ExpandLabel(ES, "derived", "", 64), ikm = ss_s)
HS = HKDF-Extract(salt = ExpandLabel(SS, "derived", "", 64), ikm = ss_e)

fk_r       = ExpandLabel(HS, "relay finished", "", 64)
finished_r = HMAC-SHA512(fk_r, TH2)[0:32]

c2r_key = ExpandLabel(HS, "c2r key", TH3, 32)
c2r_iv  = ExpandLabel(HS, "c2r iv",  TH3, 24)
r2c_key = ExpandLabel(HS, "r2c key", TH3, 32)
r2c_iv  = ExpandLabel(HS, "r2c iv",  TH3, 24)
```

Both sides compare `binder` and `finished_r` with
`subtle.ConstantTimeCompare`. All intermediate secrets, `eph_sk_c` and both
HPKE contexts are dropped (not kept in any struct) once the record keys
exist.

Domain strings used by this RFC (RFC006 checks them against the other parts):

| Kind | Strings |
| ---- | ------- |
| Expand-Label prefix | `kamune relayleg v2 ` + `binder`, `derived`, `relay finished`, `c2r key`, `c2r iv`, `r2c key`, `r2c iv` |
| HPKE info / export context | `kamune relayleg v2 static` (DHKEM X25519), `kamune relayleg v2 ephemeral` (X-Wing) / `kamune relayleg v2 ss` |
| Transcript prologue | `kamune relayleg v2 prologue` |
| Key hint | `kamune relayleg v2 key hint` (shared with RFC011, same function and purpose) |

The schedule is one pure internal function, so it can be tested with fixed
inputs (section 16, test 2):

```go
func schedule(psk *PSK, relayPK PublicKey, ch, sh, ssS, ssE []byte) (
	binder, finishedR []byte, keys recordKeys)
```

## 9. Record Layer

`relayleg.Channel` replaces `*exchange.Channel` on the relay leg (same method
set and semantics, so `RelayConn`, `RelayListener` and the relay `Hub` change
only their field types):

- AEAD: XChaCha20-Poly1305 (`golang.org/x/crypto/chacha20poly1305.NewX`,
  already a dependency). Overhead 16 bytes, the same as `exchange.Overhead`,
  so `RelayConn.MaxFrameSize` (65,511) and SPEC §9.4's `transportReserve`
  stay valid.
- Nonce for record `seq` (per direction, starts at 0):
  `iv XOR (16 zero bytes || uint64be(seq))` (TLS 1.3 per-record nonce).
- AAD: empty (the sequence number is implicit, the direction is bound by the
  key).
- Read: an AEAD open failure returns an error wrapping `ErrRecordAuth`; the
  caller closes. A record that is reordered, replayed, modified or dropped in
  the middle of the stream makes the next open fail.
- Truncation: there is no authenticated close on the relay leg, so an
  attacker can cut the tail of the stream undetected, exactly as a network
  drop. This is accepted: the peer layer's `RouteCloseTransport` (RFC007) is
  end to end, so the peers tell a graceful close from a drop, and the relay
  sees a cut stream as a disconnect.
- Write: the same rules as `exchange.Channel`: a frame-size check against the
  transport's `FrameLimiter` before sealing (`ErrFrameTooLarge`, the channel
  stays usable); a failed transport write after sealing breaks the channel
  (`ErrChannelBroken`, sticky); `WriteBytesWithin` arms a per-write deadline
  under the write lock.
- `seq` reaching `2^64-1` breaks the channel (unreachable in practice; tested
  through an internal hook).

`ReadWriter`, `FrameLimiter`, `ErrFrameTooLarge` and `ErrChannelBroken` move
from `pkg/exchange` into `relayleg` (the `_ exchange.FrameLimiter`
assertions in `pkg/relayconn/transport.go` become `_ relayleg.FrameLimiter`).
RFC007 stops the root handshake calling `pkg/exchange`; `kamune.Conn` keeps
embedding `exchange.ReadWriter` until the final cleanup. Once RFC007 and
this RFC have landed, `exchange.Initiate`, `Accept` and `Channel` have no
callers; `exchange.ECDH` stays while today's relay-token code (removed by
RFC010) and the v1 broker (removed by RFC011) use it, and the final cleanup
that RFC006 orders deletes the package.

## 10. State Machines

### 10.1 Client

States of `relayleg.FetchKey` and `relayleg.Initiate`, driven by `relayconn`:

```
C0  (only on first contact, section 13.3)
    send KeyRequest
    read frame: KeyResponse(36)  -> relay_pk to relayconn
                Alert            -> typed error, close
                EOF/close        -> ErrHandshakeRejected
                anything else    -> ErrBadMessage, close
    relayconn decides: verified TLS -> keep the connection, go to C1;
                       otherwise    -> close, return *UnknownRelayKeyError.
C1  generate eph_sk_c; HPKE-encapsulate to relay_pk -> enc_s, ss_s
    (encapsulation error, e.g. low-order key -> ErrInvalidRelayKey, nothing sent)
    compute binder if PSK; send ClientHello
C2  read frame: ServerHello(1156) -> decapsulate enc_e -> ss_e; schedule;
                                     verify finished_r
                                     mismatch -> ErrRelayAuthFailed, close
                Alert              -> typed error, close
                EOF/close          -> ErrHandshakeRejected
                anything else      -> ErrBadMessage, close
C3  relay authenticated: Initiate returns *Channel and the verified relay_pk.
C3a relayconn: resolve the token (WithToken value, or call the TokenFunc with
    the authenticated relay key; RFC010's hook point). TokenFunc error -> close,
    return it. Nothing has been sent on the channel yet.
C4  send Register as record 0; read record 0:
       Registered -> checkRegisteredToken (RC-17); then write the key store
                     if section 13.2 says so; done.
       Refused    -> RFC010's typed error (once RFC010 lands), close.
       other/AEAD failure -> error, close. Key store untouched.
```

Nothing secret is sent before C4. The PSK only enters the binder and the key
schedule.

### 10.2 Relay

States of `relayleg.Accept`:

```
S0  (handler has set the read limit to MaxHandshakeFrame)
    read frame
    no PSK configured:
       KeyRequest(4)          -> send KeyResponse(pk_R), go to S1
       ClientHello(1289)      -> go to S2
       other / bad length     -> Alert 1, close
    PSK configured:
       ClientHello(1289), flag bit 0 set, reserved bits 0,
       binder valid           -> go to S2
       anything else          -> ErrSilentReject (no bytes sent)
S1  read frame (no-PSK relay only)
       ClientHello            -> go to S2
       other                  -> Alert 1, close   (a second KeyRequest included)
S2  no-PSK relay only: reserved flag bits (Alert 1), flag bit 0 set
       (Alert 2), binder not all zero (Alert 1)
    both: key_hint == KeyHint(pk_R) (Alert 3),
    HPKE-decapsulate enc_s (error: Alert 1),
    HPKE-encapsulate to eph_pk_c (error: Alert 1),
    schedule, send ServerHello -> return *Channel
```

A PSK relay checks the binder with one HMAC before any public-key operation,
so non-members cost it no KEM work (section 11.4).

`handleRelayConn` (`cmd/relay/internal/handlers/ws_handler.go`) then raises
the read limit to the configured `max_message_size` and reads record 0:

- AEAD failure on record 0: a broken client or an attack (with a binder, a
  wrong PSK can no longer get this far). Logged at warn through a new sampler
  `authFailLog = &logSampler{interval: rejectLogInterval}` in `logsample.go`
  (separate from `rateLimitLog`, so auth failures do not hide rate-limit
  lines), message `relay: first record failed authentication`; then close.
- `ErrSilentReject`: logged at debug through `authFailLog`
  (`relay: rejected unauthenticated handshake`), then the delayed close of
  section 7.2.
- Record 0 that is not `Register` closes as today. Once RFC010 lands,
  `SessionManager.Create`, `CreateWith` and `Join` failures send RFC010's
  `Refused{reason}` before closing.

The `case frame.GetAuth()` branch and `Hub.Password` are deleted.

### 10.3 Timeouts

Unchanged values, wider scope:

- Relay: `session.handshake_timeout` (default 30 s) covers S0 to the
  `Registered` write, as it covers HPKE, auth and register today.
  Enforcement is unchanged (connection deadline for tcp and tls, timer for ws
  and wss). The silent close delay is capped by the same deadline.
- Client: `WithHandshakeTimeout` (default `DefaultHandshakeTimeout`, 30 s)
  covers connect, TLS and C0-C4. The context passed to `Dial` or `Listen`
  bounds only the handshake (RC-14). There is no callback during the
  handshake: first contact over an unverified channel returns an error and
  the caller retries.

## 11. Security Considerations

### 11.1 Properties

| Attacker | ws / tcp | wss / tls, `tls=skip` or CDN in the middle | wss / tls, verified or `cert=` pinned |
| -------- | -------- | ------------------------------------------ | ------------------------------------- |
| Passive on path, now or with a future QC | Learns nothing beyond sizes, timing, the `KR` magic, the PSK flag and `key_hint` (X-Wing ephemeral in HS). With a PSK it can test PSK guesses offline against the binder (section 11.3). | same | TLS hides the handshake |
| Active on path, client has the key (address or store) | Cannot complete: no `sk_R` -> no `ss_s` -> wrong `finished_r`. Client aborts before sending the token. | same | same (two independent checks) |
| Active on path, first contact, no PSK | Can substitute its own KeyResponse; the client shows that key to the user and connects only if the user accepts it (TOFU limit). | same | TLS authenticates the KeyResponse; accepted without a prompt (a TLS-terminating CDN is trusted for that first contact) |
| Active on path, client has PSK but no key | Client refuses before connecting (`ErrRelayKeyRequired`). | same | same |
| Active prober, relay has PSK | Gets no bytes and a delayed close; cannot fetch the key or learn that a PSK is in use. | same | same |
| Active prober, relay without PSK | Learns the relay key (public anyway) and that it is a kamune relay. | same | same |
| Malicious or compromised relay | Reads the token, sees message sizes and timing (as today and as intended: the relay is the endpoint of this leg). Cannot read peer payloads (RFC007). | same | same |
| `sk_R` stolen later | Recorded sessions stay confidential (`ss_e` is ephemeral). The thief can impersonate the relay to pinned clients until the operator replaces the key. With a PSK, it also needs the PSK. | same | TLS pin still blocks it if the TLS key was not stolen too |
| PSK leaked | Lets the holder use the relay (as today). Does not let it impersonate the relay to clients that have the key. | same | same |
| Attacker alters a share card or address | Can name another host (as today). Cannot replace a stored pin: a different `rk` for a pinned `host:port` fails with `ErrRelayKeyChanged` before any connection. | same | same |

### 11.2 Why each piece is there

- `ss_s` through HPKE to `pk_R`: implicit relay authentication, as Noise NK's
  `es`. `finished_r` turns it into explicit authentication before the client
  sends anything secret (TLS 1.3 server Finished).
- `ss_e` through X-Wing: forward secrecy and PQ confidentiality. `ss_s` is
  classical; it only has to resist forgery at handshake time, so a future
  quantum attacker gains nothing from recorded traffic.
- PSK as the first extract input (NKpsk0, TLS 1.3 early secret): every record
  key depends on it.
- Binder (TLS 1.3 PSK binder): the relay learns PSK membership before any KEM
  work, which gives silent rejection, cheap rejection, and an error that
  separates "wrong access key" (silent close, `ErrHandshakeRejected`) from
  "relay could not prove the key" (`ErrRelayAuthFailed`).
- Key hint, PSK flag and binder in the transcript: an attacker cannot strip
  the flag, swap the key or change the binder without breaking `finished_r`.
- No 0-RTT: sending Register inside ClientHello under `ss_s` only would hand
  the token to anyone who later steals `sk_R` and recorded the flight, and
  could be replayed to register a session.

### 11.3 Dictionary attacks and the PSK format

The binder is visible to a passive observer on ws and tcp (and to a
TLS-terminating CDN), and `finished_r` to any client. Both are HMACs keyed
from the PSK, so anyone who sees one can test PSK guesses offline. This is
acceptable only because the PSK is a generated 256-bit key (section 6.3);
RELAY.md states that dependency. Human passwords would need a PAKE (CPace,
OPAQUE), which is not in the dependency set and is not supported (section
5.1).

### 11.4 Replay and DoS

- A replayed ClientHello with a valid binder makes the relay do one X25519
  decapsulation and one X-Wing encapsulation, less work than today's accept
  (key generation, encapsulation and decapsulation), and the replayer cannot
  derive keys (no `eph_sk_c`). No replay cache is needed; this stays true
  with the binder.
- A PSK relay rejects non-members with one HMAC-SHA512 and no allocation
  beyond the 1289-byte read.
- Pre-auth buffering: the handler sets the read limit to `MaxHandshakeFrame`
  (1289) before `Accept` (ws: `conn.SetReadLimit`; tcp and tls: the length
  prefix is checked before the body is read, through a new
  `Framing.SetReadLimit(n int)`), and raises it to `max_message_size` after
  ServerHello. A pre-auth connection costs at most 1289 bytes of buffer.
- KeyRequest is answered without cryptography. Everything runs behind the
  existing per-address rate limiter and the handshake timeout. TCP and
  WebSocket give no amplification (a 3-way handshake precedes any reply).
- A silently rejected connection holds a goroutine and a socket for 2-8 s;
  the per-address rate limiter bounds how many one source can open.

### 11.5 Key separation with the broker

This section is the contract RFC011 follows.

One X25519 key serves the relay leg and the broker (RFC011). Rules:

1. Outside `relayleg`, the private key is reachable only through two methods:
   HPKE-based use inside `relayleg` itself, and
   `(*PrivateKey).ExtractShared(domain, peer)`, which returns
   `HKDF-Extract(SHA-512, salt = domain || pk_R, ikm = X25519(sk_R, peer))`
   and refuses any `domain` that does not start with `kamune broker v2`
   (`ErrKeyUsage`). There is no accessor for the raw scalar, the
   `*ecdh.PrivateKey`, or a raw DH output.
2. The relay leg feeds the same DH value only into HPKE's
   `LabeledExtract("", "eae_prk", dh)`, that is HKDF-Extract with an empty
   salt and ikm `"HPKE-v1" || suite_id || "eae_prk" || dh`. The broker feeds
   it into HKDF-Extract with salt `"kamune broker v2 dh " || pk_R` and ikm
   `dh`. The salts differ, so modelling HKDF-Extract as a random oracle makes
   the two outputs independent: submitting a victim's relay-leg `enc_s` to
   the broker as `E_C_PUB` yields a broker PRK unrelated to the victim's
   `ss_s`.
3. The key never signs.
4. **Classical only.** `pk_R` gives classical authentication and, alone,
   classical confidentiality. The relay leg is hybrid because of `ss_e`.
   RFC011's broker uses X25519 only, so anything sealed to `pk_R` there (the
   `RID` and the matched addresses; the broker never carries the token, see
   RFC010 and RFC011) is open to harvest-now-decrypt-later. RFC010 and RFC011
   state this. If they need PQ confidentiality, the client sends an X-Wing key
   and the broker encapsulates to it, as relayleg does.

RFC011's broker key derivation `PRK = HKDF-Extract(SHA-512, salt = "kamune
broker v2 dh " || S_pub, ikm = DH)` is exactly
`ExtractShared("kamune broker v2 dh ", E_C_PUB)`; the domain (with its
trailing space) satisfies the prefix rule above. The broker's public key is
the relay key, and RFC010's `relay_id` (`rendezvous.NewServiceID`) is derived
from it.

### 11.6 Alternatives not taken

- **A PSK-free split tag (`finished_k`) instead of the binder**, with the PSK
  moved to the last extract. The binder solves the same problem and more: the
  relay rejects non-members with one HMAC before any KEM work, which enables
  silent PSK relays, and the client still gets a key verdict that does not
  depend on the PSK (`finished_r` is reached only after a valid binder, so its
  failure means a wrong key or a MITM). `finished_k` would leave PSK relays
  doing two KEM operations for every prober and answering every prober with
  a ServerHello. Both designs expose the same offline PSK test (to observers
  of the binder or to any client that gets `finished_r`), which the generated
  256-bit PSK makes harmless.
- **A separate daemon `trust_relay_key` command** instead of returning the
  key in the error. The key has to reach the app for it to be shown to a
  human, and an app that wants silent TOFU can call a trust command as easily
  as it can re-send with `rk`; the command adds a second path without
  stopping automation. What reduces habituation is fewer prompts, and that is
  adopted: verified TLS needs none. DAEMON.md states that the key must be
  shown to a human, and a conflicting key still needs the explicit
  `replace_relay_key: true`.
- **A two-key `relay-static-key.pem` now.** An overlap lets old-key clients
  keep working, but nothing tells them the new key; they still hit the same
  `RelayKeyChangedError` once the operator hands out new addresses, and for a
  compromise the old key must go at once anyway, which is the documented
  procedure. Rotation done properly needs an authenticated "next key"
  announcement inside the channel, a protocol feature of its own. The wire is
  ready for it (`key_hint`), so it can come later without a version change.
- **Dropping `key_hint`, alert 3 and the version check.** The hint is 4
  bytes and one comparison; removing it would make the later rotation a wire
  break after v1.0. Alert 3 maps to `ErrRelayKeyNotHeld`, which is never
  treated as a key change, so a forged alert gains an attacker nothing beyond
  the denial of service it already has. The version check is not a special
  case: the client checks the header of every relay frame, alerts included.
- **A `server.silent` option.** Silence is adopted as behaviour, not as a
  knob: a PSK relay is private by definition, so it is always silent, and a
  public relay's key is public, so silence would only cost its users the
  first-contact path.
- **Binding the relay-leg transcript to the TLS exporter.** It adds nothing
  to relay authentication (the relay key already does it) and breaks behind a
  CDN.

## 12. Composition with TLS

The relay leg is authenticated by the relay key (or the PSK) whatever TLS
does. TLS remains for traffic shape (looking like HTTPS), CDN compatibility,
first contact without a prompt, and as a second, independent check.

| Address | TLS config used | Counts as verified TLS (section 13.3) |
| ------- | --------------- | ------------------------------------- |
| `wss://h` / `tls://h:p` | System roots and host name, `MinVersion: tls.VersionTLS13`. | yes |
| `...?cert=<sha256 hex>` | `relayconn.PinnedTLSConfig(pin)`: only that certificate, chain and name checks off; `MinVersion` raised from 1.2 to 1.3 in `pin.go`. | yes |
| `...?tls=skip` | `InsecureSkipVerify: true`, TLS 1.3 minimum. | no |
| `ws://`, `tcp://` | No TLS. `cert` and `tls` parameters are parse errors. | no |
| any, with `WithTLSConfig(c)` | `c`, cloned, `MinVersion` raised to 1.3 if lower. `WithTLSConfig` together with `cert` or `tls=skip` in the address returns `ErrTLSOptions` before connecting. | iff `!c.InsecureSkipVerify` |

The relay server already requires TLS 1.3 (`newServerTLSConfig`), so the 1.3
client minimum breaks nothing. The client parsers that set TLS 1.2 today
(tui's `relayTarget.tlsConfig` in `relayaddr.go`, bus's
`relayAddress.tlsConfig`) are deleted with the rest of those parsers.

`cert` and `tls=skip` together are a parse error. `?insecure=true` no longer
exists; the parser rejects unknown parameters, so an old share card fails
loudly. `tls=skip` does not require `rk`: an unverified TLS channel never
yields a key without the user (section 13.3), so an imported `tls=skip`
cannot silently disable relay authentication.

A TLS verification failure (for example the shipped self-signed certificate
reached as `wss://host:8891`) returns an error wrapping `ErrTLSVerify` whose
text names both ways out: "add ?cert=<sha256> or ?rk=rk1-... from the relay's
startup log". For a self-signed relay the recommended address is the logged
line `tls://host:8890?rk=rk1-...&cert=<fp>`.

## 13. Relay Address and First Contact

### 13.1 Address grammar

```
address = [scheme "://"] host [":" port] [path] ["?" param *("&" param)]
scheme  = "wss" / "tls" / "ws" / "tcp"        ; case-insensitive, default "wss"
path    = "/" *( unreserved / "/" )           ; ws and wss only
param   = "rk=" relay-key / "cert=" sha256-hex / "tls=skip"
```

- `host` is a DNS name, an IPv4 literal or a bracketed IPv6 literal, and is
  canonicalized:
  - DNS names: ASCII only (an IDN must be given as its `xn--` A-label;
    non-ASCII is `ErrInvalidAddress`, which avoids a new dependency on
    `golang.org/x/net/idna`), lowercased, one trailing dot stripped, labels
    checked as LDH (letters, digits, hyphen; 1-63 chars; total at most 253);
  - IP literals: `netip.ParseAddr`, then `Unmap()`, then `String()`, so
    `[::ffff:192.0.2.1]` becomes `192.0.2.1` and IPv6 is compressed; zones
    (`%eth0`) are rejected.
- Default port 443 for wss and 80 for ws; tls and tcp need an explicit port.
- `path` (ws, wss): the WebSocket request path. Empty or `/` means `/ws`, the
  relay's route. Any other path is used verbatim, so a relay behind a
  path-routing proxy is `wss://example.com/kamune/ws`. A path on tcp or tls
  is an error.
- No user info, no fragment. Each parameter at most once; unknown
  parameters, empty values and duplicates are errors (`ErrInvalidAddress`).
- `rk` value: `relayleg.ParsePublicKey`. `cert` value:
  `relayconn.ParseCertFingerprint` (64 hex digits, colons allowed).
- `Address.String()` prints the canonical form:
  `scheme://host:port[path]?rk=...&cert=...&tls=skip` with only the present
  parameters, in that order, lowercase scheme, path omitted when `/ws`, `rk`
  in `rk1-` form, `cert` as 64 lowercase hex digits.
  `ParseAddress(a.String())` round-trips, and `String()` of any accepted
  input is a fixed point.
- `Address.Display()` is `String()` without `cert` and without `rk` (short,
  for error messages).
- `Address.StoreName()`: `host:port` from the canonical form, plus the path
  when it is not `/ws`. Path-routed relays behind one host are separate
  relays with separate keys. The ws and wss (or tcp and tls) ports of one
  relay are pinned separately; with verified TLS the second port is pinned
  without a prompt.

### 13.2 Key resolution and the key store

The key store is the authority for pins.

`relayconn` resolves the key before it opens any connection:

```
stored, ok, err := store.RelayKey(a.StoreName())
err != nil                                  -> fail, return err (fail closed)
a.RelayKey set, ok, *a.RelayKey != stored:
    WithReplaceStoredKey() not given        -> *RelayKeyChangedError{Address,
                                               Stored, Presented}; no connection
    given                                   -> use *a.RelayKey; write after success
a.RelayKey set, ok, equal                   -> use it
a.RelayKey set, !ok                         -> use it; write after success (seed)
a.RelayKey nil, ok                          -> use stored
a.RelayKey nil, !ok, PSK set                -> ErrRelayKeyRequired; no connection
a.RelayKey nil, !ok, no PSK                 -> first contact (13.3)
```

- "After success" means after `Registered` passed `checkRegisteredToken`
  (C4). A relay that authenticates but then fails registration, sends a
  mismatched token or `Refused`, never changes the store.
- `WithReplaceStoredKey()` without an `rk` in the address returns
  `ErrInvalidOption` before connecting. Clients set it only after a user
  confirmed a dialog that showed both keys; share-card imports and background
  reconnects never set it.
- A stored or address key that fails the handshake returns
  `ErrRelayAuthFailed` (bad `finished_r`) or `ErrRelayKeyNotHeld` (alert 3).
  Neither is wrapped into `ErrRelayKeyChanged`, and neither is ever followed
  by a key fetch. `ErrRelayKeyChanged` is returned only when both keys are
  known and differ, which only the caller's own input can cause.
- Clients persist addresses **without** `rk`
  (`a.WithoutRelayKey().String()`); the store holds the pin. So
  `ForgetRelayKey` removes the only copy of the pin, and a saved address
  cannot fight the store after a key replacement.
- Share output takes `rk` from `RelayConn.RelayKey()` or
  `ListenResult.RelayKey` (the authenticated key), never from address text.

### 13.3 First contact

No key in the address or the store, and no PSK. `relayconn` connects, runs C0
and then:

| Channel the KeyResponse came over | Result |
| --------------------------------- | ------ |
| Verified TLS (section 12 table) | The key is used on the same connection (C1-C4) and stored after success; `FirstContact()` reports true. RELAY.md states that behind a TLS-terminating CDN this trusts the CDN for the first contact only. |
| ws, tcp, `tls=skip`, `WithTLSConfig` with `InsecureSkipVerify` | The connection is closed and `*UnknownRelayKeyError{Address, Key}` is returned (`errors.Is(err, ErrRelayKeyUnknown)`). Nothing secret was sent. The caller shows `Key.Display()` to a human and retries with `a.WithRelayKey(key)`, which seeds the store after success. |

There is no policy option: the rule depends only on how the key was
obtained. The same retry is the trust step in all three clients.

### 13.4 How keys reach users

- Operators publish the `relay address` lines the relay logs, which carry
  `rk` (and `cert` for a self-signed certificate). For a PSK relay the
  operator hands out the access key with such an address.
- Share cards carry the canonical relay address in one parameter (section
  15.1). A forged card can seed a pin only for a `host:port` the user has
  never pinned, which equals naming an attacker's host; it cannot replace an
  existing pin.

## 14. Go API

### 14.1 New package `pkg/relayconn/relayleg`

```go
package relayleg

const (
	Version           = 2
	MaxHandshakeFrame = 1289
)

type ReadWriter interface { /* moved from exchange */ }
type FrameLimiter interface { MaxFrameSize() int } // moved from exchange

type PublicKey [32]byte
func ParsePublicKey(s string) (PublicKey, error)
func (k PublicKey) String() string                 // "rk1-..."
func (k PublicKey) Display() string                // "rk1-abcd-efgh-..."
func (k PublicKey) ECDH() (*ecdh.PublicKey, error) // for RFC011's client side
func KeyHint(k PublicKey) [4]byte

type PrivateKey struct{ /* unexported ecdh + hpke keys */ }
func GenerateKey() (*PrivateKey, error)
func (k *PrivateKey) PublicKey() PublicKey
// ExtractShared: section 11.5. domain must start with "kamune broker v2".
func (k *PrivateKey) ExtractShared(domain string, peer []byte) ([]byte, error)
func CreatePrivateKeyFile(path string) (*PrivateKey, error) // O_EXCL, 0600
func LoadPrivateKeyFile(path string) (*PrivateKey, error)

type PSK [32]byte
func GeneratePSK() (PSK, error)
func ParsePSK(s string) (PSK, error)
func (p PSK) String() string                       // "psk1-..."

type ClientConfig struct {
	RelayKey PublicKey
	PSK      *PSK // nil: no PSK
}
func FetchKey(rw ReadWriter) (PublicKey, error)                  // C0
func Initiate(rw ReadWriter, cfg ClientConfig) (*Channel, error) // C1-C3

type ServerConfig struct {
	Key *PrivateKey
	PSK *PSK
}
func Accept(rw ReadWriter, cfg ServerConfig) (*Channel, error)   // S0-S2
func SilentDelay() time.Duration // uniform in [2s, 8s]

type Channel struct{ /* ... */ }
func (c *Channel) ReadBytes() ([]byte, error)
func (c *Channel) WriteBytes(b []byte) error
func (c *Channel) WriteBytesWithin(b []byte, d time.Duration) error
func (c *Channel) MaxFrameSize() int
func (c *Channel) Close() error
func (c *Channel) SetDeadline(t time.Time) error
func (c *Channel) SetWriteDeadline(t time.Time) error

var (
	ErrInvalidRelayKey, ErrInvalidPSK, ErrKeyUsage,
	ErrBadMessage, ErrUnsupportedVersion,
	ErrRelayAuthFailed,   // finished_r mismatch
	ErrPSKUnexpected,     // alert 2
	ErrRelayKeyNotHeld,   // alert 3
	ErrHandshakeRejected, // closed before ServerHello without an alert
	ErrSilentReject,      // relay side: no reply, delayed close
	ErrRecordAuth,
	ErrFrameTooLarge, ErrChannelBroken error // moved from exchange
)
```

The package does no I/O beyond `rw`, except the two key-file helpers, keeps
no globals, and takes randomness from `crypto/rand` (through `crypto/hpke`
and `ecdh`).

`relayleg.ErrHandshakeRejected` (relay leg closed before ServerHello) and
RFC007's `kamune.ErrHandshakeRejected` (the peer rejected the handshake) are
different values; clients match them with the package-qualified name and map
them to different codes.

### 14.2 `pkg/relayconn`

Removed: `DialRelay`, `DialRelayWSS`, `DialRelayTCP`, `DialRelayTLS`,
`ListenRelay`, `ListenRelayWSS`, `ListenRelayTCP`, `ListenRelayTLS`,
`WithPassword`, `auth.go`. `pin.go` stays (TLS 1.3 minimum).

```go
type Address struct {
	Scheme        string // "wss", "tls", "ws", "tcp"
	Host          string // canonical host:port
	Path          string // ws/wss only; "/ws" by default
	RelayKey      *relayleg.PublicKey
	CertPin       []byte // SHA-256, nil if none
	SkipTLSVerify bool
}
func ParseAddress(s string) (Address, error)
func (a Address) String() string
func (a Address) Display() string
func (a Address) StoreName() string
func (a Address) WithRelayKey(k relayleg.PublicKey) Address
func (a Address) WithoutRelayKey() Address

// The token comes from an option (RFC010's shape; section 14.5).
func Dial(ctx context.Context, a Address, opts ...Option) (*RelayConn, error)
func Listen(ctx context.Context, a Address, opts ...Option) (*ListenResult, error)

func WithPSK(p relayleg.PSK) Option
func WithToken(t rendezvous.Token) Option          // semantics: RFC010
func WithTokenFunc(f rendezvous.TokenFunc) Option  // called at C3a
func WithHandshakeTimeout(d time.Duration) Option  // unchanged
func WithKeyStore(s KeyStore) Option               // default: NewMemoryKeyStore()
func WithReplaceStoredKey() Option
func WithTLSConfig(c *tls.Config) Option           // see section 12

// KeyStore implementations are safe for concurrent use.
type KeyStore interface {
	RelayKey(name string) (relayleg.PublicKey, bool, error)
	SetRelayKey(name string, k relayleg.PublicKey) error
	DeleteRelayKey(name string) error // no error if absent
}
func NewMemoryKeyStore() KeyStore
// SettingsStore is satisfied by *storage.Storage.
type SettingsStore interface {
	GetSettings(app, key string) (string, error)
	SetSettings(app, key, value string) error
	DeleteSettings(app, key string) error
}
// SettingsKeyStore keeps PublicKey.String() under app "kamune-relay-keys",
// key StoreName. A stored value that does not parse is a read error.
func SettingsKeyStore(s SettingsStore) KeyStore
func ForgetRelayKey(s KeyStore, a Address) error // DeleteRelayKey(a.StoreName())

var (
	ErrInvalidAddress    error
	ErrInvalidOption     error
	ErrTLSOptions        error // WithTLSConfig with cert= or tls=skip
	ErrTLSVerify         error // wraps the x509 error, with the hint text
	ErrRelayKeyUnknown   error // first contact over an unverified channel
	ErrRelayKeyChanged   error // address rk differs from the stored pin
	ErrRelayKeyRequired  error // PSK given, no key known
)
type UnknownRelayKeyError struct {
	Address Address
	Key     relayleg.PublicKey // as presented, unauthenticated
}
type RelayKeyChangedError struct {
	Address   Address
	Stored    relayleg.PublicKey
	Presented relayleg.PublicKey // from the address
}

type ListenResult struct {
	Listener     *RelayListener
	Token        rendezvous.Token
	TTL          time.Duration
	SessionTTL   time.Duration
	RelayKey     relayleg.PublicKey
	FirstContact bool
}
func (c *RelayConn) RelayKey() relayleg.PublicKey
func (c *RelayConn) FirstContact() bool
```

The token types come from RFC010's `pkg/rendezvous`, which RFC006 orders
before `Dial` and `Listen` land. If that package were not there yet, the same
options would ship typed with `[]byte` and a
`TokenFunc func(relayKey relayleg.PublicKey) ([]byte, error)`, and RFC010
would retype them; `ListenResult.Token` likewise.

Key store contract:

- A `RelayKey` read error fails the call before connecting (fail closed).
- A `SetRelayKey` error after a successful handshake is logged with
  `slog.Warn` (`relayconn: could not store relay key`, attributes `relay`
  and `error`) and the call succeeds: the connection is authenticated, and
  the next connection without a pin goes through first contact again, which
  is safe.
- `storage.Storage` has `GetSettings` and `SetSettings` (where an empty value
  deletes the key) but no delete method. It gains
  `DeleteSettings(app, key string) error`, a delete in the settings
  namespace (root module, `kamune:` commit).
- Bus and daemon incognito modes use `NewMemoryKeyStore()`.

`Dial` and `Listen` run the option checks that need no network first:
`ErrInvalidOption`, `ErrTLSOptions`, `RelayKeyChangedError`,
`ErrRelayKeyRequired`, and RFC010's `ErrNoToken` and `ErrTokenOptions`.

`RelayConn`, `RelayListener` and `newRelayConn` take `*relayleg.Channel`
instead of `*exchange.Channel`. `checkRegisteredToken` and the
`context.WithoutCancel` handling stay as they are. The package doc in
`relayconn.go` ("Protocol design") is rewritten.

Error wrapping: every `Dial` and `Listen` error is
`fmt.Errorf("%s: %w", a.Display(), err)`, so UIs can show it and match
sentinels with `errors.Is` and `errors.As`.

`relayconn.IsRelayTrustError(err) bool` reports whether `err` is one of
`ErrRelayKeyUnknown`, `ErrRelayKeyChanged`, `ErrRelayKeyRequired`,
`ErrRelayAuthFailed`, `ErrRelayKeyNotHeld`, `ErrPSKUnexpected`,
`ErrHandshakeRejected` or `ErrTLSVerify`. Multi-token loops stop on it
(section 15.1).

### 14.3 New test helper `pkg/relayconn/relaytest`

The helper lives in the root module.

Sub-modules cannot import `cmd/relay/internal`, and today's `relayconn` tests
hand-roll fake relays on `exchange.Accept`. One shared helper, in the style
of `net/http/httptest`:

```go
package relaytest

type Options struct {
	PSK        *relayleg.PSK
	Transports []string // "ws", "wss", "tcp", "tls"; default all four
	SelfSigned bool     // wss/tls serve a generated certificate
}
func Start(t testing.TB, o Options) *Server // stops on t.Cleanup
func (s *Server) Addr(scheme string) relayconn.Address      // rk and cert set
func (s *Server) AddrNoKey(scheme string) relayconn.Address // cert set, no rk
func (s *Server) Key() relayleg.PublicKey
func (s *Server) KeyRequests() int // KeyRequests seen
func (s *Server) Connections() int
```

It runs `relayleg.Accept` and a minimal create/join pairing with the same
record-0 rules as the relay. The relayconn fakes, the daemon test, and the
bus and tui tests use it. The real-relay end-to-end test stays in
`cmd/relay/internal/handlers`.

### 14.4 `cmd/relay`

- `internal/config`: `Server.Password` becomes
  ``Server.PSK string `toml:"psk"` ``; `Validate` parses it;
  `func (s Server) ParsedPSK() *relayleg.PSK`.
- `run/relaykey.go` (new): `loadOrCreateRelayKey(dataDir string)
  (*relayleg.PrivateKey, path string, err error)`, using
  `relayleg.LoadPrivateKeyFile` and `CreatePrivateKeyFile` and the
  `DefaultDataDir` error text of section 6.2.
- `run.Run` order: config, log level, **relay key**,
  `services.New(ctx, cfg, key)`, certificate store, broker, listeners. The
  key and address lines are logged after the certificate store (the address
  lines need the certificate fingerprint).
- `main.go`: `-gen-psk` (print `relayleg.GeneratePSK()` and exit) and
  `-print-key` (load config, resolve the key path, **read only**: fail with
  the resolved path if the file is missing, otherwise print `rk1-...` and the
  address lines; never creates a key).
- `internal/services`: `New(ctx, cfg, key *relayleg.PrivateKey)`; `Hub`
  stores `relayleg.ServerConfig` (`Hub.Leg()`) and drops `password` and
  `Password()`; `func (s *Service) StaticKey() *relayleg.PrivateKey` for
  RFC011. `SessionManager`, `Hub.RegisterListener`, `RegisterListenerWith`,
  `RegisterDialer`, `ReadPump`, `handleMessage`, `handlePing`, `Leave` and
  `closeChannels` switch `*exchange.Channel` to `*relayleg.Channel`
  (mechanical). The startup log line "psk auth on" names `server.psk`.
- Call sites of `services.New` and `NewHub` that change (tests pass
  `relayleg.GenerateKey()`): `run/run.go`; `run/run_test.go` (three calls);
  `internal/handlers/ws_handler_test.go`;
  `internal/handlers/frame_size_test.go`; `internal/handlers/relay_test.go`
  (`NewHub`); `internal/services/hub_test.go` (`NewHub`);
  `internal/services/services.go` (`NewHub` inside `New`).
- `internal/handlers`: `wsAdapter` and `rawTCPAdapter` gain
  `SetReadLimit(n int)`; `handleRelayConn` sets `MaxHandshakeFrame`, runs
  `relayleg.Accept(rw, hub.Leg())`, handles `ErrSilentReject` (section 7.2),
  raises the limit, and handles record 0 as in section 10.2. `logsample.go`
  gains `authFailLog`.
- `pkg/relayconn/pb/relay.proto`: drop `Auth`, regenerate
  (`make gen-proto`).
- Sample config `assets/config.toml`: `psk = ""` with a comment pointing at
  `-gen-psk` and saying a PSK relay needs `rk` in client addresses; the
  `data_dir` comment mentions `relay-static-key.pem`. The Dockerfile comment
  too.

### 14.5 Interfaces with other RFCs

- **RFC011 (broker).** This RFC provides, and RFC011 uses:
  - server: `services.Service.StaticKey() *relayleg.PrivateKey`; the broker
    computes its PRK with `key.ExtractShared("kamune broker v2 dh ",
    E_C_PUB)` (section 11.5). There is no separate `[broker] key_file`: a
    broker in its own process is a relay with only `[broker]` enabled and its
    own `data_dir`.
  - client: `relayleg.ParsePublicKey`, `PublicKey.ECDH()`,
    `PublicKey.String()` and `Display()`, `KeyHint`, and
    `LoadPrivateKeyFile` for test vectors. Broker addresses carry the key as
    `udp://host:port?rk=rk1-...`; there is no `broker_pin` field.
  - This RFC does not edit `broker.New`, `run.newBroker` or the broker
    address syntax; those stay RFC011's. Until RFC011 lands, `run.newBroker`
    is untouched and compiles.
  - RFC011 must honour the section 11.5 contract, including the
    classical-only note for anything it seals to `pk_R`.
- **RFC010 (tokens).** This RFC adopts RFC010's shape: no positional token;
  `WithToken` and `WithTokenFunc` options; the `TokenFunc` runs at C3a, after
  `finished_r` verifies and before record 0. relayconn computes
  `rendezvous.NewServiceID(relayKey)` from the authenticated key before it
  calls the hook. `ListenResult` gets no derived-token field. A failed
  handshake, `ErrRelayKeyUnknown`, `ErrRelayKeyChanged` and
  `ErrRelayKeyRequired` all return before the `TokenFunc` runs. The relay
  handler sends RFC010's `Refused` where RFC010 lists it. Both RFCs edit
  `relay.proto` (this one deletes field 6, RFC010 adds field 7): each commit
  regenerates `relay.pb.go` with `make gen-proto`; whichever lands second
  rebases and regenerates, never merging the generated file by hand.
- **RFC007 (handshake).** `RelayConn` still implements `kamune.Conn`; the
  per-frame overhead on the relay leg is unchanged (16-byte tag plus the
  `pb.Frame` wrapping), so `transportReserve` (SPEC §9.4, §13) holds. The
  peer handshake runs in `Message` frames and is independent of this leg.
  `pkg/exchange` cleanup as in section 9. The RELAY.md text on what a relay
  learns about peers comes from RFC007 and is used verbatim.
- **RFC008 (UDP path).** None.

## 15. Client Changes

### 15.1 Common

All three clients drop their own address parsers (`parseRelayAddr` and
`relayAddress` in bus; `parseRelayAddr`, `parseInsecureFlag` and
`parseRelayPin` in daemon; `relayTarget` and `relayaddr.go` in tui) and use
`relayconn.ParseAddress`, `Dial`, `Listen`, `WithPSK` and
`WithKeyStore(relayconn.SettingsKeyStore(store))` (or `NewMemoryKeyStore()`
before storage is open and in incognito mode). They persist
`a.WithoutRelayKey().String()`. The `insecureSkipVerify bool` parameters
disappear from every helper, and the per-client certificate pin options of
`main` (bus `?pin=`, daemon `relay_pin`, tui fingerprint input) are replaced
by `cert=` in the address. Error hints that guess "wrong password?" from a
close frame (daemon `wrapRelayError`) are replaced by `errors.Is` and
`errors.As` checks.

User-facing outcomes (the same in all clients; text abbreviated):

| Error | Meaning shown | Action offered |
| ----- | ------------- | -------------- |
| `UnknownRelayKeyError` | First connection to this relay; key not verified by TLS. Shows `Key.Display()` and asks to compare it with the operator's. | Trust: retry with `a.WithRelayKey(key)`. |
| `RelayKeyChangedError` | You supplied a key that differs from the one stored for this relay. Shows both. | Replace (retry with `WithReplaceStoredKey()`), or cancel. |
| `ErrRelayAuthFailed` | The relay could not prove it holds the pinned key: it was intercepted, or the operator replaced the key. Get the new address from the operator before changing anything. | None automatic; "Forget relay key" stays in settings. |
| `ErrRelayKeyNotHeld` | The relay, or someone between you and it, rejected the pinned key. | As above. |
| `ErrHandshakeRejected` | Relay closed the handshake: wrong or missing access key, or not a kamune relay. | Check the access key. |
| `ErrRelayKeyRequired` | An access key needs the relay key; ask the operator for the full address. | None |
| `ErrPSKUnexpected` | This relay has no access key; remove it. | None |
| `ErrTLSVerify` | Certificate not trusted; add `cert=` or `rk=` from the operator. | None |

Background paths (relay reconnects, relay resume listeners, multi-token
dials) never prompt and never pass `WithReplaceStoredKey()`. Loops over
several tokens (`dialRelayFuncMultiToken` in bus and daemon, and the
reconnect paths that call it) stop at the first error for which
`relayconn.IsRelayTrustError` is true and return it, so one relay-key or PSK
problem costs one rate-limit unit and raises one event, not one per token.

Share URLs: `relay://?addr=<URL-escaped Address.String()>&token=...&psk=1`.
`addr` carries scheme, host, port, path, `rk` (from the authenticated key),
`cert` and `tls=skip`; `psk=1` says the relay needs an access key (the key
itself is never in a share URL). The token fields belong to RFC010 (`token`
appears only for random tokens). Import parses `addr` with
`relayconn.ParseAddress` in Go; `scheme`, `insecure` and `password` are no
longer read. An imported `rk` follows section 13.2: it seeds the store only
for an unpinned relay and otherwise yields `RelayKeyChangedError`.

### 15.2 bus

Files: `cmd/bus/relay.go`, `network.go`, `app.go` and the frontend.

Go:

- `listenRelay`, `listenRelayTracked`, `dialRelayFunc`,
  `dialRelayFuncMultiToken` and `dialRelayFuncWithSessionTTL` take
  `relayconn.Address` and `*relayleg.PSK` and call `Listen` or `Dial`.
  `parseRelayAddr`, `relayAddress`, its `tlsConfig` and `ErrRelayPinScheme`
  are deleted.
- The Wails entry points `StartServer` and `ConnectToServer` take one struct
  in place of their relay address and password arguments (and the
  `insecure` and `pin` the frontend puts in the address today); the other
  arguments, such as `brokerAddr`, stay:

  ```go
  type RelayOptions struct {
  	Address          string `json:"address"`          // section 13.1
  	AccessKey        string `json:"accessKey"`        // "psk1-..." or ""
  	TrustRelayKey    string `json:"trustRelayKey"`    // "rk1-..." the user accepted
  	ReplaceStoredKey bool   `json:"replaceStoredKey"`
  }
  ```

  `TrustRelayKey` is applied with `WithRelayKey`; it is how the dialog's
  "Trust" retries.
- `ConnectToServer` keeps returning `ConnectResult`, which gains
  `RelayKey string` and `StoredRelayKey string`. `StartServer` returns a new
  `StartServerResult{ErrorCode, RelayKey, StoredRelayKey}` that also carries
  the values it returns today. Error codes as the daemon's (section 15.3).
  No pending state and no separate trust method: the frontend calls the same
  method again.
- `ForgetRelayKey(address string) error` and a settings entry.
- `ParseShareURL(url string) (ShareTarget, error)` parses share URLs in Go
  (`ShareTarget{Address, Token, NeedsAccessKey}`); `GetShareInfo` builds the
  card in the section 15.1 form, with the relay key from the authenticated
  connection.
- The reconnect path (the reconnect function `ConnectToServer` builds, run by
  `reconnectSession`) and the relay resume listeners (`awaitRelayResume`) use
  the stored address (no `rk`; the store has the pin) and stop with the event
  `relay-trust-error {address, code}`.

Frontend (`cmd/bus/frontend/src`):

- `App.svelte` connect and start-server forms: stop assembling scheme, host,
  `pin=` and `insecure=true` into an address; send one address string. The
  password inputs become "Relay access key (psk1-...)"; the "Skip TLS
  verification" checkbox and the pin field are removed (an advanced user
  types `?tls=skip` or `?cert=` in the address).
- `lib/relayaddr.ts` (`relayAddress`, `insecureWarning`, `pinPlaceholder`)
  and `lib/importurl.ts` (`importedRelayScheme`, `insecureIgnored`) lose
  their callers: Go parses addresses and share URLs.
- `lib/ImportDialog.svelte` and the clipboard import in `App.svelte` import
  through `ParseShareURL`; default scheme `wss`; no `insecure`.
- `lib/ShareDialog.svelte`: the password row (in the dialog and the drawn
  card) becomes "needs access key"; the relay key is shown with `Display()`
  grouping.
- New `lib/RelayKeyDialog.svelte`: shows the address and the key (or both
  keys for a change), "Trust" or "Replace", and "Cancel".
- `lib/P2PFallbackDialog.svelte`: rewritten to the `RelayOptions` call with
  an address field and an access-key field (BUS-29).
- `lib/go.ts`, `lib/models.ts`: regenerated Wails bindings.

### 15.3 daemon

Files: `cmd/daemon/relay.go`, `param.go`, `network.go`, `daemon.go`, the
JSON schemas and `docs/DAEMON.md`.

- `StartServerParams.Password` and `DialParams.Password` become
  ``RelayPSK string `json:"relay_psk,omitempty"` `` (`psk1-...`), plus
  ``ReplaceRelayKey bool `json:"replace_relay_key,omitempty"` ``.
  `RelayPin` (`relay_pin`), `parseRelayPin`, `checkRelayPin` and
  `relayTLSConfig` are removed: a certificate pin is `cert=` in `relay_addr`.
- `relay_addr` accepts the section 13.1 grammar; `?insecure=` is rejected.
  `relayAddrWarning` and `warnRelayAddr` are removed: their claim (an on-path
  attacker on ws or tcp reads the password and the tokens) no longer holds.
- The error event (`emitError` in `daemon.go` already sends `code`) gains
  `relay_key` and `stored_relay_key`. Codes: `relay_key_unknown` (with
  `relay_key`), `relay_key_changed` (both keys), `relay_key_required`,
  `relay_auth_failed`, `relay_key_not_held`, `relay_handshake_rejected`,
  `relay_psk_unexpected`, `relay_tls_verify`. The app shows the key to a
  human and re-sends the command with `rk` in `relay_addr` (and
  `replace_relay_key: true` for a change). DAEMON.md says the key must be
  shown to a human and never accepted automatically.
- New command `forget_relay_key {relay_addr}`.
- `relayShareInfo` gains `relay_addr` (canonical, with `rk` from the
  authenticated key) and `psk bool` (renamed from `password bool`); its `pin`
  field goes, as `relay_addr` carries `cert`.
- Every function that opens a relay connection gets the same
  error-to-code mapping: `startServer` (behind `start_server` and
  `restart_server`), `dial`, `makeReconnectFn` (multi-token reconnect),
  `addRelayToken` (behind `generate_relay_token`, `get_share_info` and the
  relay resume listeners of `awaitRelayResume`).
- Schema files: `commands/start_server.schema.json` and
  `commands/dial.schema.json` (`password` becomes `relay_psk`, `relay_pin`
  removed, `replace_relay_key` added, `relay_addr` description),
  `events/error.schema.json` (`relay_key`, `stored_relay_key`, the codes),
  new `commands/forget_relay_key.schema.json`,
  `commands/get_share_info.schema.json` output, and
  `commands/restart_server.schema.json` and
  `commands/generate_relay_token.schema.json` where they carry relay fields.

### 15.4 tui

Files: `cmd/tui/relayaddr.go`, `welcome.go`, `relayclient.go` and
`relayserver.go`.

- `relayTarget` and `relayaddr.go` are replaced by `relayconn.Address`.
- The "Relay certificate SHA-256 fingerprint" input is replaced by "Relay key
  (rk1-..., empty to fetch)". A certificate pin is still possible with
  `?cert=` in the address field. The password input is relabelled "Relay
  access key".
- On `UnknownRelayKeyError` a confirm screen shows the address and
  `Key.Display()`; `y` retries with the key, anything else returns to the
  form. On `RelayKeyChangedError` the same screen shows both keys; `y`
  retries with `WithReplaceStoredKey()`.
- Key store: `SettingsKeyStore(storage)` once storage is open,
  `NewMemoryKeyStore()` before.

## 16. Test Plan

All tests use `a := require.New(t)`, real implementations, and tables where
there are several cases. File-mode assertions skip on Windows.

### 16.1 `relayleg` unit tests

1. Round trip over `net.Pipe` framed connections: with and without PSK; with
   and without `FetchKey`; 1,000 records each way; `MaxFrameSize` honoured.
2. Known-answer vectors on the pure `schedule` function: fixed hex inputs
   (PSK or none, relay key, ClientHello and ServerHello bytes, `ss_s`,
   `ss_e`) -> `binder`, `finished_r`, TH3 and the four record keys, compared
   with `testdata/relayleg_v2.json` (`-update` regenerates). No dependence
   on how `crypto/hpke` consumes randomness. A separate seeded round trip
   (`cryptotest.SetGlobalRandom`) checks determinism within one run only.
3. Parsing: `ParsePublicKey` and `ParsePSK` tables (valid, grouped with
   dashes, upper case, wrong prefix, 51 and 53 chars, non-base32, empty,
   non-zero unused bits in the last character, all-zero key, all-zero PSK);
   `String()` and `Display()` round trips; `String(Parse(s))` is canonical.
4. PEM files: create and load round trip; `CreatePrivateKeyFile` on an
   existing file fails; wrong type, second block, trailing data, 31- and
   33-byte bodies rejected.
5. Key usage: `ExtractShared` with a domain not starting with
   `kamune broker v2` -> `ErrKeyUsage`; a relayleg ClientHello's `enc_s`
   passed to `ExtractShared("kamune broker v2 dh ", enc_s)` gives a value
   unrelated to the relay side's `ss_s` and HPKE shared secret; a reflection
   test asserts that the exported methods of `*PrivateKey` are exactly
   `PublicKey` and `ExtractShared`, so a raw accessor cannot be added
   unnoticed.

Negative handshake tests (each asserts the error sentinel and that the client
wrote no record):

6. Wrong relay key (client pins B, relay holds A, hints forced equal by a
   test hook) -> `ErrRelayAuthFailed`.
7. Hint mismatch -> alert 3 -> `ErrRelayKeyNotHeld`.
8. PSK cases: client PSK, relay none -> `ErrPSKUnexpected`; relay PSK, client
   none -> relay returns `ErrSilentReject` and wrote zero bytes, client gets
   `ErrHandshakeRejected`; both PSK but different -> same as the previous
   case, never `ErrRelayAuthFailed`; right key, wrong PSK on a relay with a
   stored pin -> `ErrHandshakeRejected` and the store unchanged (test 18).
9. Right PSK, wrong key on a PSK relay -> alert 3 or `ErrRelayAuthFailed`,
   never a silent close.
10. Every single-bit flip in ServerHello (`enc_e` and `finished_r` regions)
    -> `ErrRelayAuthFailed` or a decapsulation error, never success. Every
    flip in the ClientHello binder -> silent reject on a PSK relay.
11. ServerHello from another session spliced in -> `ErrRelayAuthFailed`.
12. Bad version (client side -> `ErrUnsupportedVersion`), bad magic, unknown
    type, each length off by one, reserved flag bits, non-zero binder with
    the flag clear, all-zero `enc_s` (low-order point), malformed
    `eph_pk_c`, KeyRequest twice -> alert 1 on a no-PSK relay, silent reject
    on a PSK relay.
13. Low-order relay key on the client -> `ErrInvalidRelayKey`, nothing
    written.
14. Records: reordered, replayed, bit-flipped, dropped in the middle ->
    `ErrRecordAuth`; write failure after seal -> `ErrChannelBroken`, sticky;
    oversize -> `ErrFrameTooLarge` and the channel still usable; sequence
    exhaustion through the hook.
15. Fuzz `FuzzAccept` (arbitrary first and second frames, with and without
    PSK: no panic, at most one response frame, zero response bytes with PSK
    unless the binder is valid) and `FuzzInitiate` (arbitrary relay
    replies).

### 16.2 `relayconn` tests

16. `ParseAddress` table: every rule in section 13.1 (defaults, path on ws
    and wss and its rejection on tcp and tls, IPv6 compression, IPv4-mapped,
    zone rejected, trailing dot, upper case, non-ASCII rejected, each error)
    and `String()` round trip and fixed point; `StoreName` equal for all
    spellings of one relay; `FuzzParseAddress`.
17. TLS config derivation table (section 12): `cert` with `tls=skip`
    rejected; `WithTLSConfig` with `cert` -> `ErrTLSOptions`;
    `PinnedTLSConfig` has TLS 1.3 minimum; self-signed wss without `rk` or
    `cert` -> `ErrTLSVerify` whose text names both options.
18. Key resolution (section 13.2) against `relaytest`: stored key used when
    `rk` absent; `rk` seeds an empty store after success; stored K1 plus
    address `rk=K2` -> `RelayKeyChangedError{Stored: K1, Presented: K2}`,
    `relaytest.Connections() == 0`, store unchanged; the same with
    `WithReplaceStoredKey()` -> success and store K2;
    `WithReplaceStoredKey()` without `rk` -> `ErrInvalidOption`; PSK and no
    key -> `ErrRelayKeyRequired`, zero connections; stored key and a relay
    with another key -> `ErrRelayAuthFailed`, not `ErrRelayKeyChanged`, no
    KeyRequest sent; a forged alert 3 (test proxy) -> `ErrRelayKeyNotHeld`,
    not `ErrRelayKeyChanged`.
19. First contact: ws, tcp and `tls=skip` -> `UnknownRelayKeyError` with the
    relay's key, and the relay saw only KeyRequest; a retry with the key
    succeeds and stores it; verified TLS (relaytest with `cert`) -> success
    without error, `FirstContact() == true`, key stored, one connection.
20. Store timing: a relay that passes `finished_r` but echoes a mismatched
    token, or closes before `Registered`, leaves the store unchanged.
21. KeyStore: `SettingsKeyStore` against a real `storage.Storage` in a temp
    dir (set, get, delete, unparseable value -> read error); a store whose
    read fails -> the call fails with zero connections; a store whose write
    fails -> the call succeeds and a warning is logged; `NewMemoryKeyStore`
    under `-race` with concurrent dials.
22. Token hook: the `TokenFunc` receives the authenticated key (as its
    service ID); it is never called when the handshake fails or a key error
    returns early; a `TokenFunc` error closes without sending a record.
23. Ported RC-17 tests (`handshake_test.go`): echoed token mismatch,
    truncated, missing, wrong length -> `ErrRelayTokenMismatch` or
    `ErrInvalidRelayToken`, on both `Dial` and `Listen`.
24. Ported RC-14 tests (`context_test.go`): cancel the dial or listen
    context after success on each of the four transports; reads and writes
    still work; the handshake timeout still aborts a stalled relay after
    KeyResponse and after ServerHello.
25. The in-package fake relays in `relayconn_test.go`, `conn_test.go`,
    `ws_test.go`, `listener_test.go`, `context_test.go` and
    `handshake_test.go` switch to `relaytest`.
26. Path: `wss://host/kamune/ws` reaches a relaytest server mounted at
    `/kamune/ws`.

### 16.3 `cmd/relay` tests

27. `relaykey`: creates a 0600 file in a new 0700 dir; reload gives the same
    key; corrupt file, wrong PEM type, unreadable file -> startup error
    naming the path; never overwrites; `DefaultDataDir` failure -> error
    mentioning `server.data_dir`.
28. Config: `psk` valid, invalid and all-zero; the old `password` key ->
    `ErrUnknownKey`.
29. Handlers: record 0 not `Register` closes; record 0 AEAD failure logs at
    warn through `authFailLog` (log capture as in `log_test.go`) and does not
    consume `rateLimitLog`; a pre-auth tcp frame with length prefix 1290 is
    refused without reading the body; a ws message of 1290 bytes before
    ServerHello closes the connection; after ServerHello frames up to
    `max_message_size` pass; the existing frame-size and ws tests pass with
    the new channel.
30. Silent mode: a PSK relay answers KeyRequest, garbage, a ClientHello
    without PSK and a bad binder with zero bytes and closes between 2 s and
    the handshake deadline (time through a test hook, not real sleeps).
31. Stalls: a client that stalls in S1 after KeyRequest on ws (timer path)
    and tcp (deadline path) -> the relay closes at `handshake_timeout`.
32. Old client: an `exchange.Initiate` client against the v2 relay gets
    alert 1 (no PSK) or silence (PSK), logged at debug.
33. `-gen-psk` output parses; `-print-key` prints the same key twice, and
    with no key file fails naming the path and creates nothing.

### 16.4 MITM tests

These live in the relay module, in `internal/handlers/mitm_test.go`.

A test proxy sits between a relayconn client and a real relay on tcp, and
one on tls with `tls=skip`:

34. The proxy runs `relayleg.Accept` with its own key toward the client: a
    client with the real `rk` fails with `ErrRelayAuthFailed`; the proxy's
    channel never yields a record; the real relay never sees a Register.
35. The proxy answers KeyRequest with its own key (client without `rk`, no
    PSK): `UnknownRelayKeyError` carries the proxy's key; nothing else is
    sent.
36. Passive forwarding proxy: the session works and the captured byte stream
    contains neither the token nor the PSK.
37. The proxy flips the PSK flag or a binder bit: the PSK relay goes silent,
    the client gets `ErrHandshakeRejected`; no retry happens (the proxy
    counts connections: exactly one).
38. The proxy forges alert 3 toward a pinned client: `ErrRelayKeyNotHeld`;
    the store is unchanged.

### 16.5 End-to-end

39. `cmd/relay/internal/handlers/relay_test.go`: start the relay with a
    generated key and PSK, all four listeners and the self-signed
    certificate. Listener on `tls://...?rk=..&cert=..` with PSK, dialer on
    `ws://...?rk=..` with PSK, static token. Run a full kamune handshake over
    the pair (root `kamune.Server` and `Dialer` with `RelayConn`), exchange
    messages both ways, close, and check that `Accept` then returns
    `net.ErrClosed`. Repeat as a table across transport pairs.
40. Daemon (`cmd/daemon`, driving the binary as `integration_test.go` does,
    against `relaytest` without PSK on ws): `start_server` with an address
    without `rk` -> `code: relay_key_unknown` with the right key; re-send
    with `rk` -> token; `get_share_info` carries `rk`; `forget_relay_key`
    makes the next start fail with `relay_key_unknown` again; `relay_addr`
    with a different `rk` -> `relay_key_changed` with both keys; with
    `replace_relay_key: true` -> success; a multi-token dial against a relay
    with another key returns after one connection
    (`relaytest.Connections() == 1`).
41. bus and tui against `relaytest`: bus `ConnectToServer` returns
    `ErrorCode: relay_key_unknown` and `RelayKey`; the same call with
    `TrustRelayKey` succeeds; `ParseShareURL` round-trips the share builder's
    output and ignores `insecure`; the tui confirm screen model update for
    both error types.

Checks of one part's assumption about another: that RFC011 feeds the relay
key to nothing but `ExtractShared` is checked by test 5 here and by RFC011's
cross-protocol test; that the relay logs no token-derived string is checked
by RFC010's handlers test and by this RFC's `authFailLog` test (test 29).

## 17. Documentation Changes

- `docs/RELAY.md`:
  - Design Goals (the relay leg is authenticated; the relay also keeps
    `relay-static-key.pem` in `server.data_dir`).
  - Threat Model and "What the Relay Observes" and "What a Compromised Relay
    Can and Cannot Do": remove the PSK and token exposure to an active
    attacker; add the TOFU limits, CDN trust on first contact, key
    compromise, and the classical-only static key; the paragraph on what a
    relay learns about peers comes from RFC007.
  - Protocol, Wire Format and Frame Schema (sections 7 to 9 here, `Auth`
    removed), Connection Flow (listener and dialer), Forward Secrecy (the
    leg stays ephemeral X-Wing; the static key identifies the relay, not the
    peers).
  - Authentication Modes: relay key plus PSK, the generated PSK format,
    silent PSK relays, why a PSK relay needs `rk`, and that the binder makes
    a generated key necessary.
  - Rate Limiting: KeyRequest and ClientHello costs, the binder check, the
    1289-byte pre-auth limit, the silent close.
  - Transports and TLS: the composition table, `tls=skip`, TLS 1.3 minimum,
    `cert=` in place of client pin options.
  - Handshake Timeout (its scope).
  - Go Client: the new API, key store, first contact, the errors table of
    section 15.1.
  - Configuration Reference and Field Semantics: `psk`,
    `relay-static-key.pem`, `-gen-psk`, `-print-key`.
  - Deployment Patterns and the CDN footnotes: the relay key authenticates
    the relay end to end through a CDN; addresses with `rk`; the WebSocket
    path.
  - Known Limits and Operator Responsibilities (`psk` instead of
    `password`; keep `data_dir`, which now holds the relay key).
  - New subsection **Replacing the relay key**: stop the relay, move
    `relay-static-key.pem` away (keep it offline if the replacement is
    routine; destroy it if compromised), start the relay, publish the new
    address lines. Clients see `ErrRelayAuthFailed`, get the new address from
    the operator, and accept the `RelayKeyChangedError` dialog (or forget the
    key). Clients cannot tell a replacement from an attack, so the new key
    must come over a channel the users already trust.
- `docs/SPEC.md` §9.3 Relay: one paragraph on relay-leg authentication; the
  per-frame overhead text of §9.4 and §13 still holds.
- `cmd/relay/README.md`: server table (`psk` replaces `password`), TLS and
  pinning section, key file and Docker volume note, new flags.
- `docs/DAEMON.md`: `start_server` and `dial` parameters, address grammar,
  error codes and fields, `forget_relay_key`, `replace_relay_key`,
  `get_share_info`, and "show the key to a human".
- `cmd/tui/README.md`: relay fields and the key confirm screen.
- `cmd/bus/README.md`: relay fields.
- `docs/RED_TEAM_REVIEW.md`: mark RC-03, REL-02, RC-14, RC-17, DMN-10,
  BUS-36 and BUS-29 resolved only if the maintainer asks. `CHANGELOG.md` is
  not touched unless asked.

## 18. Implementation Plan

Every commit builds and passes `go vet` and `go test ./...` in all five
modules. All sub-modules use `replace => ../../`, so nothing old is deleted
until no caller remains. Subjects stay within 72 characters, with
`relayconn:` for the package and its subpackages, as AGENTS.md requires.

| Order | Module | Commit group | Depends on |
| ----- | ------ | ------------ | ---------- |
| 0 | root | `kamune: add Storage.DeleteSettings` | none |
| 1 | relayconn | `relayconn: add relayleg keys, psk and their text forms` | none |
| 2 | relayconn | `relayconn: add the relayleg v2 handshake and record channel` | 1 |
| 3 | relayconn | `relayconn: add relay addresses and the relay key store` | 0, 2 |
| 4 | relayconn | `relayconn: add Dial and Listen over relayleg`, next to the old helpers | 3; RFC010's `pkg/rendezvous` |
| 5 | relayconn | `relayconn: add the relaytest server` | 4 |
| 6 | relay | `relay: keep a static relay key in the data dir and log it` | 5 |
| 7 | relay | `relay: authenticate the relay leg with relayleg and a psk`; v1 clients now fail at runtime against the relay, everything compiles. Merges together with end-to-end test 39. | 6 |
| 8 | relay | `relay: add -gen-psk and -print-key` | 7 |
| 9 | daemon | `daemon: use relayconn addresses, psk and relay key trust` (code and schema) | 5 |
| 10 | bus | `bus: use relayconn addresses, psk and relay key trust` (Go, Svelte, bindings) | 5 |
| 11 | tui | `tui: replace the certificate pin field with a relay key` | 5 |
| 12 | relayconn | `relayconn: remove the v1 relay helpers, password option and auth frame`: deletes the eight helpers, `WithPassword`, `auth.go`, `pb.Auth`; regenerates `relay.pb.go`; moves the `ReadWriter` and `FrameLimiter` uses to `relayleg` | 9, 10, 11; RFC010's relayconn token options |
| 13 | docs | `docs: ...`, one commit per document (section 17) | the code of this RFC |

The client commits (9 to 11) need only the API and `relaytest`, so they can
start once commit 5 lands. The sample config and Dockerfile comments are part
of the relay code commits, not `docs:` commits.

Ordering with the other parts (RFC006 holds the combined order):

- RFC010's `pkg/rendezvous` lands before commit 4, so `WithToken` and
  `WithTokenFunc` use `rendezvous.Token` and `rendezvous.TokenFunc` from the
  start and RFC010 does no retyping.
- RFC010's `Refused` frame lands after commit 4, and the relay sends it once
  commit 7 is in. RFC010's relayconn token options (`WithPair`,
  `AllowPeer`) build on commit 4.
- RFC011's broker codec and server use `relayleg.PublicKey`, `KeyHint`,
  `LoadPrivateKeyFile` and `ExtractShared` after commit 1; its relay-module
  switch uses `Service.StaticKey()` after commit 6.
- In each client file, this RFC's changes come first, then RFC011's,
  RFC010's token changes, RFC008's, RFC010's reconnect changes, and RFC007's
  last.
- In the relay module, commits 6 to 8 come before RFC010's relay changes and
  RFC011's relay switch.
- Commit 12 belongs to the deletion phase; `pkg/exchange` is deleted by the
  final cleanup after RFC007, this RFC, RFC010 and RFC011 have removed their
  callers.

## 19. Deferred

- **PAKE for human passwords** (CPace, OPAQUE): not in the dependency set;
  the generated PSK avoids the need, and passwords are not supported
  (section 5.1).
- **Key rotation with overlap**: the relay holds one key. `key_hint` is on
  the wire and in the transcript so that a later relay can hold a "current"
  and a "retiring" key and pick by hint without changing the v1.0 wire
  format. Without an authenticated way for the relay to announce its next key
  to pinned clients, an overlap only delays the same user-visible key change,
  so both parts are deferred together. RELAY.md documents the replacement
  procedure.
- **Post-quantum relay authentication**: forging needs a quantum computer at
  handshake time; confidentiality is already hybrid, and with a PSK an
  active quantum attacker still cannot impersonate the relay. An ML-KEM
  static key (1184 bytes) does not fit in an address and would need the key
  fetch on every contact.
- **Per-client credentials and PSK identities**: one relay-wide PSK, as
  today.
- **Traffic-analysis resistance on ws and tcp**: the `KR` magic, fixed sizes,
  the PSK flag and `key_hint` are visible without TLS. Hiding them needs
  padding and Elligator-encoded keys; use wss or tls where this matters.
- **TLS exporter channel binding**: adds nothing over the relay key and
  breaks behind a CDN.
- **Relay key file outside `data_dir`** for the relay leg (a
  `relay_key_file` option for mounted secrets), in the same PEM format.

## 20. Open Questions

1. When a client accepts and stores a relay key fetched over verified TLS
   (which trusts a TLS-terminating CDN for that first contact), should it
   show a one-time "new relay key stored" notice? There is no prompt either
   way; `FirstContact()` gives clients what they need to show one.
