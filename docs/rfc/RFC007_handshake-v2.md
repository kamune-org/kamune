# RFC: Handshake v2: Transcript-Bound Authentication and Resumption

**Status:** Draft

**Target:** Kamune Protocol Specification before v1.0 (not scheduled)

**Relates to:** §2 (Terminology), §3 (Cipher Suite), §5 (Routes), §6
(Protocol Flow), §7 (Encryption and Key Derivation), §8.1 (Digital
Signatures), §9.4 (Connection Contract), §10 (Endpoint Roles), §11.3 (Stored
Entities), §11.6 (Sessions Without Persistence), §12 (Security Properties),
§13 (Constants and Limits), §14 (Error Conditions); RELAY.md "Threat Model",
"What the Relay Observes", "What a Compromised Relay Can and Cannot Do";
RFC001, RFC002; RFC006 (overview), RFC008, RFC009, RFC010, RFC011

---

## 1. Summary

Replace the four phases that establish a session today (Exchange,
Introduction, Handshake, Challenge) and the token-based resumption path with
one handshake of four flights and two round trips:

- one ephemeral X-Wing (ML-KEM-768 + X25519) encapsulation through
  `crypto/hpke`, which keeps hybrid post-quantum confidentiality;
- SIGMA-I authentication: an Ed25519 signature and a Finished MAC from each
  side, over one SHA-512 transcript of every handshake byte;
- resumption as a pre-shared key mixed into that full handshake (TLS 1.3
  `psk_dhe_ke`), offered with a binder MAC; no token goes on the wire.

The verifier runs on every handshake, resumed ones included, and only after
the peer has proved possession of its key over this transcript. Prompts show
two labelled 40-digit verification codes. An exporter gives RFC010 a
per-session secret.

The change is a wire-incompatible hard cut, as in RFC004. The peer wire
protocol, the on-disk resumption format and the exported Go APIs change; a v1
peer and a v2 peer cannot complete a handshake, and there is no negotiation.
This RFC is not implemented. It is one part of the pre-v1.0 rework that
RFC006 describes.

It closes KAM-01, KAM-02, KAM-03, KAM-08, KAM-15, KAM-26, KAM-27, KAM-28 and
KAM-32 of `docs/RED_TEAM_REVIEW.md`, and partly closes KAM-10 and KAM-31
(§24).

In the **Relates to** line, as in the other RFCs, § numbers are sections of
`docs/SPEC.md`. Everywhere else, section numbers without a prefix refer to
this RFC, and "SPEC §n" refers to `docs/SPEC.md`.

## 2. Current Behavior

Session establishment runs four phases in sequence (SPEC §6.1 to §6.4):

1. **Exchange.** `exchange.Initiate` and `exchange.Accept`
   (`pkg/exchange/channel.go`) run an ephemeral HPKE exchange
   (MLKEM768-X25519, HKDF-SHA512, ChaCha20-Poly1305) in three messages. No
   long-term key takes part, so the resulting `exchange.Channel` is
   encrypted but not authenticated. The Introduction, resumption and
   Handshake messages travel inside it.
2. **Introduction.** The dialer sends `Introduce{Name, PublicKey,
   AppVersion}` signed by the key it carries (`sendIntroduction`,
   `intro.go`). The server (`handleNewConnection`, `server.go`) checks the
   version, runs the `RemoteVerifier` through `verifyPeer`, which lifts the
   connection deadline for up to the verify timeout (150 s), and only then
   sends its own Introduce. The dialer checks it and runs its own verifier.
3. **Handshake.** `requestHandshake` and `acceptHandshake` (`handshake.go`)
   run ML-KEM-768 (`exchange.NewMLKEM`, `exchange.EncapsulateMLKEM`) inside
   the tunnel, in messages signed with the identity keys. The session ID is
   a 12-character prefix chosen by the initiator plus a 12-character suffix
   chosen by the responder (`enigma.Text`): 24 characters of `[A-Z2-7]`.
   One `enigma.Enigma` per direction is derived from the ML-KEM secret and
   each side's salt.
4. **Challenge.** `sendChallenge` derives a value from the ML-KEM secret and
   `handshakeTranscriptHash` (SHA-256 over the inner `pb.Handshake` fields)
   and sends it under the new keys. `acceptChallenge` echoes what it
   received without recomputing it.

The dialer can send application data after about 5.5 round trips: 1.5 for
the Exchange, 1 for the Introduction, 1 for the Handshake and 2 for the
Challenge.

**Resumption** (SPEC §6.8, RFC001). After a handshake,
`persistEstablishedSession` stores 20 single-use 32-byte tokens
(`deriveResumptionTokens`) under the session meta key `resumption_tokens`
with `PutSessionResumption`. `DialWithResume` pops one (`PopList`) and, in
place of the Introduction, sends a signed `ResumeRequest{SessionID, Token}`
inside the Exchange tunnel (`attemptResume`). `handleResume` finds the peer
by session (`GetPeer(sessionID)`), checks the signature and a window of 24
hours from `established_at` that resumes do not move
(`resumptionGracePeriod`), removes the token and answers with a signed
`ResumeAccept`. A rejection is a signed `ResumeAccept` too, sent to a
requester that has not been authenticated (`rejectResume`). Neither side runs
the verifier. The Handshake and Challenge then run with the stored session
ID.

**Teardown.** `Transport.Close` and the first call of `terminate` delete the
session's stored tokens (`invalidateResumptionTokens`), whatever ended the
session: a local close, a received `RouteCloseTransport`, an AEAD failure, a
bad signature, a duplicate sequence number or a gap. `CloseAbort` keeps
them.

**Admission.** `admit` (`server.go`) puts an accepted connection on
`Server.waiting`, capped by `maxPending` (default 256); at the cap,
`dropCandidateLocked` evicts the oldest connection of a network that holds
the most entries. `introduced` takes the connection off that list when the
first message after the Exchange arrives, and from then on it is not
evictable. The per-source cap (default 16) counts a connection at `admit`,
except one with a UDP source (`forgeableAddr`), which counts at
`introduced`.

**Verifier.** `RemoteVerifier` is `func(store *storage.Storage, peer
*storage.Peer) error` (`kamune.go`). It sees the peer's self-signed
Introduce before any key confirmation, and it does not run on resumption.

**Fingerprints.** `fingerprint.Numeric` (eight groups of five digits, about
132.9 bits, SHA-512 over the PKIX key) exists. The verify prompts of the
daemon, bus and TUI also show `fingerprint.Emoji` (about 52.7 bits) and
`fingerprint.Hex`, and the default fingerprint format of the daemon and the
bus is `hex`.

## 3. Motivation

The design answers these findings of `docs/RED_TEAM_REVIEW.md`. Fixes
already made on the v1 code cover parts of some of them: for example,
`fingerprint.Numeric` exists (KAM-03), and the resume rejection tests in
`resume_test.go` now drive `Server.serve` (KAM-32). This RFC replaces that
code; §24 records what closes each finding in the new design.

| Finding | What the review found                                                                                                                                                               |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| KAM-02  | The Exchange is unauthenticated. An active relay or on-path attacker that runs it separately with each side reads both identities, the session IDs and the resumption tokens.   |
| KAM-01  | Introduce, ResumeRequest and ResumeAccept carry no nonce and no channel binding, so they replay across connections; the verifier runs before the peer has confirmed any key.     |
| KAM-27  | The receiver of a challenge echoes it without recomputing it, so the transcript binding that SPEC §6.4 describes is never checked.                                               |
| KAM-10  | The server signs a `ResumeAccept` for any unauthenticated client, which confirms its identity to anyone who guesses its key.                                                     |
| KAM-15  | A lost final challenge echo leaves the two sides with different token sets, and every later resume fails.                                                                       |
| KAM-08  | Resumption skips the verifier, so Strict mode in the bus, daemon and TUI does not prompt for resumed sessions.                                                                  |
| KAM-28  | The resumption window counts from the first cold handshake and never resets on resume.                                                                                          |
| KAM-03  | The 8-emoji fingerprint shown for verification has 52.7 bits of second-preimage resistance.                                                                                     |
| KAM-26  | The pseudonym is listed as a fingerprint format but carries 29.6 bits.                                                                                                          |
| KAM-32  | The resume rejection tests reimplement server logic instead of driving `Server.serve`.                                                                                          |
| KAM-31  | Handshake, transport and storage failure paths have no tests, and the fuzzers only produce validly signed input.                                                                |

## 4. Terminology

| Term                        | Definition                                                                                                                                                                 |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Initiator, Responder**    | The dialer and the server. The roles are fixed for a connection.                                                                                                           |
| **Flight**                  | One message of the handshake: F1 ClientHello, F2 (ServerHello and ResponderAuth), F3 InitiatorAuth, F4 Confirm.                                                            |
| **Transcript, `TH`**        | The SHA-512 hash of a domain label and the tagged entries of §11. `TH_x` is its value after entry `x`.                                                                     |
| **Pin**                     | A key the initiator requires the responder to hold: the key of `DialWithPeerKey`, the stored key of the session offered for resumption, or a key the `Conn`'s `PeerConstraint` allows. |
| **Resumption secret (`res`)** | A 64-byte secret per session and role, stored on disk, from which the binder key and the PSK derive (§12.3, §15.1).                                                     |
| **Binder**                  | `HMAC-SHA512` over `TH_iid` keyed from `res`; proves the initiator holds `res` for this transcript.                                                                       |
| **Verification code**       | `fingerprint.Numeric` of one PKIX identity key: 40 digits, about 132.9 bits. Prompts show two, labelled.                                                                   |
| **Safety number**           | `fingerprint.SafetyNumber`: both codes, the bytewise-smaller key first, joined by a newline. For copy and paste.                                                           |
| **Exporter**                | `Transport.ExportKeyingMaterial`, per-session keying material for other protocols (RFC 8446 §7.5 pattern).                                                                 |
| **COLD, RESUMED, REJECTED** | The three Confirm statuses (§10.7).                                                                                                                                        |
| **Authenticated stage**     | The server admission stage a connection enters once `sig_I` and `finished_I` verify (§14.4).                                                                               |

## 5. Decisions

| Question                         | Decision                                                                                                                                                                                                                                                                                                                                               |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Rollout                          | **Maintainer decision: not implemented now.** Draft, targeted before v1.0, not scheduled. A wire-incompatible hard cut with no version negotiation and no backward compatibility: the peer wire protocol, the on-disk resumption format and the exported Go APIs change.                                                                                               |
| Key exchange                     | **One ephemeral X-Wing encapsulation** (`crypto/hpke`, `MLKEM768X25519`, `HKDF-SHA512`, `ExportOnly`) replaces the HPKE Exchange, the Introduction, the ML-KEM-768 Handshake and the Challenge. Identities, names, versions, session ID, resumption data and all traffic sit behind ML-KEM-768 and X25519 together. 1.5 RTT for the responder, 2 RTT for the initiator. |
| Authentication                   | **SIGMA-I, sign-and-MAC** (TLS 1.3 `CertificateVerify` plus `Finished`). The responder proves its key first. The initiator sends its identity only after it has checked the responder's signature and either matched a pin or had its verifier accept the responder. The responder sends its name and version only after it has authenticated and accepted the initiator. |
| Transcript                       | **One SHA-512 transcript** over every handshake byte, both hellos included. Both signatures and all three Finished MACs cover it, and every later key derives from it. A split key exchange (KAM-02), a replayed message (KAM-01) or a mismatched transcript (KAM-27) fails at the first signature or MAC check.                                  |
| Resumption                       | **A PSK mixed into a full handshake** (TLS 1.3 `psk_dhe_ke`). The fresh hybrid KEM and both signatures still run. The offer travels only inside the initiator's encrypted authentication message, after it has authenticated the responder, and carries a binder, never a token. The responder decides only after it has authenticated the initiator. A failed resumption becomes a cold handshake on the same connection. |
| Resumption state                 | **One rotating secret per session and role; the responder also accepts the previous one.** Writes are compare-and-swap on a generation number; resumes of one session are serialized in-process on the initiator; only authenticated end-of-session events delete state. Sliding idle window plus a maximum age. Deleting or expiring the peer revokes resumption. |
| Verifier                         | **Runs on every handshake**, resumed ones included, and only after the peer has proved key possession over this transcript. It gets a `VerifyRequest` with `Role`, `Pinned`, `ResumeOffered` and `Resumed`.                                                                                                                                     |
| Verification code                | **Two labelled 40-digit codes** (`fingerprint.Numeric` of each key), read back in full. `fingerprint.SafetyNumber` gives the combined 80-digit string. Emoji leave every verification surface.                                                                                                                                                   |
| Exporter                         | **`Transport.ExportKeyingMaterial`** gives RFC010 a per-session secret for relay reconnect tokens. No relay token travels inside the peer handshake.                                                                                                                                                                                               |
| Listener identity exposure       | **Maintainer decision: accepted for now and documented** (§8.3). Anyone who can reach a listener, the relay operator included, learns its identity key and gets a fresh signature by it. Contact-only listeners are left for a future RFC (§25.1). KAM-10 is partly closed.                                                                                            |
| Handshake plaintext encoding     | **Fixed binary layouts**, not protobuf. Canonical by construction, with zero padding checked; no `handshake.proto`.                                                                                                                                                                                                                               |
| Channel binding to the UDP path  | **Not absorbed** into the transcript (§21).                                                                                                                                                                                                                                                                                                         |

## 6. Proposed Defaults

| Item                                   | Proposed default                                                                                                                                                                                                         |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Resumption window                      | 24 h idle from `RefreshedAt` (moved by every handshake of the session and by a transport end that keeps state) and 7 days maximum age from the last cold handshake. Constants (`defaultResumeIdle`, `defaultResumeMaxAge`); no option until a client needs one. |
| Strict initiator on a pinned resume    | No prompt when `Pinned && ResumeOffered`: an automatic reconnect to a key the user already approved, which cannot change. A Strict responder prompts on every handshake, resumed ones included.                        |
| COLD answer to a resume offer          | Clients fall back: the old session ends and a new one starts. No client sets `DialWithResumeOnly` by default.                                                                                                           |
| Identity key encoding on the wire      | PKIX `SubjectPublicKeyInfo` (44 bytes, as storage uses), with a fixed 12-byte prefix check so each key has exactly one encoding. A later move to raw 32-byte keys would be a separate wire change (§25).                  |
| Second resume of a session in progress | Fails at once with `ErrResumeInProgress`, rather than waiting: deterministic to test, and waiting would hold a goroutine across a verifier prompt.                                                                      |
| Timeouts                               | Handshake 30 s; verify 150 s; accept to ClientHello (`introTimeout`) 10 s; hello stage `handshakeTimeout + verifyTimeout` = 180 s.                                                                                     |
| Admission caps                         | `maxPending` 256 for each pre-authentication stage; per-source cap 16.                                                                                                                                                  |
| Sweep of expired state                 | At `ListenAndServe` start and every hour (`sweepInterval`).                                                                                                                                                             |
| Client prompt limits                   | One open verification prompt per client; at most 6 prompts per rolling minute. No exemption: prompts on the initiator side of the user's own dials count too (open question 2, §27). |
| `fingerprint.Emoji`                    | Output and vectors unchanged; removed from every verification prompt and verify event; other uses stay (§17.2). Its later fate is open question 1 (§27).                 |
| Fingerprint format setting             | `numeric` is the default in the daemon and the bus.                                                                                                                                                                      |
| `AppVersion`                           | `"0.8.0"` from the switch commit, so logs and share info show which peers speak v2; at most 32 bytes.                                                                                                                   |
| Daemon error codes                     | `self_connection`, `handshake_rejected`, `version_mismatch`, `unsupported_protocol`, `verification_failed`, `resume_refused` for the final handshake errors; `peer_key_mismatch` (shared with RFC010) for `kamune.ErrPeerKeyMismatch`. |

## 7. Scope and Interfaces with Other RFCs

In scope: everything between "a `Conn` exists" and "a `Transport` is
established": phase order, wire messages, key schedule, transcript, verifier
policy, resumption state and window, admission stages, the exporter,
verification codes, and the verifier and reconnect code of the clients.

Out of scope: the per-frame `SignedTransport` format and the padding of
session frames (unchanged, §18), the UDP path (RFC008), the relay leg
(RFC009), rendezvous tokens (RFC010) and the broker (RFC011).

| RFC              | What this RFC assumes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | What this RFC provides                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC008 (UDP)     | A `kamune.Conn` (ordered, reliable, length-prefixed frames up to `maxFrameSize`) reaches `Server` or `Dialer` only after RFC008's return-routability check. RFC008 keeps `pendingConn.forgeable` but computes it from `ReturnRoutable` and deletes `forgeableAddr`; this RFC does not edit that computation, and its stage logic counts a forgeable conn on entering "authenticated" (§14.4). That rule is permanent. RFC008's `ServeWithHandshakeRate` check runs first in `admit`, before this RFC reads the ClientHello.                                    | Frame sizes for RFC008's amplification budget: the initiator's first frame is 1282 bytes; the responder answers with 1154 + 214 = 1368 bytes. The responder does one X-Wing encapsulation and one Ed25519 signature per ClientHello. No value from the UDP path enters the transcript (§21); RFC008 only reserves its `binding` label.                                                                                                                                                                                                                    |
| RFC009 (relay)   | Nothing. Peer handshake security does not depend on the relay leg. RFC009 owns the relay static key and the relay-leg text in RELAY.md.                                                                                                                                                                                                                                                                                                                                                                                                                        | The RELAY.md paragraph on what a relay learns about peers (§8.3), placed in RFC009's rewrite of "What the Relay Observes" and "What a Compromised Relay Can and Cannot Do".                                                                                                                                                                                                                                                                                                                                                                              |
| RFC010 (tokens)  | If RFC010 derives a static pairwise secret from the two Ed25519 identity keys, the raw X25519 output is never returned to callers: `pkg/attest` exposes only `func (a *Attest) PairSecret(peerPKIX []byte, salt string) ([64]byte, error)`, which returns `HKDF-Extract(SHA-512, salt, dh \|\| lo \|\| hi)` over the DH output and both raw public keys (the joint-security condition of Thormarker, ePrint 2021/509, for one scalar used for Ed25519 and X25519). The conversion helpers are unexported. RFC010 adds `PeerConstraint`, `ExpectPeer` (root `peerconstraint.go`) and `ErrPeerKeyMismatch`; this RFC calls `AllowPeer` at §13.3 steps 4a and 3a. RFC010's relay dialer grace and first-frame watchdog are 10 s; the initiator sends its ClientHello as soon as the conn is open. | `func (t *Transport) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)` (§12.5). Its output depends on the full transcript (`TH_final`) and, when resumed, on the PSK, so a resumed session has a new exporter. There is no `ErrNotEstablished`: a `Transport` exists only once established. After `Close`, `CloseAbort` or termination it returns `ErrConnClosed`. A nil and an empty `context` give the same output. Labels starting with `kamune/` are reserved for kamune; RFC010 uses `kamune/relay-reconnect` (`rendezvous.ReconnectLabel`). Also `DialWithPeerKey`, `DialWithResume`, `Transport.Resumed`, `SessionID` and `ErrSelfConnection`. |
| RFC011 (broker)  | Nothing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | The signature-context registry in `pkg/attest` (§13.4). RFC011 signs nothing with the identity key, so it registers nothing there.                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

The identity key is used only for signatures under the contexts registered
in §13.4, and is converted to X25519 only inside `attest.PairSecret`. There
is no separate X25519 identity key.

`pkg/exchange`: the root stops calling `exchange.Initiate`,
`exchange.Accept`, `exchange.NewMLKEM` and `exchange.EncapsulateMLKEM`. This
RFC deletes only `pkg/exchange/mlkem.go` and `mlkem_test.go`. `kamune.Conn`
still embeds `exchange.ReadWriter` (`conn.go`), and `exchange.NewECDH` has
callers in `pkg/relayconn/token.go` and
`cmd/relay/internal/broker/broker.go`. RFC009, RFC010 and RFC011 remove the
remaining callers, and a final commit deletes the package (§26).

## 8. Threat Model and Security Properties

Adversaries are those of `docs/RED_TEAM_REVIEW.md`: A1 passive network, A2
active on-path, A3 malicious relay or broker, A5 unauthenticated remote
client.

### 8.1 Goals

| Goal                                                                                                  | Mechanism                                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| (1) No man in the middle without both signatures covering a transcript that includes the key exchange | Both Ed25519 signatures and all Finished MACs cover `TH`, which starts with the ClientHello (initiator ephemeral X-Wing key, nonce, tag) and the ServerHello (X-Wing ciphertext, nonce). A split KEM gives each side a different `TH`, so the real responder's signature does not verify at the initiator, and the attacker cannot sign as the responder.                                                 |
| (2) Initiator identity protected against active attackers                                             | SIGMA-I order: the responder's key, signature and Finished arrive first. The initiator sends its identity only after (a) the responder's key equals the pinned key (`DialWithPeerKey`, or the stored key when resuming), or (b) without a pin, the initiator's verifier has accepted the responder's key. **Exception: an unpinned AutoAccept dialer accepts any key and so reveals its identity to any active attacker** (§8.2, §23). |
| (3) Every handshake and resume message bound to this connection                                       | Every message after the hellos is encrypted under keys derived from `TH`, and every signature, MAC and binder covers `TH`, which contains two fresh nonces and a fresh ephemeral KEM key and ciphertext.                                                                                                                                                                                                 |
| (4) A resume rejection reveals nothing to an unauthenticated requester                                | The offer is read only inside the initiator's authenticated, encrypted message, after `sig_I` and `finished_I` verify. Any failure (unknown session, wrong key, deleted peer, bad binder, expired, disabled) produces the same `Confirm{COLD}` as no offer, encrypted to that initiator.                                                                                                                  |
| (5) Resumption that cannot desynchronize or be destroyed from the network                            | Fixed commit points (§15.4); `Previous` accepted; CAS on a generation; initiator-side serialization; deletion only on authenticated end-of-session events (§18.3).                                                                                                                                                                                                                                       |
| (6) Verifier policy on resumption                                                                     | The verifier runs on every handshake; `Resumed`, `ResumeOffered` and `Pinned` let each mode decide (§16.1).                                                                                                                                                                                                                                                                                              |
| (7) Verification code of at least 128 bits by default in all clients                                 | Two labelled `Numeric` codes, 132.9 bits each (§17).                                                                                                                                                                                                                                                                                                                                                     |

### 8.2 What Each Party Learns

| Observer                                                     | Initiator identity, name, version                 | Responder identity                                                                                         | Responder name, version                        | Session ID                            | Resume or cold                                 | Linkable across sessions                                  |
| ------------------------------------------------------------ | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------- | ---------------------------------------------- | --------------------------------------------------------- |
| A1 passive network, or a relay that only forwards            | no                                                | no                                                                                                         | no                                             | no                                    | not by size (fixed sizes); possibly by timing  | no (fresh ephemerals and nonces; no ticket in the clear)  |
| A2/A3 active, impersonating the responder to a pinned initiator | no (pin check fails before F3)                 | n/a                                                                                                        | n/a                                            | no                                    | no                                             | no                                                        |
| Same, unpinned Strict or Quick initiator                     | only if the user accepts the attacker's key at the prompt | n/a                                                                                                | n/a                                            | only then                             | only then                                      | no                                                        |
| Same, unpinned AutoAccept initiator                          | **yes**                                           | n/a                                                                                                        | n/a                                            | no (resume offers are always pinned)  | no                                             | no                                                        |
| A2/A3/A5 acting as initiator toward a responder (prober)     | n/a                                               | **yes**: identity key, plus a signature over a transcript the prober chose (proof the key is live there now) | no: sent only after the responder accepts the prober | no                              | no                                             | the responder's key, across probes                        |
| The authenticated, accepted peer                             | yes                                               | yes                                                                                                        | yes                                            | yes                                   | yes                                            | yes                                                       |

### 8.3 Listener Key Exposure

In SIGMA-I the responder proves its key first. **Anyone who can deliver a
ClientHello to a listener learns that listener's identity key and gets a
fresh signature by it.** This is the exposure of a TLS 1.3 server
certificate. It reaches:

- any host that can reach a direct TCP or KCP listener;
- through a relay, anyone who can register the listener's relay token. With
  RFC010's tokens only the two peers and the relay operator can compute it.
  **The relay operator can always probe a listener behind it.**

The signature covers a transcript the prober chose (including `nonce_i`),
so it is a transferable, timestampable proof that key K was live at that
address. The listener's name and app version are not exposed: they travel
in F4, after the listener has accepted the initiator.

Compared with today: an AutoAccept server already reveals its identity,
name and version to anyone, and a Quick or Strict server reveals them only
after its verifier has accepted the dialer (`handleNewConnection` runs
`verifyPeer` before `sendIntroduction`). **For Quick and Strict listeners,
key exposure to probers grows, and dialers are protected instead.**

**Decision.** This exposure is accepted for now and documented in SPEC §12
and RELAY.md. Contact-only listeners, which answer only ClientHellos tagged
by a stored contact, are left for a future RFC; §25.1 records the sketch.
The ClientHello already carries the 32-byte `tag` field such a mode needs,
so it will need no frame layout change. KAM-10 is therefore listed as partly
closed.

Text for RELAY.md ("What the Relay Observes" and "What a Compromised Relay
Can and Cannot Do"), merged by RFC009:

> The relay cannot read message content, and a relay that only forwards
> frames learns neither peer's identity. A relay that actively interferes
> can learn a listener's identity key, and get a signature that proves the
> key is live, by connecting to it as a dialer, as any dialer can. It does
> not learn the listener's name or version, and it cannot learn the dialer's
> identity unless the dialer pins no key and either accepts the relay's key
> at the verification prompt or runs in AutoAccept mode. It cannot complete
> a session in the middle: both peers sign the full handshake transcript.

### 8.4 Properties Not Provided

Documented in SPEC §12:

- **Post-quantum authentication of cold handshakes.** Ed25519 is classical.
  A quantum attacker that is active during the handshake could forge
  signatures. Recorded traffic stays confidential because of ML-KEM-768. A
  **resumed** handshake is PSK-authenticated (the binder and `finished_C`
  depend on a secret from an earlier hybrid session), but only if the
  initiator refuses a COLD answer (`DialWithResumeOnly`, §15.2). Without
  that option a signature-forging attacker can answer COLD; it then learns
  the initiator's identity block and the offered session ID. ML-DSA is not
  in the dependency set (§25).
- **Deniability.** The per-frame Ed25519 signatures (unchanged, §18) and the
  handshake signatures are transferable proofs.
- **Hiding cold or resumed from timing.**
- **Prompt flooding.** Any party can generate a key and complete F3, so a
  listener's verifier can be made to run repeatedly. The clients bound this
  (one prompt at a time, a rate limit, §20.1); the library does not.

## 9. Protocol Overview

Patterns reused: the TLS 1.3 key schedule and `HKDF-Expand-Label` (RFC 8446
§7.1), the TLS 1.3 transcript hash, `CertificateVerify` context strings and
`Finished` (RFC 8446 §4.4), SIGMA-I ordering (Krawczyk 2003, as in IKEv2 and
TLS 1.3 client authentication), TLS 1.3 `psk_dhe_ke` resumption with a
binder (RFC 8446 §4.2.11), TLS 1.3 encrypted extensions sent after key
confirmation (for the responder's name), the TLS exporter (RFC 8446 §7.5),
and HPKE export-only mode (RFC 9180 §5.3) for the hybrid KEM.

```
Initiator (dialer)                                   Responder (server)
------------------                                   ------------------
F1  ClientHello  [clear]
    ver, type, nonce_i, tag, pk_i          ------->
                                                     enc, ss = Encap(pk_i)
                                                     derive hs keys
F2a ServerHello  [clear]                   <-------  ver, type, nonce_r, enc
F2b ResponderAuth [r_hs key]               <-------  {key_R}, sig_R, finished_R
ss = Decap(enc); derive hs keys
check pin / self / sig_R / finished_R
run verifier on R
F3  InitiatorAuth [i_hs key]               ------->
    {key_I, name_I, version_I, resume_sid?}
    binder?, sig_I, finished_I
                                                     check sig_I, finished_I,
                                                       self, name, version
                                                     decide resume (binder)
                                                     run verifier on I
                                                     derive master, app keys
                                                     persist resumption state
F4  Confirm [r_hs key]                     <-------  {status, reason,
                                                      name_R, version_R},
                                                     finished_C
                                                     (responder established)
check finished_C (master-derived)
check name_R, version_R
derive app keys, persist state
(initiator established)
```

The verifier runs exactly once per side: the initiator's between F2 and F3,
the responder's between F3 and F4. On the initiator the verifier sees the
responder's authenticated key but not yet its name (§16).

## 10. Wire Format

All frames ride on `Conn.WriteBytes` and `Conn.ReadBytes` (2-byte length
prefix, SPEC §9.4, unchanged). Integers are big-endian. `ver` is `0x02`.

### 10.1 Frame Types

| type | Name          | Direction | Protection         | Size |
| ---- | ------------- | --------- | ------------------ | ---- |
| 0x01 | ClientHello   | I→R       | none               | 1282 |
| 0x02 | ServerHello   | R→I       | none               | 1154 |
| 0x03 | ResponderAuth | R→I       | AEAD, `r_hs_key`   | 214  |
| 0x04 | InitiatorAuth | I→R       | AEAD, `i_hs_key`   | 426  |
| 0x05 | Confirm       | R→I       | AEAD, `r_hs_key`   | 234  |

Check order on every received frame: (1) exact length for the expected
type, (2) `ver`, (3) `type`, (4) AEAD open for encrypted frames, (5)
plaintext layout. A wrong `ver` gives `ErrUnsupportedProtocol`. Any other
failure in (1) to (3) or (5) is a protocol error, `ErrInvalidHandshake`
(new); (4) gives `ErrVerificationFailed`. In every case the connection is
closed without a reply.

### 10.2 ClientHello

1282 bytes.

| Offset | Size | Field                                                                                                                                              |
| ------ | ---- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0      | 1    | `ver` = 0x02                                                                                                                                       |
| 1      | 1    | `type` = 0x01                                                                                                                                      |
| 2      | 32   | `nonce_i`, random                                                                                                                                  |
| 34     | 32   | `tag`: 32 random bytes. Reserved for a contact tag (§25.1); the responder ignores it.                                                              |
| 66     | 1216 | `pk_i`: X-Wing (MLKEM768-X25519, HPKE KEM 0x647a) ephemeral public key                                                                             |

`pk_i` must parse with `hpke.MLKEM768X25519().NewPublicKey`.

### 10.3 ServerHello

1154 bytes.

| Offset | Size | Field                        |
| ------ | ---- | ---------------------------- |
| 0      | 1    | `ver` = 0x02                 |
| 1      | 1    | `type` = 0x02                |
| 2      | 32   | `nonce_r`, random            |
| 34     | 1120 | `enc`: the X-Wing encapsulation |

### 10.4 Encrypted Handshake Frame

| Offset | Size   | Field                                                              |
| ------ | ------ | ------------------------------------------------------------------ |
| 0      | 1      | `ver` = 0x02                                                       |
| 1      | 1      | `type` (0x03, 0x04 or 0x05)                                        |
| 2      | 24     | XChaCha20-Poly1305 nonce, random                                   |
| 26     | P + 16 | ciphertext and tag, where P is the fixed plaintext size of the type |

`AD = "kamune/2 hs" || ver || type`. P is 172 (0x03), 384 (0x04) or 192
(0x05). Plaintexts are fixed binary layouts (below), never protobuf. Each
layout is self-delimiting; bytes after the last field up to P are padding
and **must be zero** (else `ErrInvalidHandshake`). Fixed sizes hide the name
length, the presence of a resume offer and the Confirm status. Keys come from
`enigma.NewFromKey` (new, §19.4). Random nonces are safe because each key
seals at most 2 frames.

Common sub-encodings:

- `key`: 44 bytes, an Ed25519 PKIX `SubjectPublicKeyInfo`. The first 12
  bytes must equal `30 2a 30 05 06 03 2b 65 70 03 21 00`; the remaining 32
  must pass `attest.IsValidPublicKey` (canonical, not small order). One key
  has exactly one encoding.
- `str8(max)`: `u8 len || len bytes`, `len <= max`.

### 10.5 ResponderAuth Plaintext

P = 172; the fields fill it, so there is no padding.

| Offset | Size | Field                                   | Transcript entry |
| ------ | ---- | --------------------------------------- | ---------------- |
| 0      | 44   | `key_R` (the responder identity block)  | 0x10             |
| 44     | 64   | `sig_R`                                 | 0x11             |
| 108    | 64   | `finished_R`                            | 0x12             |

### 10.6 InitiatorAuth Plaintext

P = 384. The initiator identity block (transcript entry 0x20) is, in order:

| Field        | Encoding     | Rule                                                 |
| ------------ | ------------ | ---------------------------------------------------- |
| `key_I`      | `key` (44)   | as in §10.4                                          |
| `name_I`     | `str8(64)`   | `ValidatePeerName`; empty allowed                    |
| `version_I`  | `str8(32)`   | 1 to 32 bytes; `parseSemver` must accept it          |
| `resume_sid` | `str8(24)`   | length 0 (no offer) or 24 characters of `[A-Z2-7]`   |

Then: `binder` (64 bytes, present if and only if `len(resume_sid) == 24`,
entry 0x21), `sig_I` (64, entry 0x22), `finished_I` (64, entry 0x23), and
zero padding. Maximum used: 44+1+64+1+32+1+24+64+64+64 = 359 bytes.

### 10.7 Confirm Plaintext

P = 192. The Confirm body (transcript entry 0x30):

| Field       | Encoding   | Rule                                                                                  |
| ----------- | ---------- | ------------------------------------------------------------------------------------- |
| `status`    | u8         | 1 COLD, 2 RESUMED, 3 REJECTED; any other value is `ErrInvalidHandshake`              |
| `reason`    | u8         | 0 with COLD or RESUMED; with REJECTED: 1 VERIFIER, 2 VERSION                          |
| `name_R`    | `str8(64)` | empty with REJECTED; otherwise `ValidatePeerName`                                     |
| `version_R` | `str8(32)` | empty with REJECTED; otherwise 1 to 32 bytes that `parseSemver` accepts               |

Then `finished_C` (64, entry 0x31) and zero padding. Maximum used: 164
bytes.

### 10.8 Protobuf Changes

`internal/box/model.proto` loses `Introduce`, `Handshake`, `ResumeRequest`
and `ResumeAccept` and gains `ResumptionState` (§15.1, on disk only).
`internal/box/box.proto` `Route` loses the handshake routes (§18.2). There
is no `handshake.proto`.

## 11. Transcript

```
TH(entries) = SHA-512( "kamune/2 transcript" || entry_1 || ... || entry_n )
entry       = uint8(tag) || uint32_be(len(bytes)) || bytes
```

| Tag  | Bytes                                | Name of TH after it |
| ---- | ------------------------------------ | ------------------- |
| 0x01 | ClientHello frame, all 1282 bytes    | `TH_ch`             |
| 0x02 | ServerHello frame, all 1154 bytes    | `TH_sh`             |
| 0x10 | `key_R` (44 bytes)                   | `TH_rid`            |
| 0x11 | `sig_R`                              | `TH_rsig`           |
| 0x12 | `finished_R`                         | `TH_rfin`           |
| 0x20 | initiator identity block             | `TH_iid`            |
| 0x21 | `binder` (only when present)         | `TH_ibind`          |
| 0x22 | `sig_I`                              | `TH_isig`           |
| 0x23 | `finished_I`                         | `TH_ifin`           |
| 0x30 | Confirm body                         | `TH_cbody`          |
| 0x31 | `finished_C`                         | `TH_final`          |

Padding and AEAD framing are not hashed; the AEAD covers them and the
padding must be zero. When no binder is present, `TH_ibind = TH_iid`.
Because every layout is canonical, the hashed bytes and the parsed values
correspond one to one.

Implementation: `transcript` keeps a running `hash.Hash` and clones it at
each named point (`crypto/sha512` digests implement `hash.Cloner`), or
rehashes the buffer; the total is under 4 KB.

## 12. Key Schedule

All functions use HKDF-SHA512 (`crypto/hkdf`, HashLen = 64).

```
Expand-Label(S, label, ctx, L) =
    HKDF-Expand(S, uint16_be(L) || uint8(len(full)) || full
                   || uint8(len(ctx)) || ctx, L)
    where full = "kamune2 " || label     // len(full) <= 255, len(ctx) <= 255

Derive-Secret(S, label, TH) = Expand-Label(S, label, TH, 64)
zeros = 64 zero bytes
```

### 12.1 Hybrid KEM

```
Responder: enc, ctx = hpke.NewSender(pk_i, HKDFSHA512, ExportOnly, info)
Initiator: ctx      = hpke.NewRecipient(enc, sk_i, HKDFSHA512, ExportOnly, info)
info = "kamune/2 kex"
ss   = ctx.Export("kamune/2 kex secret", 64)
```

`ss` combines ML-KEM-768 and X25519 through the HPKE key schedule. ML-KEM
decapsulation does not fail (implicit rejection), so a corrupted ML-KEM half
shows up as an AEAD failure on frame 0x03. The X25519 half can fail:
`NewPublicKey` accepts any 32-byte X25519 component, and `ecdh.ECDH`
rejects a low-order point. Error mapping:

- `hpke.NewSender` error at the responder (low-order X25519 part of
  `pk_i`): treated as a bad ClientHello. Close without reply and return a
  wrapped `ErrInvalidHandshake`.
- `hpke.NewRecipient` error at the initiator (low-order X25519 part of
  `enc`): close and return `ErrVerificationFailed`, the same as an AEAD
  failure.

### 12.2 Handshake Secrets

```
hs          = HKDF-Extract(salt = zeros, IKM = ss)
r_hs        = Derive-Secret(hs, "r hs traffic", TH_sh)
i_hs        = Derive-Secret(hs, "i hs traffic", TH_sh)
r_hs_key    = Expand-Label(r_hs, "key", "", 32)       // frames 0x03, 0x05
i_hs_key    = Expand-Label(i_hs, "key", "", 32)       // frame 0x04
r_fin_key   = Expand-Label(r_hs, "finished", "", 64)
i_fin_key   = Expand-Label(i_hs, "finished", "", 64)
```

### 12.3 Resumption Inputs

Only when F3 carries an offer. `res` is a stored 64-byte resumption secret
(§15.1).

```
binder_key  = Expand-Label(res, "res binder", "", 64)
binder      = HMAC-SHA512(binder_key, TH_iid)
psk         = Expand-Label(res, "res psk", "", 64)
```

### 12.4 Master Secret and Session Secrets

```
psk_in      = psk if status == RESUMED else zeros
master      = HKDF-Extract(salt = Expand-Label(hs, "derived", "", 64),
                           IKM  = psk_in)
c_fin_key   = Expand-Label(master, "r confirm", "", 64)

// after TH_final:
i_ap        = Derive-Secret(master, "i ap traffic", TH_final)
r_ap        = Derive-Secret(master, "r ap traffic", TH_final)
i_ap_key    = Expand-Label(i_ap, "key", "", 32)   // initiator->responder
r_ap_key    = Expand-Label(r_ap, "key", "", 32)   // responder->initiator
exp_master  = Derive-Secret(master, "exp master", TH_final)
res_next    = Derive-Secret(master, "res master", TH_final)
sid_bytes   = Derive-Secret(master, "session id", TH_final)[0:15]
```

On REJECTED the initiator derives `master` with `psk_in = zeros` only to
check `finished_C`; nothing after it is derived.

Session ID:

- Cold: `base32.StdEncoding.EncodeToString(sid_bytes)`, 24 characters of
  `[A-Z2-7]` with no padding (120 bits): the same alphabet and length as
  today.
- Resumed: the `resume_sid` that was offered and accepted.

The session ID is never sent in the clear. It appears only in frame 0x04,
and only on a resume offer.

### 12.5 Exporter

```
ExportKeyingMaterial(label, context, L) =
    Expand-Label( Expand-Label(exp_master, label, "", 64),
                  "exporter", SHA-512(context), L )
```

The inner call passes an empty context where RFC 8446 passes `Hash("")`;
this is deliberate, and the test vectors pin it. `label` must be 1 to 200
bytes and `L` 1 to 16320 (255 × 64); otherwise the call returns
`ErrInvalidExport` (new). A nil and an empty `context` are the same.
`t.exporter` is read and zeroized under `t.mu`; after `Close`, `CloseAbort`
or termination the call returns `ErrConnClosed`.

### 12.6 Label Table

Through Expand-Label (prefix `kamune2 `): `r hs traffic`, `i hs traffic`,
`key`, `finished`, `derived`, `res binder`, `res psk`, `r confirm`,
`i ap traffic`, `r ap traffic`, `exp master`, `res master`, `session id`,
`exporter`, and the exporter labels that callers supply.

Outside Expand-Label: `kamune/2 transcript` (§11), `kamune/2 kex` and
`kamune/2 kex secret` (§12.1), `kamune/2 hs` (AEAD AD, §10.4), and the
signature contexts of §13.1. The future contact-only mode would add the
`PairSecret` salt `kamune/2 contact tag` (§25.1).

Across the rework (RFC008 to RFC011) no domain string is used for two
purposes: repeated short labels such as `derived` and `key` appear only
behind different prefixes or under different secrets, as in TLS 1.3.

## 13. Authentication

### 13.1 Signatures

In the style of TLS 1.3 `CertificateVerify`:

```
sig_R = Ed25519.Sign(sk_R, "kamune/2 responder signature" || 0x00 || TH_rid)
sig_I = Ed25519.Sign(sk_I, "kamune/2 initiator signature" || 0x00 || TH_ibind)
```

The two context strings differ, so a responder signature cannot be reflected
as an initiator signature. `TH_rid` covers both hellos and the responder's
key. `TH_ibind` also covers everything the responder sent, the initiator's
own identity block and the binder. Each party signs its own identity
together with both ephemeral contributions (SIGMA identity binding).

### 13.2 Finished MACs

```
finished_R = HMAC-SHA512(r_fin_key, TH_rsig)
finished_I = HMAC-SHA512(i_fin_key, TH_isig)
finished_C = HMAC-SHA512(c_fin_key, TH_cbody)
```

All comparisons use `hmac.Equal`. `finished_R` and `finished_I` prove that
each side holds the KEM secret for this transcript: the key confirmation the
Challenge was meant to give (KAM-27). `finished_C` proves the responder
derived the same `master`, including the PSK, and authenticates `name_R` and
`version_R`: only the party that ran the encapsulation, which signed
`TH_rid`, holds `master`.

### 13.3 Checks on Receipt

Initiator, on F2b, in this order; any failure aborts with nothing sent:

1. `key_R` layout and `IsValidPublicKey` (`ErrInvalidHandshake`).
2. `key_R` differs from the local PKIX key (`ErrSelfConnection`, new).
3. Pin: with `DialWithPeerKey(k)` or a resume offer, `key_R` must equal the
   pin byte for byte (`ErrPeerKeyMismatch`).
4. `sig_R` verifies (`ErrInvalidSignature`), then `finished_R`
   (`ErrVerificationFailed`).

   4a. If the `Conn` implements `PeerConstraint` (RFC010, root
   `peerconstraint.go`), `AllowPeer(key_R)` must return true, else
   `ErrPeerKeyMismatch`. Nothing has been sent, so SIGMA-I identity
   protection holds. When it ran and passed, `Pinned` is true.
5. The verifier runs (§16).

Responder, on F3, in this order:

1. Layout, `IsValidPublicKey`, `ValidatePeerName(name_I)`
   (`ErrInvalidPeerName`); `version_I` parses (`ErrInvalidHandshake`).
2. `key_I` differs from the local key (`ErrSelfConnection`).
3. `sig_I` verifies (`ErrInvalidSignature`), then `finished_I`
   (`ErrVerificationFailed`). From here on the connection is authenticated
   (§14.4).

   3a. If the `Conn` implements `PeerConstraint`, `AllowPeer(key_I)` must
   return true; otherwise close without a Confirm and return
   `ErrPeerKeyMismatch`. When it ran and passed, the responder's
   `VerifyRequest.Pinned` is true.
4. `checkVersion(local, version_I)`; on a mismatch send
   `Confirm{REJECTED, VERSION}` and return `ErrVersionMismatch`.
5. The resume decision (§15.3), then the verifier (§16).

Initiator, on F4:

1. Layout; `finished_C` verifies (`ErrVerificationFailed`).
2. REJECTED: return `ErrHandshakeRejected` (VERIFIER) or
   `fmt.Errorf("%w: %w", ErrHandshakeRejected, ErrVersionMismatch)`
   (VERSION).
3. RESUMED without an offer: `ErrInvalidHandshake`.
4. `ValidatePeerName(name_R)`, then `checkVersion(local, version_R)`. A
   mismatch closes the connection and returns `ErrVersionMismatch`. The
   responder has established by then and sees `ErrConnClosed`; both sides
   check versions by the same symmetric rule, so this happens only when a
   responder skips its own check.

### 13.4 Signature-Context Registry

New file `pkg/attest/contexts.go` lists every context string signed with an
identity key:

```go
const (
	ContextResponderHandshake = "kamune/2 responder signature\x00"
	ContextInitiatorHandshake = "kamune/2 initiator signature\x00"
	ContextTransportFrame     = "kamune/transport-sign/v1"
)

// Contexts returns every registered signing context.
func Contexts() []string
```

`TestContexts_PrefixFree` asserts that no context is a prefix of another.
Any later protocol that signs with an identity key adds its context here;
RFC008 to RFC011 sign nothing with it. `serde.go`, which uses
the same string as `transportSignInfo` today, and the handshake use the
constants.

## 14. State Machines

### 14.1 Initiator

```
I_START
  if offering: acquire the resume lock (§15.4) or return ErrResumeInProgress
  generate X-Wing key pair (sk_i, pk_i), nonce_i, tag (random)
  send ClientHello                                     -> I_WAIT_SH
  deadline: now + handshakeTimeout (30 s)

I_WAIT_SH
  recv; check length, ver, type (§10.1)
  NewRecipient error -> ErrVerificationFailed
  derive hs keys                                       -> I_WAIT_RA

I_WAIT_RA
  recv frame 0x03; checks 1-4 (§13.3)
  run verifier (Role=Initiator, Pinned, ResumeOffered, SessionID)
      deadline lifted to verifyTimeout while it runs (ctx, §16)
      on reject: close, return ErrVerificationFailed (nothing sent)
  build InitiatorAuth (identity, binder if offering, sig_I, finished_I)
  send frame 0x04                                      -> I_WAIT_CONFIRM
  deadline: now + handshakeTimeout + verifyTimeout (responder may prompt)

I_WAIT_CONFIRM
  recv frame 0x05; checks 1-4 (§13.3)
  COLD after an offer with DialWithResumeOnly:
      close, keep stored state, return ErrResumeRefused
  derive app keys, exporter, res_next, session ID
  commit resumption state (§15.4); on storage error: log, continue
  release the resume lock
  clear deadline; return Transport                     -> I_ESTABLISHED
```

Every exit path releases the resume lock (defer).

### 14.2 Responder

```
R_START (accepted conn, stage "waiting", §14.4)
  deadline: now + introTimeout (10 s)
  recv; check length, ver, type; parse pk_i
  NewSender error -> close, ErrInvalidHandshake
  enc, ss = Encap(pk_i); derive hs keys
  move p to stage "hello" (§14.4); if dropped -> close
  send ServerHello, then ResponderAuth (key_R, sig_R, finished_R)
  deadline: now + handshakeTimeout + verifyTimeout     -> R_WAIT_IA

R_WAIT_IA
  recv frame 0x04; AEAD-open with i_hs_key
  checks 1-3 (§13.3)
  mark p authenticated (§14.4); if dropped or over the per-source cap
      -> close
  check 4: version mismatch -> send REJECTED(VERSION), close
  resume decision (§15.3): read state now, compare binders
  run verifier (Role=Responder, Resumed, SessionID if resumed)
  on reject: send Confirm{REJECTED, VERIFIER}; if resumed,
      DeleteResumption(sid, responder, g); close; return ErrVerificationFailed
  derive master, finished_C, app keys, res_next, session ID
  if server closed: close without Confirm, return ErrClosedServer
  commit resumption state (§15.4) BEFORE sending Confirm
      CAS conflict -> close without Confirm
      other storage error -> log; send Confirm; session not resumable
  send Confirm{COLD|RESUMED, name_R, version_R}         -> R_ESTABLISHED
  clear deadline; hand Transport to handler
```

### 14.3 Errors and Peer-Visible Behavior

| Condition                                                                   | Side       | Peer sees                       | Error returned locally                                  |
| --------------------------------------------------------------------------- | ---------- | ------------------------------- | ------------------------------------------------------- |
| Wrong `ver`                                                                 | either     | close                           | `ErrUnsupportedProtocol`                                |
| Wrong length, `type`, layout, non-zero padding, low-order X25519 in `pk_i`  | either     | close                           | `ErrInvalidHandshake` (wrapped detail)                  |
| AEAD open fails, low-order X25519 in `enc`                                  | either     | close                           | `ErrVerificationFailed`                                 |
| Self connection                                                             | either     | close                           | `ErrSelfConnection`                                     |
| Pin mismatch                                                                | I          | close after F2                  | `ErrPeerKeyMismatch`                                    |
| `PeerConstraint` rejects the authenticated key                              | either     | close (no F3, no Confirm)       | `ErrPeerKeyMismatch`                                    |
| Bad signature                                                               | either     | close                           | `ErrInvalidSignature`                                   |
| Bad Finished                                                                | either     | close                           | `ErrVerificationFailed`                                 |
| Binder does not match                                                       | R          | `Confirm{COLD}`                 | none (not an error)                                     |
| Bad name                                                                    | either     | close                           | `ErrInvalidPeerName`                                    |
| Version mismatch                                                            | R          | `Confirm{REJECTED, VERSION}`    | `ErrVersionMismatch`                                    |
| Version mismatch                                                            | I (at F4)  | close                           | `ErrVersionMismatch`                                    |
| Verifier rejects                                                            | I          | close                           | `ErrVerificationFailed` (wraps the verifier's error)    |
| Verifier rejects                                                            | R          | `Confirm{REJECTED, VERIFIER}`   | `ErrVerificationFailed`                                 |
| Confirm REJECTED, VERIFIER                                                  | I          | n/a                             | `ErrHandshakeRejected`                                  |
| Confirm REJECTED, VERSION                                                   | I          | n/a                             | `ErrHandshakeRejected` wrapping `ErrVersionMismatch`    |
| Offer answered COLD, `DialWithResumeOnly`                                   | I          | close                           | `ErrResumeRefused`                                      |
| Second resume of a session in progress                                      | I          | nothing sent                    | `ErrResumeInProgress`                                   |
| Deadline or context end                                                     | either     | close                           | wrapped timeout or `ctx.Err()`                          |

The responder sends nothing before the initiator is authenticated except F2
(its key, §8.3), and never a cleartext or unauthenticated rejection.

### 14.4 Server Admission Stages

Today a `pendingConn` is "waiting" until `introduced`, then non-evictable.
This RFC has three stages:

| Stage         | Entered                               | Bounded by                                                | Eviction                                         | Deadline                                                                                   |
| ------------- | ------------------------------------- | --------------------------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| waiting       | accept (`admit`)                      | `maxPending` (default 256)                                | `dropCandidate` among waiting conns              | `introTimeout` (10 s) to a valid ClientHello                                               |
| hello         | valid ClientHello, before Encap       | `maxPending` (a second, separate list of the same size)  | `dropCandidate` among hello conns only           | `handshakeTimeout + verifyTimeout` (180 s): the initiator's user may be comparing codes     |
| authenticated | `sig_I` and `finished_I` verified     | per-source cap (16) for conns with a source               | not evictable                                    | the responder verifier's limit, then the handshake timeout                                 |

Rules:

- A connection never becomes non-evictable before it has proved key
  possession over this transcript. A flood of ClientHellos can only evict
  other hello-stage connections, and `dropCandidate` picks from the networks
  with the most entries, so a flood from a few networks mostly evicts
  itself, as today's waiting list does.
- A real dialer in the hello stage does not compete with pre-ClientHello
  connections.
- The per-source cap is counted where it is today, at `admit`, for
  connections with a non-forgeable source. Connections with a forgeable
  source are counted on entering "authenticated", where `introduced` counts
  them today. This RFC does not edit `forgeable`: before RFC008 lands it
  means "UDP address"; after RFC008 it means "conn without
  `ReturnRoutable`", so path-layer conns count at `admit` and only
  third-party conns use the second rule.
- Relay-accepted connections have no source. A `RelayListener` yields one
  connection per registration and later `Accept` calls return
  `net.ErrClosed` (its doc comment in `pkg/relayconn/listener.go`), so a
  relay cannot multiply handshakes against one listener registration.
- RFC008's `ServeWithHandshakeRate` runs in `admit`, before any stage.
- Logging in `ListenAndServe` keys on `p.authenticated`: Debug for any
  failure before authentication (scanners, pin rejections at the
  initiator), Error after.

Implementation: replace `waiting []*pendingConn` and `networks
map[string]int` with a `stage` struct holding those two fields and the
methods `add`, `remove` and `dropCandidate` (today's `dropCandidateLocked`
body). `Server` holds `waiting, hello stage`. `introduced(p)` is split into
`helloReceived(p) error` (moves p from waiting to hello, may evict) and
`authenticated(p) error` (removes p from hello, counts a forgeable source,
sets `p.authenticated`). `wasIntroduced` becomes `wasAuthenticated`.
`ServeWithMaxPendingHandshakes(n)` sets the cap of both stages.
`ServeWithIntroTimeout` bounds "accept to ClientHello". The doc comments of
these options change accordingly.

DoS accounting: each hello-stage connection costs the listener one X-Wing
encapsulation, one Ed25519 signature, a goroutine and about 3 KB until it is
evicted or times out, bounded by 256 per listener plus RFC008's per-source
rate.

## 15. Resumption

### 15.1 Stored State

A new message in `internal/box/model.proto`, stored with `PutEncrypted` in
the session's meta namespace under `"resumption_i"` (initiator role) or
`"resumption_r"` (responder role). A store shared by both ends of a
connection (tests, or a process dialing itself under different identities)
keeps both rows apart.

```proto
message ResumptionState {
  uint64 Generation          = 1; // >= 1; local only
  bytes  Current             = 2; // 64-byte res secret
  bytes  Previous            = 3; // 64 bytes or empty; responder only
  bytes  PeerPublicKey       = 4; // PKIX key authenticated for this session
  int64  ColdAtUnixNano      = 5; // last cold handshake of this session
  int64  RefreshedAtUnixNano = 6; // last handshake or transport end (§15.5)
  ResumeRole Role            = 7; // must match the meta key it is stored under
}
enum ResumeRole {
  RESUME_ROLE_INVALID   = 0;
  RESUME_ROLE_INITIATOR = 1;
  RESUME_ROLE_RESPONDER = 2;
}
```

Only an initiator row may be offered, and only a responder row may be
accepted (the asymmetry of SPEC §6.8.4, and the TLS 1.3 "Selfie" guard).

Removed: the `resumption_tokens` meta key (a value left in an old store is
ignored), the 20-token set, the resumption root, `PutSessionResumption`,
`PopList`, `RemoveListItem`, `DeleteListIfContains` and `GetList`. These
have no other callers after the switch except the clients' `relayResumable`
(§20.1); the implementer greps and keeps any that remain in use. `GetMeta`,
`SetMeta`, `GetPeer(sessionID)` and the `PeerKey` and `established_at` metas
stay; `established_at` is written on every cold establishment, and
`pruneIdleSessions` keeps using it.

### 15.2 Initiator Offer

`DialWithResume(sessionID)`:

1. `NewDialer` fails with `ErrNoResumptionState` when the store has no
   initiator row for `sessionID`, and with an error when the option is
   combined with `DialWithoutPersistence`.
2. `Dial` acquires the resume lock (§15.4), then reads the row again. No
   row: `ErrNoResumptionState`. `DialWithPeerKey(k)` with `k` different from
   `PeerPublicKey`: `ErrPeerKeyMismatch`. If `store.FindPeer(PeerPublicKey)`
   fails (deleted or expired peer), delete the row
   (`DeleteResumption(sid, initiator, g')`) and return
   `ErrNoResumptionState`.
3. The pin becomes `PeerPublicKey`; `resume_sid = sessionID`;
   `binder = HMAC(binder_key(Current), TH_iid)`. There is no local window
   pre-check: the responder decides, and an expired offer costs it one HMAC.

`DialWithResumeOnly()` (new, used with `DialWithResume`): when the answer to
the offer is COLD, the initiator closes and returns `ErrResumeRefused`
instead of establishing a new session, and keeps its row. A session that
does resume under this option is authenticated by the PSK as well as by the
signatures (§8.4). No client sets it by default.

### 15.3 Responder Decision

Only after `sig_I` and `finished_I` have verified, the responder reads the
responder row for `resume_sid` (if an offer is present) and computes:

```
okCurrent  = state found
             && hmac.Equal(binder, HMAC(binder_key(Current), TH_iid))
okPrevious = state found && len(Previous) == 64
             && hmac.Equal(binder, HMAC(binder_key(Previous), TH_iid))
peerStored = store.FindPeer(key_I) succeeds (stored and not expired)

resumed = offer present
       && resumeEnabled && !noPersistence
       && state found && state.Role == RESPONDER
       && bytes.Equal(state.PeerPublicKey, key_I)
       && peerStored
       && now - state.RefreshedAt <= resumeIdle
       && now - state.ColdAt      <= resumeMaxAge
       && (okCurrent || okPrevious)
used   = Current if okCurrent else Previous
```

There are no dummy candidates: only an authenticated peer sees the outcome,
and it learns it from the Confirm anyway. When `resumed` is false, for
whatever reason, the handshake continues as a cold one.

`peerStored` keeps today's revocation: `DeletePeer` or peer expiry stops
resumption, as `handleResume` does now through `GetPeer(sessionID)`.
Incognito sessions, whose peers the clients never store, stay
non-resumable.

### 15.4 Commit Rules

| Event                                                | Responder writes                                                                                                                        | Initiator writes                                                                                                                       |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Cold established                                     | `SwapResumption(newSid, 0, {Gen 1, Current res_next, Previous ∅, Peer key_I, ColdAt now, RefreshedAt now, RESPONDER})` before sending Confirm | `SwapResumption(newSid, 0, {Gen 1, Current res_next, Peer key_R, ColdAt now, RefreshedAt now, INITIATOR})` after verifying `finished_C` |
| Resumed (responder read gen g, initiator gen g')     | `SwapResumption(sid, g, {Gen g+1, Current res_next, Previous used, Peer, ColdAt, RefreshedAt now, RESPONDER})` before sending Confirm      | `SwapResumption(sid, g', {Gen g'+1, Current res_next, Peer, ColdAt, RefreshedAt now, INITIATOR})`                                      |
| Offer answered COLD                                  | nothing for the old sid                                                                                                                 | `DeleteResumption(oldSid, initiator, g')`, then the cold row (not with `DialWithResumeOnly`)                                          |
| Verifier rejects a resumed peer                      | `DeleteResumption(sid, responder, g)`                                                                                                   | `DeleteResumption(sid, initiator, g')` on REJECTED                                                                                     |
| Session ends (§18.3)                                 | delete or touch                                                                                                                         | delete or touch                                                                                                                        |
| Initiator CAS conflict                               | n/a                                                                                                                                     | read the row again and `DeleteResumption(sid, initiator, readGen)`, so the next dial is a clean cold one                              |

`SwapResumption` replaces the whole record: the caller copies `PeerKey`,
`ColdAt` and `Role` from the record it read. `g` and `g'` need not be equal.

**Why this cannot desynchronize (KAM-15).** The responder commits before it
sends Confirm, and the initiator commits only after it has verified Confirm:

- Confirm never written (crash or CAS conflict before sending): if the
  responder committed, the initiator's `Current` is now the responder's
  `Previous`; if not, nothing changed.
- Confirm written but lost: the responder holds (`res_next`, `used`), the
  initiator holds `used`. The next offer matches `Previous`, and the
  responder stores (`res_next'`, `used`).
- Confirm received: both hold `res_next`.

The initiator's `Current` is always in the responder's `{Current,
Previous}`, provided one initiator resumes the session at a time, which the
lock below guarantees.

**Resume lock.** A package-level `resumeLocks` map keyed by
`(*storage.Storage, sessionID)` holds a mutex per session being resumed.
`Dial` takes it with `TryLock` before reading the initiator row and keeps it
until the initiator's commit or failure. A second `Dial` of the same session
while one is in progress returns `ErrResumeInProgress` at once. Bolt locks
the database file (`internal/engine/lock_unix.go`), so one process owns a
store and an in-process lock covers every real case. The responder's CAS
stays as the backstop against a copied store.

**Generation tagging.** A `Transport` records the generation it committed
(`resGen`) and its role. Its deletions and touches act only if the stored
generation still equals `resGen`, so a stale transport whose session has
been resumed elsewhere leaves the newer state alone.

**Cost of accepting `Previous`.** A secret stolen from storage stays usable
for one extra resume. Every resume still needs the identity key and a fresh
KEM.

### 15.5 Resumption Window

This section closes KAM-28.

- `resumeIdle` = 24 h from `RefreshedAt`. `RefreshedAt` moves on every
  successful handshake of the session, and when a transport ends without
  deleting state (drop, `CloseAbort`, or a keep-state termination, §18.3),
  through `TouchResumption`. A session that stayed connected for days and
  then dropped can therefore resume within 24 h of the drop.
- `resumeMaxAge` = 7 days from `ColdAt`, the last cold handshake. Resumes and
  touches do not move it.
- Constants only (`defaultResumeIdle`, `defaultResumeMaxAge`); tests move
  time with `ServeWithClock`. No option until a client needs one.
- The responder's values decide. The initiator does not pre-check.

A crash leaves `RefreshedAt` at the last handshake; that only shortens the
window.

### 15.6 Persistence and Resumption Off

- `ServeWithoutPersistence`: the server writes no resumption state and
  never accepts an offer. (Today it still resumes a session stored earlier.)
- `DialWithoutPersistence`: the dialer writes no state; combining it with
  `DialWithResume` is an error at `NewDialer`.
- `ServeWithResumeEnabled(false)`: every offer falls back to COLD. Its doc
  comment names both ways to stop resumption: this option for every peer,
  and `DeletePeer` for one peer. It no longer says that resumed sessions
  skip the verifier.

### 15.7 Sweep

`Storage.SweepSessions(now, idle, maxAge)` runs in one bolt transaction:

1. Delete every resumption row (`resumption_i`, `resumption_r`) with
   `now - RefreshedAt > idle` or `now - ColdAt > maxAge`.
2. Delete every session namespace that then has no resumption row, an empty
   chat namespace, no session name, and an `established_at` older than
   `maxAge` (or no `established_at`). This is the "idle" definition of
   `pruneIdleSessions` plus an age bound, so live and named sessions are
   kept.

A `Server` with persistence runs it at `ListenAndServe` start and every hour
(a ticker goroutine stopped by `Close`, using `s.clock`). Dial-only
applications may call it themselves. This bounds the rows an AutoAccept
listener accumulates from fresh keys whose Confirm was dropped, whatever
keys the dialers use.

## 16. Verifier Policy

This section covers KAM-08, KAM-01 and KAM-07.

```go
// Role is the side of the handshake the local endpoint plays.
type Role uint8

const (
	RoleInitiator Role = iota + 1
	RoleResponder
)

// VerifyRequest describes an authenticated peer to a RemoteVerifier.
type VerifyRequest struct {
	// Peer has proved, in this handshake, possession of Peer.PublicKey
	// over the full transcript. On the responder, Name and AppVersion
	// are the initiator's claims. On the initiator they are empty: the
	// responder sends them only after it has accepted the initiator.
	Peer *storage.Peer
	// LocalPublicKey is this endpoint's PKIX identity key.
	LocalPublicKey []byte
	// SessionID is the session offered (initiator, ResumeOffered) or
	// being resumed (responder, Resumed), else "".
	SessionID string
	Role      Role
	// Pinned: on the initiator, the peer key matched DialWithPeerKey or
	// the stored key of the session offered for resumption, or the Conn's
	// PeerConstraint allowed it; on the responder, the Conn implements
	// PeerConstraint and allowed it (pair rendezvous, RFC010).
	Pinned bool
	// ResumeOffered (initiator only): the initiator will offer to
	// resume SessionID. The responder may still answer with a cold
	// session; see Transport.Resumed.
	ResumeOffered bool
	// Resumed (responder only): the initiator proved valid resumption
	// state for SessionID, its key is still a stored peer, and the
	// session will resume if the verifier accepts.
	Resumed bool
}

// RemoteVerifier decides whether to accept an authenticated peer. It runs
// exactly once per handshake on each side, cold and resumed alike, after
// the peer is authenticated and before the local side sends its next
// message. ctx carries the verify deadline and is cancelled when the
// Server closes or the Dial context ends. A nil error accepts; a nil
// return after ctx is done is treated as a rejection.
type RemoteVerifier func(
	ctx context.Context, store *storage.Storage, req VerifyRequest,
) error
```

Rules:

- The library runs the verifier for resumed sessions too; there is no skip
  path.
- The verifier sees only authenticated peers. The session can still fail
  afterwards, so clients store peers after `Dial` returns and in the server
  handler, from `t.RemotePeer()`, which carries the name and version on both
  sides (§20).
- Deadlines: `ctx = context.WithTimeout(base, verifyTimeout)`, where `base`
  is the `DialContext` context or the server's base context. `NewServer`
  creates `s.ctx, s.cancel`; `Close` calls `s.cancel()` next to
  `close(s.done)`. The connection deadline is lifted for the verifier and
  restored after, as `verifyPeer` does today. A late accept after `ctx` is
  done is a rejection (`TestLateVerifierAcceptIsRejected`, the KAM-07
  regression test, is kept).
- `DialContext(ctx)`: TCP uses `net.Dialer.DialContext`; once a `Conn` is
  open (also one from `DialWithFunc`), `context.AfterFunc(ctx, func() {
  cn.Close() })` ends the handshake when `ctx` ends, as `dialBound` in
  `cmd/tui/client.go` does today. The error wraps `ctx.Err()`.
  `DialWithFunc` keeps its signature.

### 16.1 Mode Semantics

Implemented in each client (§20):

| Mode       | Initiator                                                                                                                                                                                                                         | Responder                                                                                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Strict     | prompt, except `Pinned && ResumeOffered` (an automatic reconnect to a key the user already approved; the key cannot change)                                                                                                       | prompt on every handshake; `Resumed` shows a "reconnecting session" banner                                                                                       |
| Quick      | accept when `Pinned`; otherwise prompt. When the unpinned key is a stored peer, the prompt says "you reached <stored name>", so a splice to another known peer is visible                                                         | accept when `Resumed`, when `Pinned` (a pair-rendezvous conn admitted the key) or when the key is a stored, unexpired peer; otherwise prompt                       |
| AutoAccept | accept (no identity protection for unpinned dials, §8.2)                                                                                                                                                                          | accept                                                                                                                                                            |

A Strict initiator whose pinned offer is answered COLD gets no prompt: the
key is the approved one. The client treats the result as a new session
(§20.1).

## 17. Verification Codes and Fingerprints

This section covers KAM-03 and KAM-26.

### 17.1 Verification Codes

Prompts show two labelled lines, each a full `fingerprint.Numeric` (eight
groups of five digits, 132.9 bits, SHA-512 over the PKIX key; unchanged,
vectors kept):

```
Your code:      12345 67890 12345 67890 12345 67890 12345 67890
<peer>'s code:  09876 54321 09876 54321 09876 54321 09876 54321
Read your code to your contact and have them read theirs. Every digit
of both codes must match.
```

The lines are labelled rather than sorted, so an attacker cannot choose
which line users read first, and each user checks the other's code against
what the other reads out of their own device. An attacker in the middle
needs a second preimage of a 40-digit code (about 2^132.9 work).

```go
// SafetyNumber returns the pairwise code: the Numeric fingerprints of both
// PKIX keys, the bytewise-smaller key first, joined by "\n". Both peers
// compute the same string. For copy and paste, not for reading aloud.
func SafetyNumber(a, b []byte) string
```

A short authentication string over the transcript is not used: a man in the
middle picks `enc` after seeing `pk_i` and could grind a short string in
real time, and a commitment would cost a round trip. Key fingerprints bind
what the signatures prove.

### 17.2 Other Forms

Changes are limited to verification surfaces:

| Function               | Change                                                                                                                                                                         |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Numeric`              | Unchanged. The default of the daemon and bus fingerprint-format settings.                                                                                                     |
| `Emoji`                | Unchanged output and vectors. Removed from every verification prompt and verify event. Other uses (peer lists, share card, settings) stay until a later UI item (§25, §27).  |
| `Hex`, `Sum`, `Base64` | Unchanged; removed from verify prompts.                                                                                                                                       |
| `Pseudonym`            | Unchanged. Verify prompts label it "nickname" and show the peer's `Name` only as "name it gives itself", outside the code area (KAM-26).                                      |

## 18. Transport After the Handshake

### 18.1 Keys and Framing

The initiator's encoder uses `i_ap_key` and its decoder `r_ap_key`; the
responder the reverse; both through `enigma.NewFromKey`. Frames are
unchanged: `SignedTransport` with Ed25519 per-frame signatures, bucketed
padding, XChaCha20-Poly1305 with random nonces, strict sequence numbers.
**The first session frame is sequence 1**: no challenge frames precede it.

Fields removed from `Transport`: `resumptionRoot`, `tokens`, `established`.
Added: `resGen uint64`, `resRole storage.ResumeRole`, `exporter []byte`
(`exp_master`, zeroized under `t.mu` when the transport ends) and `resumed
bool`.

### 18.2 Routes

`Route` keeps `RouteInvalid`, `RouteExchangeMessages`, `RouteCloseTransport`,
`RoutePing`, `RoutePong` and `RouteSessionData`. The proto enum reserves the
numbers and names of `IDENTITY`, `REQUEST_HANDSHAKE`, `ACCEPT_HANDSHAKE`,
`FINALIZE_HANDSHAKE`, `SEND_CHALLENGE`, `VERIFY_CHALLENGE`, `RESUME_REQUEST`
and `RESUME_ACCEPT` (`reserved 1 to 6, 11, 12;`). The kept numbers are 0
INVALID, 7 EXCHANGE_MESSAGES, 8 CLOSE_TRANSPORT, 9 PING, 10 PONG and 13
SESSION_DATA. `isChallengeRoute` and `established` go away; `checkRoute`
accepts only session routes.

### 18.3 What Ends Resumability

Today the first `terminate` deletes the tokens, so one injected garbage
frame, or one replayed frame (session frames carry no sequence number in the
AEAD AD), makes the next reconnect cold. Under this RFC, state is deleted
only on events that the authenticated peer or the local user caused:

| Event                                                                                         | Who can cause it                                        | State                  |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------- | ---------------------- |
| Local `Close()`                                                                               | local user                                              | delete (`resGen`)      |
| Received `RouteCloseTransport` (AEAD and signature valid, in sequence)                        | the peer                                                | delete                 |
| AEAD-valid frame whose inner signature fails, or whose route fails `checkRoute`               | only a holder of the traffic key: the peer              | delete, terminate      |
| AEAD failure                                                                                  | anyone on the path                                      | terminate, keep, touch |
| Duplicate sequence (replay) or gap (dropped frame)                                            | anyone on the path, including the relay                 | terminate, keep, touch |
| Connection drop (`ErrConnClosed`), `CloseAbort()`                                             | network, local                                          | keep, touch            |

"Touch" is `TouchResumption(sid, role, resGen, now)` (§15.5). A gap is
treated as network-caused because a relay can drop a single frame.

`terminate(err)` gains a `keepState bool` argument; the doc comments of
`Close` and `terminate` change accordingly.

## 19. Go API Changes

### 19.1 Root Package `kamune`

Added:

```go
func DialWithPeerKey(pub []byte) DialOption   // PKIX; IsValidPublicKey or error
func DialWithResumeOnly() DialOption
func (d *Dialer) DialContext(ctx context.Context) (*Transport, error)
func (t *Transport) Resumed() bool
func (t *Transport) ExportKeyingMaterial(
	label string, context []byte, length int,
) ([]byte, error)
type Role uint8; const RoleInitiator, RoleResponder
type VerifyRequest struct { ... }              // §16
// From RFC010's commit (root peerconstraint.go), called by §13.3 4a and 3a:
type PeerConstraint interface { AllowPeer(pkix []byte) bool }
func ExpectPeer(c Conn, keys ...[]byte) Conn

var (
	ErrPeerKeyMismatch     = errors.New("peer key does not match the pinned key")
	ErrSelfConnection      = errors.New("peer key is the local key")
	ErrHandshakeRejected   = errors.New("peer rejected the handshake")
	ErrUnsupportedProtocol = errors.New("unsupported protocol version")
	ErrInvalidHandshake    = errors.New("malformed handshake message")
	ErrNoResumptionState   = errors.New("no resumption state for session")
	ErrResumeInProgress    = errors.New("session is being resumed already")
	ErrResumeRefused       = errors.New("peer did not resume the session")
	ErrInvalidExport       = errors.New("invalid exporter label or length")
)
```

`ErrPeerKeyMismatch` is defined by RFC010's commit with the same text; the
switch commit keeps that definition. `kamune.ErrSelfConnection` differs from
`attest.ErrSameKey` and `rendezvous.ErrSamePeer` (RFC010, token derivation),
and `kamune.ErrHandshakeRejected` (peer sent `Confirm{REJECTED}`) differs
from `relayleg.ErrHandshakeRejected` (RFC009, relay leg closed before its
ServerHello).

Changed:

- `RemoteVerifier` signature (§16).
- `DialWithResume(sessionID)`: pins the stored key, offers resumption, and
  falls back to cold unless `DialWithResumeOnly` is set.
  `ErrResumptionRejected` is removed.
- `Dial()` is `DialContext(context.Background())`.
- `ServeWithMaxPendingHandshakes` bounds each pre-authentication stage
  (§14.4).
- `AppVersion` becomes `"0.8.0"` in the switch commit, so logs and share
  info show which peers speak v2. `appVersion()` rejects a value over 32
  bytes.
- Doc comments: `ServeWithResumeEnabled`, `ServeWithoutPersistence`,
  `DialWithoutPersistence`, `ServeWithIntroTimeout`, the pending-cap
  options, `Transport.Close`, `Transport.CloseAbort`, `Transport.RemotePeer`,
  and the `RemoteVerifier` and `DialWithResume` comments that say the
  verifier does not run on resumption.

Removed: `ErrResumptionRejected`; the routes of §18.2; `sendIntroduction`,
`receiveIntroduction`, `sendResumeRequest`, `receiveResumeAccept`,
`sendResumeAccept`, `sendChallenge`, `acceptChallenge`,
`handshakeTranscriptHash`, `deriveChallengeInfo`, `validateHandshakeFields`,
`deriveResumptionTokens`, `setResumptionRoot`, `remainingResumptionTokens`,
`invalidateResumptionTokens`, `handleResume`, `rejectResume`,
`attemptResume`, `routeFromST`, `readSignedTransport`; the constants
`handshakeInfo`, `handshakeC2SInfo`, `handshakeS2CInfo`, `handshakeSaltSize`,
`handshakeChallengeSize`, `resumptionRootInfo`, `resumptionTokenInfo`,
`resumptionTokenCount`, `resumptionTokenSize`, `resumptionGracePeriod`.

New constants: `protocolVersion = 0x02`, the frame types and sizes,
`hsRespAuthPlain = 172`, `hsInitAuthPlain = 384`, `hsConfirmPlain = 192`,
the label strings, `defaultResumeIdle = 24*time.Hour`,
`defaultResumeMaxAge = 7*24*time.Hour`, `sweepInterval = time.Hour`.

File layout (root):

| File                   | Content                                                                             |
| ---------------------- | ----------------------------------------------------------------------------------- |
| `handshake.go`         | `runInitiator`, `runResponder` (§14)                                                |
| `hsframe.go`           | hello and plaintext encode and parse, `sealHS`, `openHS`                            |
| `keyschedule.go`       | `expandLabel`, `deriveSecret`, `schedule`, exporter                                 |
| `transcript.go`        | `transcript` with `add(tag, b)` and `sum()`                                         |
| `resume.go`            | offer, binder, decision, commit, lock, window                                       |
| `verify.go`            | `Role`, `VerifyRequest`, `runVerifier` (replaces `verifyPeer`)                      |
| `name.go`              | `ValidatePeerName` (moved from `intro.go`, which is deleted)                        |
| `admission.go`         | `stage`, `helloReceived`, `authenticated` (moved out of `server.go`)                |
| `dial.go`, `server.go` | state machines wired in; options; `serveConn`; sweep ticker                         |
| `transport.go`         | the changes of §18                                                                  |
| `serde.go`             | uses `attest.ContextTransportFrame`; drops `routeFromST`, `readSignedTransport`     |

### 19.2 `pkg/storage`

```go
var (
	ErrNoResumption       = errors.New("no resumption state")
	ErrResumptionConflict = errors.New("resumption state changed concurrently")
)

type ResumeRole uint8

const (
	ResumeRoleInitiator ResumeRole = iota + 1
	ResumeRoleResponder
)

type Resumption struct {
	Generation  uint64
	Current     []byte
	Previous    []byte
	PeerKey     []byte
	ColdAt      time.Time
	RefreshedAt time.Time
	Role        ResumeRole
}

// GetResumption returns the row of sessionID for role, or ErrNoResumption.
func (s *Storage) GetResumption(
	sessionID string, role ResumeRole,
) (*Resumption, error)

// SwapResumption replaces the row of sessionID for next.Role with next if
// the stored generation equals oldGen; oldGen 0 means no row may exist.
// Otherwise it returns ErrResumptionConflict and writes nothing. It
// replaces the whole record. It creates the session namespace when needed,
// stores the PeerKey meta, sets the peer's LastSeen and, when
// next.Generation == 1, sets established_at and prunes idle sessions with
// the peer (the duties of today's PutSessionResumption).
func (s *Storage) SwapResumption(
	sessionID string, oldGen uint64, next *Resumption,
) error

// DeleteResumption deletes the row of sessionID for role if its generation
// is gen (gen >= 1, else an error). A missing session or row is not an
// error, and the session namespace is never created (KAM-16).
func (s *Storage) DeleteResumption(
	sessionID string, role ResumeRole, gen uint64,
) error

// DeleteResumptionAll deletes both rows of sessionID, whatever their
// generation, without creating the namespace. For explicit user actions.
func (s *Storage) DeleteResumptionAll(sessionID string) error

// TouchResumption sets RefreshedAt of the row to at if its generation is
// gen and at is later. It never creates a namespace or row.
func (s *Storage) TouchResumption(
	sessionID string, role ResumeRole, gen uint64, at time.Time,
) error

// SweepSessions deletes expired resumption rows and the idle sessions they
// leave behind (§15.7). It returns the number of sessions deleted.
func (s *Storage) SweepSessions(
	now time.Time, idle, maxAge time.Duration,
) (int, error)
```

Removed: `PutSessionResumption`, `ResumptionTokensKey`, the list helpers of
§15.1, and `GetEstablishedAt` if no caller remains (two root tests use it;
they move to `GetResumption`).

### 19.3 `pkg/fingerprint`

Adds `SafetyNumber` (§17.1). The package doc says to compare `Numeric`
codes.

### 19.4 `internal/enigma`

```go
// NewFromKey returns an Enigma keyed directly with a 32-byte key.
func NewFromKey(key []byte) (*Enigma, error)
```

### 19.5 `pkg/attest`

`contexts.go` (§13.4). RFC010's `PairSecret` lands in RFC010's commits.

### 19.6 `pkg/exchange`

`mlkem.go` and `mlkem_test.go` are deleted in the switch commit (§7).

## 20. Client Changes

### 20.1 Common to All Three Clients

- Verifier signature `func(ctx, store, req kamune.VerifyRequest) error`. On
  `ctx.Done()`, cancel the open prompt.
- Mode policy exactly as in §16.1.
- Prompt limits: at most one open verification prompt per client. A
  handshake that needs a prompt while one is open is rejected at once with a
  client error (`errVerifierBusy`), logged at Debug. At most 6 prompts per
  rolling minute; beyond that, unknown keys are rejected without a prompt
  until the minute passes, with one Warn log line. These replace today's
  caps: `maxPendingVerifications` is 3 open prompts in the bus
  (`cmd/bus/verifier.go`) and 8 pending inbound verifications in the daemon
  (`cmd/daemon/verifier.go`).
- Name collision (responder side): when an unknown key gives a `Name` that
  equals (`strings.EqualFold`) a stored peer's name, the prompt says "A NEW
  key is using the name of your contact <name>", shows the stored contact's
  code beside the new one, and the default button is Reject.
- The clients already store a peer only after its session is established
  (`rememberPeer` in `cmd/daemon/verifier.go`, `cmd/bus/peers.go` and
  `cmd/tui/tea.go`); that stays, reading `t.RemotePeer()`, which carries the
  name and version on both sides. Verifiers never call `store.StorePeer`.
- Prompts show the two labelled codes (§17.1); no emoji or hex.
- Pass `kamune.DialWithPeerKey(peerKey)` on every dial path that has the
  peer key: a static relay token derived from a peer key, P2P with a known
  peer, a dial from the peer list, RFC010's pair rendezvous paths. Each
  client gets a test that its peer-list dial path sets the pin.
- Reconnect loops (`reconnectSession` in `cmd/daemon/messaging.go` and
  `cmd/bus/messaging.go`), one goroutine per session:
  - Stop without retrying on `ErrVerificationFailed`,
    `ErrHandshakeRejected`, `ErrPeerKeyMismatch`, `ErrSelfConnection`,
    `ErrNoResumptionState`, `ErrVersionMismatch`, `ErrUnsupportedProtocol`,
    `ErrResumeInProgress` and `ErrResumeRefused` (and on RFC009's
    `relayconn.IsRelayTrustError(err)`). Today the daemon's
    `reconnectRetryable` stops on a shorter list that includes
    `kamune.ErrResumptionRejected`, which goes away, and the bus loop
    retries every error up to 10 attempts.
  - On success with `!t.Resumed()`: end the old `liveSession` through the
    existing close path (daemon `EvtSessionClosed`, bus `session-closed`)
    and start a new one through the existing start path
    (`EvtSessionStarted`, bus `session-new`) with `t.SessionID()`. No new
    event and no rekeying of maps; the old session's relay token pool is not
    reused (RFC010 deletes the old session's `relay_reconnect` and stores
    the new root).
- Explicit disconnect: `transport.Close()` deletes the state (§18.3), as the
  bus's `DisconnectSession` and the daemon rely on today. Client code that
  clears resumption state without a transport uses
  `store.DeleteResumptionAll(sessionID)`. `relayResumable`
  (`cmd/daemon/relay.go`, `cmd/bus/relay.go`), which reads
  `ResumptionTokensKey` today, reads the client's row with `GetResumption`.
- "Remove peer" actions keep calling `DeletePeer`, which now also stops
  resumption (§15.3).
- Relay reconnect tokens: once RFC010 lands, the clients call RFC010's
  helper, which uses `t.ExportKeyingMaterial`.
- `kamune.ErrHandshakeRejected` and RFC009's `relayleg.ErrHandshakeRejected`
  are matched by their package-qualified names and map to different codes
  (`handshake_rejected` and `relay_handshake_rejected`).

### 20.2 Daemon

In `cmd/daemon` and `docs/DAEMON.md`:

- `verifier.go`: the new signature and the §16.1 policy. `EvtVerifyPeer`
  payload: `{request_id, role, peer_name, stored_name, name_collision,
  own_code, peer_code, safety_number, known, mode, pinned, resume_offered,
  resumed, session_id}`. `peer_name` is empty on the initiator side. `emoji`,
  `hex` and `numeric` are dropped (`numeric` becomes `peer_code`), and
  `pendingVerification.hex` becomes `peerCode`.
- `network.go`: `DialWithPeerKey` where the command parameters carry a peer
  key; the reconnect behavior of §20.1.
- `daemon.go`: `validFingerprintFormat` already accepts `numeric`; the
  default fingerprint format (`hex` today) becomes `numeric`. Other emoji
  uses (`network.go`, `history.go`) are unchanged by this RFC.
- New error codes of §6.
- `docs/DAEMON.md`: verify event schema, mode table (§16.1), final reconnect
  errors.

### 20.3 Bus

In `cmd/bus`:

- `verifier.go`: the new signature and policy. The `verify-peer` event adds
  `ownCode`, `peerCode`, `safetyNumber`, `storedName`, `nameCollision`,
  `role`, `pinned`, `resumeOffered` and `resumed`, and drops `emoji` and
  `hex`.
- `frontend/src/lib/VerifyDialog.svelte`: the two labelled codes
  (monospace; the copy button copies `safetyNumber`), the read-back text of
  §17.1, the resumed banner and the name-collision warning; the emoji block
  is removed. `models.ts` and `stores.ts` follow the event shape.
- `network.go`: `DialWithPeerKey` when `peerPubB64 != ""`. It takes over the
  check that `pinPeer` (`cmd/bus/verifier.go`) does in the verifier today,
  which runs only after the dialer's Introduce has gone out; the library
  pin runs before the dialer sends its identity. The reconnect behavior of
  §20.1.
- `app.go`: the fingerprint format (`fingerprintFmt`, `hex` today) defaults
  to `numeric`. The emoji uses in `ShareDialog`, `PeerSelect`, `PeersPanel`
  and `peers.go` are unchanged by this RFC.
- `cmd/bus/README.md`: verification section (modes per §16.1, read-back of
  codes).

### 20.4 TUI

In `cmd/tui`:

- `tea.go` `mkVerifier`: the new signature and policy. The verify screen
  shows the two labelled codes, drops `emojiFP` and `hexFP`, and shows
  "Reconnecting session <id>" when `req.Resumed`. The "No verify prompt:
  this session resumes one" notice (`peerNotice`) is removed: the responder
  now prompts on resumes in Strict.
- `client.go`, `relayclient.go`: use `DialContext(att.ctx)` (through
  `dialBound`). The TUI has no peer-key input; it pins only on
  `DialWithResume`, automatically. If RFC010 adds a peer-key field for
  static tokens, that key is passed as the pin.
- Tests: `session_test.go` moves from `PopList(sid, ResumptionTokensKey)`
  to `GetResumption` and `DeleteResumptionAll`; `verify_test.go` expects a
  prompt for a resumed session on the responder; the verifier literals in
  `attempt_test.go`, `receive_test.go`, `relay_test.go`, `session_test.go`
  and `verify_test.go` get the new signature.
- `cmd/tui/README.md`: verify screen.

## 21. Alternatives Not Taken

| Alternative                                                                                   | Reason                                                                                                                                                                                                                                                                                                                         |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| One shared evictable pool until F3                                                            | A real unpinned dialer stays evictable for up to `verifyTimeout` (150 s) while its user compares codes, and a stream of fresh pre-ClientHello connections would evict it. The separate hello stage keeps "nothing non-evictable before authentication", with its own cap, without that regression.                         |
| Marking a connection non-evictable on a well-formed ClientHello                               | It makes connections non-evictable before they have proved anything.                                                                                                                                                                                                                                                           |
| Scheduling the contact-only listener now                                                     | It depends on RFC010's `PairSecret`, adds a server mode with first-contact consequences for users, and the maintainer decided to leave it to a future RFC (§8.3). Its wire field is reserved now.                                                                                                                             |
| Deleting every resumption row in `DeletePeer`'s transaction and on peer expiry                | Peer expiry is lazy (`removeExpiredPeer` runs on read, `pkg/storage/peer.go`), so there is no transaction to hook. The `FindPeer` check in the decision (§15.3) covers deletion and expiry, matches today's tested behavior (`TestResumeSkipsVerifierUntilPeerDeleted`) and keeps `DeletePeer` independent of the session layout. The sweep removes left-over rows. |
| Deleting state on a sequence gap                                                              | A relay can drop a single message and so cause a gap; gaps keep state, like duplicates (§18.3).                                                                                                                                                                                                                                |
| A `VerifyRequest.FellBack` field, or running the initiator's verifier after F4 for resume offers | The initiator's verifier runs before F3 and cannot know the F4 outcome. Moving it after F4 changes the state machine for one case, and the session ID has already gone out in F3 by then. `DialWithResumeOnly` gives post-quantum authentication of resumed sessions, and clients see a fallback through `Transport.Resumed()`. |
| Protobuf plaintexts re-marshalled with `Deterministic: true` and compared                     | Fixed binary layouts are canonical by construction and need no re-marshal check.                                                                                                                                                                                                                                              |
| Absorbing RFC008's path `ChannelBinding()` as a transcript entry                              | End-to-end signatures over a transcript that contains the fresh KEM already defeat a path-layer man in the middle; the gain is DoS-only, and RFC008 defers it. The value exists only on UDP, which would add a transport-dependent entry and test matrix.                                                                     |
| Capping the resumption rows per unknown peer key (for example at 4)                           | An attacker uses a fresh key per handshake, so a per-key cap never triggers. The global sweep (§15.7) bounds growth whatever the keys.                                                                                                                                                                                          |
| QR-code comparison of codes                                                                   | Deferred (§25). The labelled two-code display and the full read-back instruction address prefix comparison now.                                                                                                                                                                                                               |
| Deleting `fingerprint.Emoji` now                                                              | Emoji is used in share cards, peer lists, search, daemon events and the format settings; removing it is a UI item of its own (§27). It leaves every verification surface now, which is what KAM-03 needs.                                                                                                                    |
| A second `Dial` of a session waits for the first                                              | Fail-fast (`ErrResumeInProgress`) is deterministic to test, the clients run one reconnect goroutine per session, and waiting would hold a goroutine across a verifier prompt.                                                                                                                                                  |
| A peer-key input field in the TUI                                                             | The TUI pins on automatic resumes; a peer-key field belongs with RFC010's static-token UI, if RFC010 adds one.                                                                                                                                                                                                                |
| Dummy binder candidates for unknown sessions                                                  | Only an authenticated peer sees the outcome, and it learns it from the Confirm anyway.                                                                                                                                                                                                                                         |
| A window pre-check on the dialer                                                              | The responder's clock and values decide; an expired offer costs the responder one HMAC.                                                                                                                                                                                                                                       |

## 22. Testing Strategy

Unit tests use `a := require.New(t)`, table-driven cases and real
implementations (AGENTS.md). Fault seams: `storage.WithBackend` with a
wrapping `engine.Store` whose `Command` fails on demand, and `kamune.Conn`
wrappers that drop, record or corrupt frames.

### 22.1 Root: Positive

| Test                          | Asserts                                                                                                                                                                                                                                                                                                                   |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TestKeySchedule_Vectors`     | From `sk_i = DeriveKeyPair(seed)` and a recorded `enc`: a fixed `ss` (decapsulation is deterministic), fixed hello and auth bytes, so fixed `TH_*`. Pins every derived value (`r_hs`, `i_hs`, keys, finished, master with and without PSK, `i_ap`, `r_ap`, `exp_master`, `res_next`, session ID, one exporter output). Printed in a new SPEC Appendix A. |
| `TestExpandLabel_Encoding`    | HkdfLabel byte layout; label and context length limits.                                                                                                                                                                                                                                                                  |
| `TestTranscript_Order`        | Entry encoding; changing any entry changes all later `TH_*`.                                                                                                                                                                                                                                                             |
| `TestHSFrame_RoundTrip`       | Each plaintext layout encodes and parses back; sizes 1282, 1154, 214, 426, 234.                                                                                                                                                                                                                                          |
| `TestHandshake_Cold`          | Table over pipe, TCP and KCP: both established, same session ID, `Resumed()` false, first frame sequence 1, each verifier called once with the right `Role` and `Pinned`; the initiator's verifier sees an empty `Name`; `RemotePeer()` has the name on both sides.                                                     |
| `TestHandshake_PinnedDialer`  | Correct `DialWithPeerKey`: the verifier sees `Pinned: true`.                                                                                                                                                                                                                                                            |
| `TestResume_Success`          | Cold, then `DialWithResume`: same session ID, `Resumed()` true on both sides, the responder's verifier sees `Resumed`, the initiator's sees `ResumeOffered`, generations increment, `RefreshedAt` moves, `ColdAt` stays.                                                                                                |
| `TestResume_Chain`            | 5 consecutive resumes succeed (KAM-28).                                                                                                                                                                                                                                                                                  |
| `TestResume_AfterLongSession` | Server clock +30 h while connected, `CloseAbort`, resume succeeds (touch).                                                                                                                                                                                                                                              |
| `TestResumeOnly_Success`      | `DialWithResumeOnly` with valid state resumes.                                                                                                                                                                                                                                                                          |
| `TestExporter`                | Equal on both sides; differs by label, context and session; nil equals empty context; `ErrInvalidExport` for a label of 0 or 201 bytes and a length of 0 or 16321; `ErrConnClosed` after `Close`; concurrent `Export` and `Close` under `-race`.                                                                       |
| `TestSafetyNumber`            | Symmetric, 80 digits, contains both `Numeric` values, smaller key first.                                                                                                                                                                                                                                                |
| `TestContexts_PrefixFree`     | `pkg/attest`: no registered context is a prefix of another.                                                                                                                                                                                                                                                             |

### 22.2 Root: Negative and Adversarial

| Test                                     | Setup                                                                                                                                         | Expected                                                                                                                         |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `TestMITM_SplitKEM`                      | A proxy runs the hellos separately with each side and forwards F2b and F3 bytes re-encrypted (the KAM-02 proof of concept, adapted)           | Dialer: `ErrInvalidSignature` at F2b. The proxy saw no initiator key or name. The server's verifier never runs.                  |
| `TestMITM_OwnKey_Pinned`                 | The proxy answers with its own identity                                                                                                       | `ErrPeerKeyMismatch`; the proxy never receives 0x04.                                                                             |
| `TestMITM_OwnKey_Unpinned_Rejected`      | Same; the dialer's verifier rejects                                                                                                           | `ErrVerificationFailed`; no 0x04 sent.                                                                                           |
| `TestMITM_ProbeResponder`                | The proxy acts as initiator to the real server                                                                                                | The proxy learns the server key only; the recorded frames do not contain the server's name or version.                          |
| `TestQuick_SpliceToOtherKnownPeer`       | An unpinned Quick dial lands on another stored peer (test verifier from the shared client policy helper)                                     | The policy returns "prompt", not accept.                                                                                         |
| `TestReplay_InitiatorAuth`               | Replay F1 and F3 of connection 1 on connection 2                                                                                              | AEAD failure; no verifier call; no state change.                                                                                 |
| `TestReplay_ResponderAuth`               | Feed connection 1's F2 to a dialer on connection 2                                                                                            | AEAD or signature failure.                                                                                                       |
| `TestReplay_ResumeOffer`                 | Replay a captured resume F3                                                                                                                   | Fails; the responder's row is unchanged.                                                                                         |
| `TestResume_RejectUniform`               | Offers: unknown sid, wrong peer key, bad binder, idle expired, max age expired, resume disabled, no-persistence server, initiator-role row only | Each: `Confirm{COLD}`, same frame sizes, new session ID, no dialer error.                                                        |
| `TestResume_DeletedPeerFallsBackToCold`  | The responder deletes the peer, then the dialer resumes; also a peer past `WithExpiryDuration`                                                | COLD (replaces `TestResumeSkipsVerifierUntilPeerDeleted`).                                                                       |
| `TestResume_DialerDeletedPeer`           | The dialer deletes the peer, then `DialWithResume`                                                                                            | `ErrNoResumptionState`; the row is deleted.                                                                                      |
| `TestResume_LostConfirm`                 | A wrapper drops frame 0x05 of a resume                                                                                                        | The dialer errors and keeps g'; the server is at g+1; the next resume succeeds through `Previous`, the one after through `Current`. |
| `TestResume_LostConfirmTwice`            | Drop 0x05 twice                                                                                                                               | The third resume succeeds.                                                                                                       |
| `TestResume_CommitFails`                 | The responder backend's `Command` fails once during the commit                                                                                | Confirm sent, session established; the next offer falls back to COLD without error.                                              |
| `TestResume_CrashAfterCommit`            | The responder's `Conn` wrapper fails the 234-byte Confirm write                                                                               | The lost-Confirm case: the next resume succeeds through `Previous`.                                                              |
| `TestResume_ConcurrentDialsLocked`       | Two `Dial`s of one session; the first blocks in its verifier                                                                                  | The second returns `ErrResumeInProgress` without sending; after the first completes, a resume succeeds.                         |
| `TestResume_StaleClose`                  | Resume S on T2, then `Close` T1                                                                                                               | T2's row survives.                                                                                                               |
| `TestResume_SurvivesInjectedGarbage`     | A wrapper injects a garbage frame into an established session                                                                                 | Receive terminates; the next resume succeeds.                                                                                    |
| `TestResume_SurvivesReplayedFrame`       | A wrapper replays a recorded session frame                                                                                                    | The duplicate sequence terminates; the next resume succeeds.                                                                    |
| `TestResume_SurvivesDroppedFrame`        | A wrapper drops one frame                                                                                                                     | The gap terminates; the next resume succeeds.                                                                                    |
| `TestResume_PeerCloseEndsIt`             | The peer calls `Close`                                                                                                                        | Both rows deleted; the next `DialWithResume` returns `ErrNoResumptionState`.                                                     |
| `TestResume_VerifierRejects`             | The responder's verifier rejects a resumed peer                                                                                               | `ErrHandshakeRejected` at the dialer; rows deleted on both sides.                                                                |
| `TestResume_Window`                      | Server fake clock: idle +24h+1s; max age +7d+1s with resumes in between                                                                       | COLD in both.                                                                                                                    |
| `TestResumeOnly_Refused`                 | `DialWithResumeOnly` against a server with resumption disabled                                                                                | `ErrResumeRefused`; the dialer's row is kept.                                                                                    |
| `TestHandshake_BadHello`                 | Wrong version, type, length; invalid `pk_i`; `pk_i` and `enc` with a low-order X25519 half                                                    | Close without reply; `ErrUnsupportedProtocol`, `ErrInvalidHandshake` or `ErrVerificationFailed` per §14.3.                      |
| `TestHandshake_BadIdentity`              | Small-order key, wrong PKIX prefix, invalid name, version over 32 bytes, sid of length 5, non-zero padding, status 9                          | The matching error per §14.3 (KAM-22 and KAM-23 regressions).                                                                    |
| `TestHandshake_SelfConnection`           | Dialer and server with the same identity                                                                                                      | `ErrSelfConnection` on both sides.                                                                                               |
| `TestHandshake_VersionReject`            | Minor version mismatch                                                                                                                        | Dialer: `ErrHandshakeRejected` wrapping `ErrVersionMismatch`; server: `ErrVersionMismatch`.                                      |
| `TestHandshake_ReflectedSignature`       | Return F2b's fields as F3                                                                                                                     | `ErrInvalidSignature`.                                                                                                           |
| `TestHandshake_Deadlines`                | Server idle after F1; a dialer verifier slower than `verifyTimeout`; `DialContext` cancelled mid-handshake                                    | Timeouts per §14; `ctx.Err()` wrapped.                                                                                           |
| `TestLateVerifierAcceptIsRejected`       | Kept (KAM-07)                                                                                                                                 | As today.                                                                                                                        |
| `TestServer_F1FloodDoesNotBlock`         | 10,000 TCP connections that send F1 and hold, from many /24s; then a real unpinned dialer whose verifier waits 2 s                           | The dialer completes; no flood connection becomes authenticated.                                                                 |
| `TestServer_HelloStageEviction`          | Fill the hello stage; one more F1                                                                                                             | One hello connection evicted per §14.4; waiting connections untouched.                                                           |
| `TestServeConnLogLevel`                  | Rewritten: a failure before and one after authentication                                                                                      | Debug before, Error after.                                                                                                       |
| Fuzz `FuzzParseClientHello`, `FuzzParseServerHello`, `FuzzParseAuthPlain`, `FuzzParseConfirmPlain`, `FuzzServerServe` (raw bytes after a valid F1) | Replace `preauth_fuzz_test.go` and today's `serve_fuzz_test.go`                                       | No panics; no state change on invalid input.                                                                                     |

### 22.3 Storage

`SwapResumption` CAS: success, conflict, create with `oldGen` 0, refusal to
create when a row exists, independence of the two roles.
`DeleteResumption`: matching and non-matching generation, gen 0 is an
error, never recreates a deleted namespace (KAM-16 regression).
`DeleteResumptionAll`. `TouchResumption` acts only on a matching generation
and never creates. `SweepSessions` deletes expired rows and idle unnamed
empty sessions and keeps named, chatting and fresh ones
(`TestStorage_SweepUnconfirmedRows`). The raw bolt file does not contain the
`Current` bytes.

### 22.4 Root Test Migration

| File                                          | Kept unchanged (verifier literal only)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Rewritten                                                                                                                                                                                                                                                                                                                                       | Deleted                                                                                                                                  |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `server_test.go`                              | AcceptedMeta_ReachesHandler, NilStorageIsAnError, ListenAndServeBacksOffOnAcceptErrors, ListenAndServeReturnsOnCloseWhateverAcceptReturns, ListenAndServeDropsWaitingConnAtCap, ListenAndServeCapsPendingPerSource, SourceKey, ListenAndServeLimitsPerSourceByDefault, IdleConnIsClosedAfterIntroTimeout, IdleTCPConnsFromOneHostDoNotBlockDialer, IdleTCPConnsFromManyHostsDoNotBlockDialer, IdleConnsFromOneNetworkDoNotDropDialer, TiedNetworksLoseConnsAtRandom, PendingCapsByTransport, KCPFloodFromManySourcesDoesNotDropDialer (until RFC008 rewrites it), IntroTimeoutOptionRejectsNonPositive, SlowVerifierOutlastsHandshakeDeadline, LateVerifierAcceptIsRejected, VerifyTimeoutOptionsRejectNonPositive, CloseStopsHandshakesInProgress, ShutdownWaitsForHandlers, NewServerFailureLeavesPortFree, ServerClearsHandshakeDeadlineBeforeHandler, WithoutPersistenceLeavesNoSessionRecord | ServerHandshakeDeadlineCoversExchange → ServerHandshakeDeadlineCoversHello; DialPersistsAndResumesSession (`GetResumption`); ClosingReplacedTransportKeepsResumedSession (generation); IntroducedConnIsNotDropped → AuthenticatedConnIsNotDropped; ServeConnLogLevel (authenticated); ResumeSkipsVerifierUntilPeerDeleted → Resume_DeletedPeerFallsBackToCold; ResumeWindowStartsAtColdHandshake → Resume_Window | WithoutPersistenceResumedSessionLosesTokensOnClose (the combination is now an error; replaced by a `NewDialer` error case)                |
| `transport_test.go`                           | ReceivePayload_RoundTrip, the Receive_* drop tests, Receive_ConcurrentCallersKeepSequence, ReceiveValidatesSequenceBeforeClose, ReceiveAdvancesSequenceForClose, ReceiveRejectsInvalidRouteBeforeMutatingMessage, both fuzzers, PadToBucket, FrameBudget, LargestFrameFitsRelayWrapping, CloseIsNotHeldUpByStalledSend                                                                                                                                                                                                                                                              | Receive_FatalFrameTerminatesTransport (§18.3 table); CloseClearsResumptionTokens → CloseDeletesResumption; CloseKeepsTokensOfResumedSession → generation; ReceiveCloseClearsResumptionTokens; CloseClearsTokensWhenCloseFrameFails; CloseDoesNotRecreateSession (`DeleteResumption`); ReceiveRejectsHandshakeRoute and SendRejectsHandshakeRoute (reserved numbers) | ChallengeRoutesBeforeEstablished, SessionRoutesRejectedBeforeEstablished                                                                 |
| `resume_test.go`                              |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                                                 | The whole file (KAM-32: replaced by the §22.2 tests, which drive `Server.serve`)                                                         |
| `handshake_test.go`                           |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | TestHandshake → TestHandshake_Cold                                                                                                                                                                                                                                                                                                             | ValidateHandshakeFields, RequestHandshakeRejectsBadResponder, AcceptHandshakeRejectsBadInitiator                                        |
| `intro_test.go`                               | ValidatePeerName, NameOptionsRejectInvalidName (moved to `name_test.go`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | ReceiveIntroductionRejectsInvalidName → a row in TestHandshake_BadIdentity                                                                                                                                                                                                                                                                     | TestIntroduce                                                                                                                            |
| `preauth_fuzz_test.go`, `serve_fuzz_test.go`  |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | FuzzServerServe                                                                                                                                                                                                                                                                                                                                 | FuzzPreAuthEnvelopeValidation                                                                                                            |
| `routes_test.go`, `version_test.go`           |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | tables (routes); 32-byte limit (version)                                                                                                                                                                                                                                                                                                        |                                                                                                                                          |
| `conn_test.go`, `serde_test.go`               | all                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |                                                                                                                                                                                                                                                                                                                                                 |                                                                                                                                          |

Tests outside the root whose verifier literals change:
`pkg/relayconn/token_test.go`,
`cmd/relay/internal/handlers/frame_size_test.go`, and the five
`cmd/tui/*_test.go` files of §20.4.

### 22.5 Clients

- daemon: the verify event schema; Strict prompts on a resumed connection on
  the responder and not on a pinned resume offer; reconnect stops on a final
  error; a COLD fallback emits close then start events.
- bus: Go-side policy tests for each mode × role × pinned × resumed; the
  name-collision flag; prompt-busy rejection. Frontend: `VerifyDialog`
  renders the two codes (vitest if present, else a manual check in the PR).
- tui: `verify_test.go` updated.
- A shared table of the §16.1 policy lives in each client's verifier test.

### 22.6 End-to-End

`TestE2E_RelayBlindHandshake`, in a new
`cmd/relay/internal/handlers/handshake_e2e_test.go`:

1. Start the in-process relay. Wrap both ends' `kamune.Conn` (the dialer
   through `DialWithFunc`, the server through a wrapping listener for
   `ServeWithListener`) to record every frame; these are the bytes the hub
   forwards in `Message.Data`. No hub change.
2. A server and a pinned dialer, named "Alice" and "Bob", connect. Cold
   session; exchange messages; inject one garbage frame (wrapper); observe
   termination; register a second listener and resume with its token;
   exchange messages; `Close`.
3. Assert that both sessions work, that the resumed one keeps the session
   ID, and that the recorded frames contain neither PKIX key, neither raw
   key, neither name, neither version string, nor the session ID.

The active man-in-the-middle variant is covered by `TestMITM_SplitKEM` in the
root and is not repeated here.

### 22.7 Cross-RFC Run

Owned by this RFC's implementer and run after the deletions of §26; it
extends `TestE2E_RelayBlindHandshake` rather than adding a file.

1. A relay with a generated key and access key (RFC009); listener and dialer
   with `WithPair` (RFC010) over `wss` with `cert=` and over `ws` with
   `rk=`; this handshake with `DialWithPeerKey` and the conn's
   `PeerConstraint`; Strict verifiers on both sides. Inject one garbage
   frame, reconnect through RFC010's reconnect index 0 with a first-frame
   watchdog, resume, and check that the Strict responder was prompted on
   the resume without the dialer giving up.
2. On the broker: RFC011's `brokertest`, RFC010's directional broker tokens,
   RFC008's `ListenUDP` and `DialUDP` on `ep.PacketConn()`, `ExpectPeer` on
   both conns, and a third identity that is handed the pair's broker listen
   token (standing in for a leaked token) and registers `RoleListen` with it
   before the real listener. The honest dialer matches it, its UDP path
   completes, and the handshake fails with `ErrPeerKeyMismatch` at the
   dialer's step 3 or 4a (§13.3), before the dialer sends its identity or
   any verifier runs.

## 23. Documentation Updates

In the `docs/SPEC.md` row, section numbers outside parentheses are SPEC
sections; those inside parentheses are this RFC's.

| Doc                                                                                                                                                                       | Sections                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `docs/SPEC.md`                                                                                                                                                            | §2 terms (remove Underlying Transport, HPKE as a tunnel, Resumption Token and Resumption Root; add Transcript, Verification Code, Resumption Secret, Pin). §3 cipher suite. §5 and §5.1 routes and validation (handshake routes gone, reserved). §6 rewritten: 6.1 Hellos; 6.2 Authentication (signatures, Finished, check order, pinning, verifier); 6.2.1 Fingerprints (two labelled codes); 6.3 Confirm; 6.4 removed (Challenge); 6.5 sequence starts at 1; 6.6 teardown and what ends resumability (§18.3); 6.8 Resumption (state per role, offer, binder, decision with `peerStored`, commit rules, lock, window with touch, sweep, persistence off). §7 key schedule with the label table. §8.1 handshake signatures and the context registry. §9.4 no channel binding. §10 roles, admission stages and timeouts. §11.3 stored entities (`resumption_i`, `resumption_r`); §11.6 sessions without persistence. §12.1, §12.3, §12.5, §12.6 (authentication at F2b, F3 and F4; replay protection by the transcript; the identity table of §8.2; the listener exposure of §8.3; the non-goals of §8.4, including post-quantum authentication only with `DialWithResumeOnly`, and prompt flooding). §13 constants. §14 errors. A new Appendix A with the test vectors. §15 gains the RFC007 row when it is merged. |
| `docs/RELAY.md`                                                                                                                                                           | "Design Goals", "Threat Model", "What the Relay Observes", "What a Compromised Relay Can and Cannot Do": the §8.3 paragraph, merged by RFC009.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `docs/rfc/RFC001_session-resumption.md`                                                                                                                                   | Banner: superseded by RFC007 (SPEC §6.8 once merged).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `docs/rfc/RFC002_signed-metadata.md`                                                                                                                                      | Note that the Introduce and Resume messages no longer exist.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `docs/DAEMON.md`                                                                                                                                                          | Verify event, mode table, reconnect errors, and that AutoAccept dialers send their identity to any key.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `cmd/bus/README.md`                                                                                                                                                       | Verification modes (§16.1), reading the two codes, the AutoAccept caveat.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `cmd/tui/README.md`                                                                                                                                                       | Verify screen.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `README.md` (root)                                                                                                                                                        | Protocol summary paragraph.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `assets/diagrams/handshake-flow.svg`, `key-derivation.svg`, `session-phases.svg`, `protocol-overview.svg`, `cipher-suite.svg`, `message-pipeline.svg`, `wire-format.svg` | Redraw for four flights and the new key schedule. Until redrawn, remove them from SPEC and README rather than show stale diagrams. `storage-hierarchy.svg` gets the two resumption rows.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `CHANGELOG.md`                                                                                                                                                            | Not touched: it changes only when the maintainer says so.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

## 24. Findings

### 24.1 Closed and Partly Closed

| Finding | Status            | Closed by                                                                                                                                                                                                                                                                                                         |
| ------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| KAM-02  | Closed            | §9 to §13: the outer tunnel is gone; identities sit under hybrid-KEM keys; signatures and Finished MACs cover the KEM; a split KEM fails at F2b; no session ID in the clear; no token sent. The listener key exposure is stated (§8.3).                                                                          |
| KAM-01  | Closed            | §11, §13, §14: everything after the hellos is bound to `TH`; replay tests in §22.2; the verifier runs only on an authenticated peer; clients store peers after establishment. The prompt-flooding residual is in §8.4 and §20.1.                                                                                 |
| KAM-27  | Closed            | The Challenge is removed; all Finished MACs are verified (§13.2).                                                                                                                                                                                                                                                |
| KAM-10  | **Partly closed** | The resume-path oracle is gone: no resume reply exists outside the authenticated F4, and every failure gives `Confirm{COLD}` (§15.3). The listener still signs for any prober on the cold path (§8.3), now without name or version. Accepted for now by maintainer decision; contact-only listeners are left for a future RFC (§25.1). |
| KAM-15  | Closed            | §15.4 commit rules, `Previous`, CAS, the resume lock, generation tags; §18.3, so injected, replayed or dropped frames do not delete state.                                                                                                                                                                        |
| KAM-08  | Closed            | §16: the verifier runs on every handshake; §16.1: Strict prompts on resumed connections at the responder; deleting a peer revokes resumption (§15.3).                                                                                                                                                            |
| KAM-28  | Closed            | §15.5: a sliding idle window with touch, plus a maximum age.                                                                                                                                                                                                                                                     |
| KAM-03  | Closed            | §17, §20: two 132.9-bit codes in every verify prompt; emoji gone from verification surfaces; `numeric` is the default format.                                                                                                                                                                                     |
| KAM-26  | Closed            | Verify prompts label the pseudonym "nickname" and keep the self-asserted name out of the code area; the initiator's prompt shows no unauthenticated responder name at all.                                                                                                                                       |
| KAM-32  | Closed            | `resume_test.go` is deleted; the resume tests drive `Server.serve` over real stores with `ServeWithClock` and `ServeWithResumeEnabled(false)` (§22.2).                                                                                                                                                           |
| KAM-31  | **Partly closed** | Handshake, resume, AEAD, duplicate and signature failure paths in §22.2, and raw-byte fuzzers. Storage reopen and relayconn coverage belong to other work.                                                                                                                                                      |

### 24.2 Regression Tests Kept

For findings the rewrite could reopen: KAM-07
(`TestLateVerifierAcceptIsRejected`), KAM-16 (`DeleteResumption` never
recreates a namespace), KAM-22 (name limits in `TestHandshake_BadIdentity`)
and KAM-23 (small-order key rows).

### 24.3 Touched but Not Claimed

These findings are in code this RFC rewrites, but their closure is not
claimed. After implementation their status is checked against the new code
and recorded, not assumed.

| Finding                 | Why it may close                                                                                                                       |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| BUS-01                  | The Quick initiator accepts only pinned peers; `DialWithPeerKey` on peer-list dials; `PeerConstraint` on pair rendezvous (with RFC010). |
| BUS-15, DMN-03          | One open prompt per client, 6 prompts per minute (§20.1).                                                                              |
| KAM-17, KAM-20, TUI-19  | Local `Close` deletes resumption state; the global sweep (§15.7); state kept only on network-caused ends.                             |
| DOC-16                  | SPEC §6.8 and RFC001 rewritten.                                                                                                         |

## 25. Deferred Items

| Item                                                                                   | Why deferred                                                                                                                                       |
| -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Contact-only listener (§25.1)                                                         | Left for a future RFC by maintainer decision. Needs RFC010's `PairSecret`. The wire field (`tag`) is already in the ClientHello, so no frame layout changes. |
| Post-quantum signatures (ML-DSA)                                                       | Not in the dependency set. `DialWithResumeOnly` gives post-quantum authentication for resumed sessions in the meantime.                            |
| Removing per-frame Ed25519 signatures; a sequence number in the session AEAD AD       | The session-frame format is outside this RFC (RFC004). §18.3 already keeps replays from deleting state.                                           |
| QR-code comparison of codes                                                            | Bus UI work outside this RFC.                                                                                                                      |
| Emoji identicon rename, emoji list change, `KeyHex`, deleting `Emoji`                  | Non-verification UI; one later UI item (§27).                                                                                                      |
| Raw 32-byte identity keys on the wire and in storage                                   | PKIX with the fixed-prefix check is canonical (§10.4); a protocol-wide move is a separate change (§6).                                             |
| Version negotiation beyond one `ver` byte                                              | Only one version exists before v1.0.                                                                                                               |
| Hiding cold or resumed from timing                                                     | Inherent in prompts.                                                                                                                               |
| Hello obfuscation                                                                      | Not a stated goal.                                                                                                                                 |

### 25.1 Contact-Only Listener Sketch

Not part of this RFC's normative changes. The sketch is recorded so the
future RFC needs no frame layout change.

`ServeWithContactsOnly()` would make a listener answer only ClientHellos
from stored peers. Pattern: a Noise `psk0`-style pre-shared tag, with the
PSK from a static-static DH (as in Noise `KK` without the extra round trip).

```
k_P = attest.PairSecret(P, "kamune/2 contact tag")    // RFC010, 64 bytes
tag = HMAC-SHA256(k_P, CH[0:34] || CH[66:1282])[0:32]
      // CH[0:34] = ver, type, nonce_i; CH[66:1282] = pk_i
```

- Dialer: with `DialWithPeerKey(P)` (or a resume pin), it sets `tag` as
  above; otherwise random. Always 32 bytes, so a passive observer cannot
  tell.
- Listener: keeps `k_P` cached per stored peer (rebuilt when the peer list
  changes). On a ClientHello it computes the tag for every stored peer and
  compares with `hmac.Equal`. No match: close without reply and count a bad
  hello. A match with P: continue; at F3 require `key_I == P`
  (`ErrPeerKeyMismatch`).
- Cost: one HMAC per stored peer per ClientHello.
- What it hides: the listener's key and liveness from anyone without a
  stored contact's private key, the relay operator included. A replayed
  ClientHello still gets an F2, encrypted to the original `pk_i`, so the
  replayer learns only that some contact-only listener that knows the
  original dialer is there, which it saw when it captured the hello.
- Limits: the static DH is classical, so a future quantum attacker that
  knows both public keys can compute tags. Contact-only listeners cannot
  accept first contact; the user switches the mode off to add a contact.

## 26. Implementation Plan

Commits follow AGENTS.md: `<module>: <lowercase description>`, at most 72
characters, one logical change each, and nothing is committed without
prompting the maintainer first. Each commit builds and passes its module's
tests, except inside the merge unit of group 2. The last column names the
commits of the other rework RFCs that a group waits for.

| Group | Commits (in order)                                                                                                                                                                                                                                                                                                                                                                                                      | Depends on                                                                                                                                                                                         |
| ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Root building blocks, beside the old code | `kamune: add handshake v2 key schedule and transcript` (`keyschedule.go`, `transcript.go`, `enigma.NewFromKey`, vectors); `kamune: add handshake v2 frame codec` (`hsframe.go`, fuzzers); `kamune: add per-role resumption state to storage` (the new storage API beside the old one, storage tests, sweep); `kamune: add signature context registry` (`pkg/attest/contexts.go`); `kamune: add fingerprint safety number` | Nothing. The context registry lands with the shared prerequisites (RFC006 phase 0); RFC008 to RFC011 sign nothing with the identity key.                                                                  |
| 2. Root switch (one merge unit)              | `kamune: switch to handshake v2` (dial, server, admission stages, verify, transport §18.3, deletion of the old phases and routes, regenerated `pb`, root test migration of §22.4, `AppVersion` 0.8.0, deletion of `pkg/exchange/mlkem.go`); `relayconn: adapt tests to the new verifier`; `relay: adapt tests to the new verifier`; minimal `bus:`, `daemon:` and `tui:` compile commits for the new `RemoteVerifier`    | Group 1; RFC010's `PeerConstraint` and `ExpectPeer` commit (the switch moves its interim check out of `verifyPeer` into §13.3); RFC008's `admit`, `forgeable` and UDP commits, which the switch rebases onto. The root suite's `pkg/relayconn` tests and every other module fail until all commits of the unit land, because AGENTS.md requires one commit per module, so they merge together. |
| 3. Client features                           | `daemon:`, `bus:`, `tui:` commits: verifier policy and prompt limits, verify events and screens, two codes, `numeric` default, reconnect stop list and COLD fallback, `DeleteResumptionAll`, `DialWithPeerKey` on every path with a known key                                                                                                                                                                           | Group 2. In each client file, after the commits of RFC009, RFC011, RFC010, RFC008 and RFC010's reconnect-root commits (which use the exporter from group 2), in that order.                        |
| 4. Deletions                                 | `kamune: remove resumption token storage helpers`; finally `kamune: delete pkg/exchange`, after `conn.go` replaces the embedded `exchange.ReadWriter` with the two methods it carries                                                                                                                                                                                                                                  | The storage helpers: after RFC010 removes its relay-token storage and group 3. The package: after group 2 and after RFC009, RFC010 and RFC011 remove the last callers.                             |
| 5. End-to-end                                | `kamune,relay: add relay end-to-end handshake test` (§22.6); then the cross-RFC run of §22.7                                                                                                                                                                                                                                                                                                                          | Group 2, RFC009's relay-leg switch and RFC010's relayconn token options; the cross-RFC run after group 4.                                                                                          |
| 6. Docs                                      | `docs:` commits for SPEC, RELAY (with RFC009), DAEMON, the READMEs, the RFC001 and RFC002 banners, and the removal or redraw of the diagrams (§23)                                                                                                                                                                                                                                                                     | The code of this RFC. In SPEC, this RFC's text lands before RFC008's, RFC009's and RFC010's edits.                                                                                                |

## 27. Open Questions

1. **`fingerprint.Emoji`.** When the later UI item removes emoji from the
   remaining surfaces (share card, peer lists, settings), delete
   `fingerprint.Emoji`, or keep it as a labelled identicon?
2. **Prompts for user-initiated dials.** The daemon today never rejects a
   prompt for a peer the user dialed because of prompts that inbound peers
   hold open (`outboundVerifier`), so an inbound flood cannot stop the user
   from reaching a peer. §20.1 allows one open prompt per client, and the
   proposed default (§6) grants no exemption. Should prompts on the
   initiator side of a user's own dial be exempt from that limit and from
   the per-minute rate?
