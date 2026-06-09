# Double-Ratchet Implementation Plan

**Target version:** v0.5.0

**Status:** Planned - First Draft

**Authors:** kamune core team

---

## 1. Motivation

The current `Transport` (`transport.go:30-40`) derives **two static `*enigma.Enigma` instances** once at handshake time and reuses the same AEAD keys for the entire session. The SPEC is explicit (`SPEC.md:892-894`):

> Within a single session, the same symmetric keys are used for all messages (no per-message ratcheting). Forward secrecy is per-session, not per-message.

This plan replaces that model with a Signal-style **Double Ratchet** providing:

- **Per-message forward secrecy** — compromising a message key reveals only that message.
- **Per-epoch DH forward secrecy** — every outbound message triggers a fresh X25519 DH agreement that mixes into the next chain key.
- **Post-compromise security** — a single observed DH step heals the ratchet.
- **Out-of-order tolerance** — a bounded skipped-message-key cache allows small reorderings and drops without terminating the session.

There is no v1.0 backward-compatibility promise, so the change ships inside v0.5.0; older clients must upgrade. The wire format and the `AppVersion` literal stay at `0.5.0` (`version.go:12`); this is a hard cut, not a version bump.

---

## 2. Decisions (locked)

| Question            | Decision                                                                                              |
| ------------------- | ----------------------------------------------------------------------------------------------------- |
| Flavor of ratchet   | **Full Double Ratchet** — KDF symmetric chain + DH ratchet on every sent message                      |
| Out-of-order policy | **Skipped-message-key cache**, Signal-style, cap 1000 entries                                         |
| Rollout             | **Always on**, no opt-in, no version negotiation; v0.5.0 is a hard cut                                |
| Code location       | New `internal/ratchet/` package                                                                       |
| DH primitive        | **X25519** via existing `pkg/exchange` (raw 32-byte pubkeys on the wire)                              |
| DH cadence          | **Every `Send`** emits a fresh ephemeral and a `ROUTE_DH_RATCHET` frame is sent immediately before it |
| Skipped cache cap   | **1000** entries, hard-coded, no public knob                                                          |

---

## 3. Package layout

```
internal/ratchet/
├── doc.go           # Package overview, security properties, references
├── chain.go         # KDF chain: ChainKey, RootKey, MessageKey, step()
├── chain_test.go
├── skipped.go       # SkippedMessageKey cache (bounded ring)
├── skipped_test.go
├── ratchet.go       # Session state machine, DH step, NextSend/NextRecv
├── ratchet_test.go
└── vectors_test.go  # Golden KDF vectors
```

All public surface is single-package. No outside dependencies beyond `crypto/ecdh`, `crypto/sha512`, `golang.org/x/crypto/hkdf`, and `golang.org/x/crypto/chacha20poly1305` (already vendored in `internal/enigma`).

---

## 4. Crypto

### 4.1 KDF chain (per direction)

Every step advances the chain key (`ck`) and emits a one-shot message key (`mk`):

```
ck', mk = HKDF-SHA512(ck, nil, "kamune/ratchet/chain/v1", 64)
         // ck' = first 32 bytes, mk = last 32 bytes
```

### 4.2 Per-message nonce

To guarantee no nonce reuse across the lifetime of the session we derive a deterministic 24-byte nonce from `mk` plus the ratchet epoch and chain index:

```
nonce = HKDF-SHA512(mk, nil, "kamune/ratchet/nonce/v1" || dhPub || index, 24)
         // dhPub is the *current* receiver-side ratchet pubkey, raw 32 bytes
         // index is the chain index as uint64 big-endian
```

`mk` and `nonce` together form the AEAD inputs; the AEAD is XChaCha20-Poly1305.

### 4.3 DH ratchet step

The standard Signal model: **every Send** first emits a `ROUTE_DH_RATCHET` frame carrying the sender's new ephemeral public key (so the peer can DH-step on its next Send), then the actual payload frame. Each side's `Step` operation consumes a fresh ephemeral and the peer's most recent ephemeral.

```
// On every Send (callers do this under the ratchet mutex):
myEphem, ephemPub = X25519.GenerateKey()
rk, sendCK = HKDF-SHA512(rk, dh(myEphem, peerEphem), "kamune/ratchet/root/v1", 64)

// On Receive of a ROUTE_DH_RATCHET carrying peerEphem:
rk, recvCK = HKDF-SHA512(rk, dh(mySess, peerEphem), "kamune/ratchet/root/v1", 64)
```

Concretely, `Ratchet.Send()` performs both halves atomically:

1. Generate a fresh ephemeral; this _is_ the `myEphem` for the next outgoing step.
2. Compute `rk, sendCK = KDF(rk, dh(myEphem, peerEphem))`.
3. Return `(sendCK, ephemPub, sendCount)` plus the new `(mk, nonce)`.
4. The caller serializes a `ROUTE_DH_RATCHET` frame carrying `ephemPub`, **encrypted by the previous static session key** (so a passive observer cannot correlate epochs without breaking AEAD).

`Ratchet.Receive(peerEphem, peerIdx)` then:

1. Computes `rk, recvCK = KDF(rk, dh(mySess, peerEphem))`.
2. Caches all `mk` values for the old receiving chain up to `peerIdx` into the skipped cache.
3. Advances `recvCK` to `peerIdx`, returns the matching `mk` (cache hit or fresh step).

### 4.4 Static session key (envelope layer)

The outer `SignedTransport` envelope is encrypted with a **non-ratcheting** key derived once at handshake. It protects metadata, signatures, padding, and the ratchet envelope itself:

```
// rootKey0 = HKDF-SHA512(mlkemSecret, localSalt || remoteSalt,
//                        "kamune/ratchet/root0/v1", 32)
// staticKey = HKDF-SHA512(rootKey0, nil, "kamune/ratchet/static/v1", 32)
```

Both sides arrive at the same `rootKey0` from the same `mlkemSecret` and the two exchanged salts (`handshake.go:40,86,172,176`), so the static key is identical on both ends without further coordination.

The ratchet lives **inside** the envelope: a fresh 32-byte AEAD key + 24-byte nonce per message, applied to `st.Data` only. The envelope sequence number (`metadata.Sequence`) keeps its existing semantics at the envelope layer.

---

## 5. Wire protocol changes

### 5.1 Protobuf additions

`internal/box/box.proto` — `Metadata` gets two fields:

```protobuf
uint64 RatchetIndex = 5;  // chain position for this message
bytes  RatchetDH    = 6;  // raw 32-byte X25519 pubkey identifying the ratchet epoch
```

`internal/box/model.proto` — `Handshake` gets two fields:

```protobuf
bytes InitRatchetKey = 4;  // raw 32-byte X25519 ratchet pubkey from initiator
bytes RespRatchetKey = 5;  // raw 32-byte X25519 ratchet pubkey from responder
```

Regenerate via `make gen-proto`. Field numbers 4 and 5 are unused in the current schema (it stops at 3) so there is no collision.

### 5.2 New routes

| Value | Name               | Phase         | Direction     | Description                                                                                                          |
| ----- | ------------------ | ------------- | ------------- | -------------------------------------------------------------------------------------------------------------------- |
| `11`  | `ROUTE_DH_RATCHET` | Communication | Bidirectional | Payload is the raw 32-byte X25519 ratchet pubkey; encrypted by the **previous** static session key, signed as usual. |

`ROUTE_FIRST_MESSAGE` from the original draft is **dropped**. The initiator's first ratchet pubkey is already in `Handshake.InitRatchetKey`, so by the time either side sends its first payload, both pubkeys are known. No new first-message semantics are needed.

### 5.3 Frame layout

```
+------------------+--------------------------------------+
| Length (2 bytes) | XChaCha20-Poly1305 ciphertext        |
+------------------+--------------------------------------+

Outer ciphertext (envelope layer, staticKey + random 24-byte nonce):
+---------+-------------------+---------+
| Nonce24 | SignedTransport   | Tag16   |
+---------+-------------------+---------+

Inner SignedTransport.Data (ratchet layer, mk + derived nonce):
+---------+-------------------+---------+
| Nonce24 | Inner message     | Tag16   |
+---------+-------------------+---------+
```

The receiver:

1. Reads length-prefixed bytes.
2. Decrypts the outer ciphertext with `staticKey` (and the embedded nonce).
3. Verifies the Ed25519 signature.
4. Reads `Metadata.RatchetDH` and `Metadata.RatchetIndex` to look up the matching `mk` from the receiving chain, the skipped cache, or — on miss — surfaces `ErrRatchetDiverged`.
5. Decrypts `st.Data` with `mk` and the embedded inner nonce; unmarshals into the destination `Transferable`.

---

## 6. Code changes

### 6.1 New files

**`internal/ratchet/doc.go`** — package overview, security claims, references to RFC 9180, the Signal spec, and the SPEC sections it implements.

**`internal/ratchet/chain.go`** — types and primitives:

- `type ChainKey [32]byte`, `type RootKey [32]byte`, `type MessageKey [32]byte`
- `chainStep(ck ChainKey) (ChainKey, MessageKey)` — the KDF chain step
- `rootStep(rk RootKey, dhSecret []byte) (RootKey, ChainKey)` — the DH-root step
- `deriveNonce(mk MessageKey, dhPub []byte, idx uint64) [24]byte` — per-message nonce
- `deriveStaticKey(root RootKey) [32]byte` — outer envelope key
- `deriveRootKey0(mlkemSecret, localSalt, remoteSalt []byte) RootKey` — initial ratchet root

**`internal/ratchet/skipped.go`** — `SkippedCache`:

- Bounded ring of 1000 entries keyed by `(ratchetDH []byte, index uint64, key MessageKey)`
- `Put(dh []byte, idx uint64, key MessageKey)`
- `Get(dh []byte, idx uint64) (MessageKey, bool)` with FIFO eviction on overflow
- Thread-safe with `sync.Mutex` per AGENTS.md convention

**`internal/ratchet/ratchet.go`** — state machine:

- `Ratchet` struct (see §7.1)
- `New(rootKey RootKey, sess, sessPub, ephem, ephemPub) (*Ratchet, error)` — full init from handshake outputs
- `Step(remotePub []byte) (MessageKey, []byte, uint64, error)` — DH step + emit per-message `(mk, dh, idx)`; called from `Transport.Send` before serializing the payload
- `NextRecv(dh []byte, idx uint64) (MessageKey, error)` — resolve a receive-side message key from the current chain, the skipped cache, or step the receiving chain forward

**Tests** — see §9.

### 6.2 Modified files (root)

| File                       | Change                                                                                                                                                                                                                                                                                                                     |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal/box/box.proto`   | Add `RatchetIndex`, `RatchetDH` to `Metadata`; add `ROUTE_DH_RATCHET` (value `11`)                                                                                                                                                                                                                                         |
| `internal/box/model.proto` | Add `InitRatchetKey` (4), `RespRatchetKey` (5) to `Handshake`                                                                                                                                                                                                                                                              |
| `internal/box/pb/*.pb.go`  | Regenerated                                                                                                                                                                                                                                                                                                                |
| `routes.go`                | Add `RouteDHRatchet = 11`; update `String` / `ToProto` / `RouteFromProto` / `IsValid` accordingly                                                                                                                                                                                                                          |
| `errors.go`                | Add `ErrRatchetSkipped`, `ErrRatchetDiverged`                                                                                                                                                                                                                                                                              |
| `kamune.go`                | Add `ratchetInfo`, `staticSessionInfo`, `dhRatchetInfo`, `ratchetNonceInfo` constants                                                                                                                                                                                                                                      |
| `handshake.go`             | (a) carry the new `InitRatchetKey`/`RespRatchetKey` in the `pb.Handshake` payloads; (b) validate 32-byte lengths via a new `validateRatchetKey` helper; (c) after ML-KEM decapsulation, derive `rootKey0` and `staticKey` and pass them into `newTransport` along with the initiator's and responder's X25519 ratchet keys |
| `transport.go`             | Replace `encoder`/`decoder` `*enigma.Enigma` pair with `*ratchet.Ratchet` + `staticKey`; rework `Send`/`Receive` per §7.2                                                                                                                                                                                                  |
| `serde.go`                 | `serialize`/`deserialize` accept a `*ratchet.Ratchet` and a `staticKey`; encrypt/decrypt the outer envelope with `staticKey`; encrypt/decrypt `st.Data` with the per-message `mk` and inner nonce from the ratchet                                                                                                         |
| `server.go`                | Plumb ratchet init from handshake into `Transport`; verify the `RouteDHRatchet` path in `handleNewConnection` is unaffected (it's a Communication route, not a Handshake route)                                                                                                                                            |
| `dial.go`                  | Same as `server.go`                                                                                                                                                                                                                                                                                                        |
| `handshake_test.go`        | New cases: ratchet-key length validation, both sides construct equal `rootKey0`                                                                                                                                                                                                                                            |
| `routes_test.go`           | Add cases for `RouteDHRatchet` (String, IsValid, ToProto, RouteFromProto)                                                                                                                                                                                                                                                  |
| `transport_test.go` (new)  | End-to-end Send/Receive with ratchet; out-of-order delivery; dropped message; double-send rejection; close/ping/pong still work                                                                                                                                                                                            |
| `SPEC.md`                  | See §10                                                                                                                                                                                                                                                                                                                    |

No changes to `version.go`. `AppVersion` stays `"0.5.0"`.

---

## 7. Detailed design

### 7.1 `Ratchet` struct

```go
type Ratchet struct {
    mu sync.Mutex

    // KDF state
    rootKey     RootKey
    sendChain   ChainKey
    recvChain   ChainKey
    sendCount   uint64
    recvCount   uint64

    // Long-lived DH keys (X25519)
    sessPriv    *ecdh.PrivateKey // my session-static key
    sessPub     *ecdh.PublicKey  // my session-static pubkey
    ephemPriv   *ecdh.PrivateKey // my *current* ephemeral — rotated on every Step
    ephemPub    *ecdh.PublicKey  // my *current* ephemeral pubkey
    peerSess    *ecdh.PublicKey  // peer's session-static pubkey (from Handshake)
    peerEphem   *ecdh.PublicKey  // peer's most recent ephemeral pubkey (from Handshake initially, then DH ratchet frames)

    // Skipped-message cache
    skipped *SkippedCache
}
```

All fields are private. The only ways to drive the ratchet are `Step` and `NextRecv`. The transport holds an `*ecdh.PublicKey` of its own current ephemeral (after the most recent `Step`) so it can include it in the next outgoing `ROUTE_DH_RATCHET` frame.

### 7.2 `Transport.Send` / `Transport.Receive` (post-ratchet)

**`Send(msg, route)`:**

1. Validate route (`RouteDHRatchet` is rejected here — it's emitted by the ratchet itself, not by callers).
2. If `route` is `RouteCloseTransport` / `RoutePing` / `RoutePong` / `RouteSendChallenge` / `RouteVerifyChallenge`, use the control-plane path (see §7.5). Otherwise take the ratchet path.
3. **Ratchet path.** Under `Transport.mu` and the ratchet's internal `mu`:
   a. Call `ratchet.Step(peerEphem)` to rotate the ephemeral, emit `(mk, newEphemPub, sendCount)`.
   b. Build `SignedTransport.Metadata` with `RatchetIndex: sendCount`, `RatchetDH: newEphemPub.Bytes()`, plus the existing `ID`, `Timestamp`, `Sequence`, `Route`.
   c. Sign + serialize the envelope.
   d. Encrypt `st.Data` with `mk` and the derived inner nonce.
   e. Encrypt the resulting envelope with `staticKey` and a fresh random 24-byte nonce.
   f. Length-prefix and write to the conn.
4. **Ratchet-frame path** (called by `Step` from the ratchet path, not by callers directly): serialize a `SignedTransport` whose `Data` is `newEphemPub.Bytes()` and whose `Route` is `RouteDHRatchet`. Encrypt with `staticKey` and a fresh random nonce. Length-prefix and write.

**`Receive(dst)`:**

1. Read length-prefixed bytes; decrypt envelope with `staticKey`.
2. Parse `SignedTransport`; verify Ed25519 signature.
3. Branch on `metadata.Route`:
   - `RouteCloseTransport` → return `ErrPeerDisconnected` (control plane; no ratchet advance).
   - `RoutePing` / `RoutePong` → control-plane decrypt (§7.5); return metadata to the caller.
   - `RouteDHRatchet` → install `peerEphem = st.Data` (raw 32 bytes), then loop to read the next frame (which is the actual payload that prompted the DH step).
   - Otherwise → look up `mk := ratchet.NextRecv(st.Metadata.RatchetDH, st.Metadata.RatchetIndex)`. On miss, return `ErrRatchetDiverged`.
4. Decrypt `st.Data` with `mk` and the embedded inner nonce; unmarshal into `dst`.
5. Increment `recvSequence`; return metadata.

### 7.3 Sequence numbers

Envelope `Metadata.Sequence` continues to be strictly monotonic per `Transport`; gaps still produce `ErrOutOfSync` at the envelope level (`transport.go:91-110` semantics unchanged). The ratchet's own ordering (`Metadata.RatchetIndex` + `Metadata.RatchetDH`) handles out-of-order delivery inside a single envelope sequence — the skipped cache absorbs small reorderings and drops without surfacing `ErrOutOfSync`.

### 7.4 Skipped cache

- Default cap 1000, hard-coded.
- Eviction: FIFO ring.
- `Put` is called when a DH step advances the receiving chain but there are still unconsumed keys at lower indices in the _previous_ receiving chain. Up to ~1000 keys are retained; older entries are evicted.
- `Get(dh, idx)` returns the cached key on hit, `(MessageKey{}, false)` on miss.

### 7.5 Control-plane routes

`RouteCloseTransport`, `RoutePing`, `RoutePong`, `RouteSendChallenge`, `RouteVerifyChallenge` must not be lost across DH ratchet steps (Signal's "whitespace" tokens are vulnerable to the same problem; we avoid it by using a **control-plane static key** derived once at handshake):

```
controlKey = HKDF-SHA512(rootKey0, nil, "kamune/ratchet/control/v1", 32)
```

Control-plane frames use `controlKey` to encrypt the envelope, sign the `SignedTransport` as usual, and never carry `RatchetIndex` / `RatchetDH`. The receiving ratchet ignores their metadata on the ratchet path. This decouples liveness / shutdown from ratchet state — close, ping, and pong work even if the ratchet has been desynchronized.

The challenge phase (`RouteSendChallenge` / `RouteVerifyChallenge`) is used only during handshake, where the ratchet is not yet driving encryption. After the ratchet takes over, those routes are control-plane. Today they are only emitted by `sendChallenge` / `acceptChallenge` (`handshake.go:238-284`) before the ratchet is wired in, so they will naturally fall on the ratchet's first session message path; the explicit `controlKey` machinery is a safety net for any future control-plane use.

---

## 8. Error handling

New sentinels in `errors.go`:

- `ErrRatchetSkipped` — a message arrived out of order and was decrypted via the skipped cache. Surfaced as an informational flag on the returned `*Metadata` (e.g., a `Skipped() bool` method), not as an error. Callers that want to detect it can do so without breaking the receive loop.
- `ErrRatchetDiverged` — chain advance could not be reconciled: skipped-cache miss, unknown DH epoch, or replay past the cache window. Returned by `NextRecv`; mapped to a `Transport.Receive` error.

Existing sentinels continue to apply unchanged:

- `ErrOutOfSync` — envelope-level sequence mismatch (`transport.go:91-110`).
- `ErrInvalidSignature` — Ed25519 verification failure (`serde.go:69-71`).
- `ErrVerificationFailed` — ping/pong or challenge token mismatch.
- `ErrUnexpectedRoute`, `ErrInvalidRoute`, `ErrMessageTooLarge`, `ErrConnClosed`, `ErrPeerDisconnected`, `ErrReceiveTimeout`, `ErrVersionMismatch`, `ErrClosedServer` — all unchanged.

---

## 9. Testing strategy

| Test file                          | Coverage                                                                                                                                                     |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `internal/ratchet/chain_test.go`   | KDF chain determinism; chain step length; nonce derivation uniqueness across `(dh, idx)` pairs                                                               |
| `internal/ratchet/skipped_test.go` | Put/Get/eviction; cap honored under overflow; concurrent Put/Get safety                                                                                      |
| `internal/ratchet/ratchet_test.go` | Alice↔Bob roundtrip; out-of-order delivery; dropped message; DH step symmetry; replay rejection; 1000+ skipped message handling                              |
| `internal/ratchet/vectors_test.go` | Golden vectors committed in-tree for the KDF chain and the DH step                                                                                           |
| `handshake_test.go`                | Ratchet-key init validates lengths (must be exactly 32 bytes); rejects mismatched lengths                                                                    |
| `routes_test.go`                   | `RouteDHRatchet` (String, IsValid, ToProto, RouteFromProto)                                                                                                  |
| `transport_test.go` (new)          | End-to-end Send/Receive with ratchet over a `net.Pipe`; ping/pong still works; close still works; verify `RatchetIndex` / `RatchetDH` round-trip on the wire |

All tests use real implementations (no mocks) per AGENTS.md. Tests that need two ratchets share an `mlkemSecret` to bootstrap symmetric initial state — the ratchet itself is symmetric, the test just instantiates both sides from the same secret.

---

## 10. Documentation updates (`SPEC.md`)

- **§6.8 Ratchet Init (new)** — handshake carries `InitRatchetKey` and `RespRatchetKey`; first outbound message in each direction is preceded by a `ROUTE_DH_RATCHET` frame carrying the sender's fresh X25519 ephemeral.
- **§7.4 Enigma Cipher** — keep; document the new ratchet wrapper that sits on top.
- **§7.5 Key Hierarchy Summary (new rows)** — ratchet root key, chain key, message key, static session key, control-plane key.
- **§8.1 Digital Signatures** — note that per-message keys do not weaken signature verification.
- **§12.4 Forward Secrecy** — replace "per-session, not per-message" with the per-message + per-DH-step guarantee.
- **§12.6 Replay Protection** — add: "The ratchet's skipped cache plus envelope sequence numbers provide bounded out-of-order tolerance; messages that cannot be reconciled (gap > 1000 or unknown DH epoch) are rejected with `ErrRatchetDiverged`."
- **§13 Protobuf Schema Reference** — show the new `Metadata` and `Handshake` fields and the new `ROUTE_DH_RATCHET` route.
- **§14 Constants and Limits** — add `ratchetSkippedCacheCap = 1000`, `ratchetKeySize = 32`, `ratchetNonceSize = 24`.
- **§15 Error Conditions** — add `ErrRatchetSkipped`, `ErrRatchetDiverged`.

**Do not** bump `AppVersion` in `version.go`. Per the locked rollout decision, the change ships inside v0.5.0 as a hard cut.

---

## 11. Commit order (per `AGENTS.md`)

1. `kamune: add internal/ratchet package with KDF chain, skipped cache, and DH ratchet`
2. `kamune: extend Handshake and Metadata proto with ratchet fields`
3. `kamune: add ROUTE_DH_RATCHET route`
4. `kamune: integrate ratchet into Transport Send/Receive`
5. `kamune: wire ratchet init through handshake orchestrators`
6. `docs: document ratchet in SPEC.md`

Each commit is self-contained, builds, and passes `go test ./... -v` from the root. Commit 1 can land even if the rest is abandoned — the new package is unused by the rest of the codebase. Commit 2 must land before commit 3 (the new `Metadata` fields are referenced by the ratchet frames). Commits 4 and 5 together form the wire-protocol change and must not be bisected by a release.

---

## 12. Out of scope (deliberately deferred)

- ML-KEM-based DH ratchet. X25519 is sufficient and matches the existing `pkg/exchange` API; using raw 32-byte X25519 pubkeys (not PKIX-DER) keeps frames small.
- Header encryption (X3DH-style). The static envelope key already protects metadata at the AEAD layer.
- Multiple concurrent sessions sharing a root key (out-of-band re-keying). v0.5.0 keeps one ratchet per `Transport`.
- Adaptive ratchet cadence. Fixed at "every Send emits a DH-ratchet frame" per the locked decision.
- Asynchronous out-of-order delivery from a worker pool. Cache lookups are O(1) on hit, O(1) amortized on miss; no worker pool needed.
- A public `pkg/ratchet/` API. The ratchet is implementation detail; `Transport` is the only consumer.
