# Double-Ratchet Implementation Plan

**Target version:** v0.5.0

**Status:** Planned - Second Draft

**Authors:** kamune core team

---

## 1. Motivation

The current `Transport` (`transport.go:30-40`) derives **two static `*enigma.Enigma` instances** once at handshake time and reuses the same AEAD keys for the entire session. The SPEC is explicit (`docs/SPEC.md:892-894`):

> Within a single session, the same symmetric keys are used for all messages (no per-message ratcheting). Forward secrecy is per-session, not per-message.

This plan replaces that model with a Signal-style **Double Ratchet** providing:

- **Per-message forward secrecy** — compromising a message key reveals only that message.
- **Per-epoch DH forward secrecy** — every time a peer rotates its ephemeral, the next outbound message produces a fresh X25519 DH agreement that mixes into the next chain key.
- **Post-compromise security** — a single observed DH step heals the ratchet.
- **Out-of-order tolerance** — a bounded skipped-message-key cache allows small reorderings and drops without terminating the session.

There is no v1.0 backward-compatibility promise, so the change ships inside v0.5.0; older clients must upgrade. The wire format and the `AppVersion` literal stay at `0.5.0` (`version.go:12`); this is a hard cut, not a version bump.

As a side effect, three existing `Metadata` fields lose their purpose and are dropped:

- **`Metadata.ID`** (`serde.go:41`, `rand.Text()`) — replay protection, ordering, and de-duplication are all handled by `(RatchetIndex, RatchetDH)` plus the skipped cache. Debugging can use the ratchet tuple.
- **`Metadata.Timestamp`** (`serde.go:42`, `timestamppb.Now()`) — the sender's _claimed_ time, which we cannot trust (clock drift, malicious peers, metadata leak of the sender's wall clock).
- **`Metadata.Sequence`** (`transport.go:38-39,93-110`) — a strict gap-fatal counter that directly conflicts with the skipped cache. The ratchet's chain index is the sole source of truth for ordering and replay.

Removing all three shrinks `Metadata` to `(Route, RatchetIndex, RatchetDH)`, deletes `ErrOutOfSync`, and removes a `rand.Text()` and a `timestamppb.Now()` per frame.

---

## 2. Decisions (locked)

| Question                             | Decision                                                                                                         |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| Flavor of ratchet                    | **Full Double Ratchet** — KDF symmetric chain + DH ratchet                                                       |
| Out-of-order policy                  | **Skipped-message-key cache**, Signal-style, cap 1000 entries                                                    |
| Rollout                              | **Always on**, no opt-in, no version negotiation; v0.5.0 is a hard cut                                           |
| Code location                        | New `internal/ratchet/` package                                                                                  |
| DH primitive                      | **X25519** via `pkg/exchange.ECDH` (raw 32-byte pubkeys on the wire)                                            |
| DH cadence                           | **DH step on the first Send after the peer rotates its ephemeral**; the local ephemeral is rotated on every Send |
| Skipped cache cap                    | **1000** entries, hard-coded, no public knob                                                                     |
| Envelope sequence counter            | **Removed** — replaced by ratchet `(RatchetIndex, RatchetDH)`                                                    |
| `Metadata.ID` / `Metadata.Timestamp` | **Removed** — no consumer that the ratchet doesn't already serve                                                 |
| Outer envelope encryption            | **Single `staticKey`** for every frame; control-plane routes just skip the ratchet step on receive               |
| Salt ordering for `rootKey0`         | **`localSalt \|\| remoteSalt`** in each side's own view (initiator and responder both concatenate local first)   |

---

## 3. Package layout

```
internal/ratchet/
├── doc.go           # Package overview, security properties, references
├── chain.go         # KDF chain: ChainKey, RootKey, MessageKey, chainStep
├── chain_test.go
├── skipped.go       # SkippedMessageKey cache (bounded ring)
├── skipped_test.go
├── ratchet.go       # Session state machine, NextSend / NextRecv
├── ratchet_test.go
└── vectors_test.go  # Golden KDF vectors
```

Public surface is single-package. Dependencies: `crypto/sha512`, `golang.org/x/crypto/hkdf`, `golang.org/x/crypto/chacha20poly1305` (already vendored in `internal/enigma`), and `github.com/kamune-org/kamune/pkg/exchange` for the `ECDH` wrapper around `crypto/ecdh.X25519`.

---

## 4. Crypto

All KDFs are HKDF-SHA512. Per RFC 5869 §2.2, a `nil` salt is treated internally as a string of `HashLen` zero bytes; this is the standard "extract from no salt" pattern, used here because the input key material is already uniformly random.

### 4.1 KDF chain (per direction)

```
ck', mk = HKDF-SHA512(ck, nil, "kamune/ratchet/chain/v1", 64)
         // ck' = first 32 bytes, mk = last 32 bytes
```

Each call is destructive: `ck` is replaced by `ck'`, and the returned `mk` is a one-shot AEAD key. There is no "peek" — the caller cannot re-derive an `mk` once the chain has stepped.

### 4.2 Per-message nonce

```
nonce = HKDF-SHA512(mk, nil,
                    "kamune/ratchet/nonce/v1" || peerRatchetDH || index, 24)
         // peerRatchetDH is the ratchet pubkey of the *receiver side* for this message, raw 32 bytes
         // index is the ratchet chain index as uint64 big-endian
```

Each `(mk, peerRatchetDH, index)` triple produces a unique 24-byte nonce. The triple is unique because the ratchet never repeats `mk` for a given index, and `index` is unique per chain.

### 4.3 DH ratchet step

A DH step is _rare_: it runs on the **first `NextSend` whose incoming-side state has observed a new peer ephemeral** (i.e., when the peer's most recent ephemeral differs from the one we last did a DH agreement against), and on the symmetric side (receiver) on the **first `NextRecv` that observes a new peer ephemeral**. It is **not** run on every `NextSend` — that would replace the receiving chain on every message and break the skipped cache.

```
// On the first NextSend where peerEphem != lastAgreedPeerEphem:
//   (this condition is true initially and after each peer rotation)
myEphem, ephemPub = X25519.GenerateKey()
rk, sendCK = KDF(rk, dh(myEphem, peerEphem), "kamune/ratchet/root/v1", 64)
lastAgreedPeerEphem = peerEphem

// On the first NextRecv where peerEphem != lastAgreedPeerEphem:
//   (mirror; also where the previous chain's leftover keys are cached)
rk, recvCK = KDF(rk, dh(mySess, peerEphem), "kamune/ratchet/root/v1", 64)
lastAgreedPeerEphem = peerEphem
```

The local ephemeral is rotated **on every `NextSend`** (cheap: one X25519 keygen) and travels in `Metadata.RatchetDH` of the outbound payload frame, so the peer can detect the change on its next `NextRecv`. The local ephemeral is *consumed* only at the moment of a DH step; on a `NextSend` that doesn't trigger a step, the ephemeral is rotated and discarded unused (the new one will be used in the *next* step).

`lastAgreedPeerEphem` is the ratchet's internal "which peer ephemeral did we last mix into the root key" tracker. It is initialized to `peerSessPub` at construction time (matching the initial DH setup in §4.4) and updated on every successful DH step on either side.

### 4.4 Initial ratchet setup

The ratchet is constructed _after_ the ML-KEM handshake with three pieces of shared state:

```
rootKey0 = HKDF-SHA512(mlkemSecret, localSalt || remoteSalt,
                       "kamune/ratchet/root0/v1", 32)
```

Both sides arrive at the same `rootKey0` because both sides know both salts and use a fixed ordering convention: the **initiator's salt is concatenated first**, followed by the **responder's salt**.

The ratchet also needs an "initial DH step" to bootstrap a usable chain before the first message. This is exactly one DH agreement, performed at construction time:

```
// Ratchet side
// Each side has its own mySess (static X25519 keypair) and peerSess (peer's static pubkey from the Handshake).

// Setup: derive an initial rk' and a sendCK (we will use it as the first sending chain)
rk', sendCKInit = KDF(rootKey0, dh(mySess, peerSess), "kamune/ratchet/root/v1", 64)
rk', recvCKInit = KDF(rk',     dh(mySess, peerSess), "kamune/ratchet/root/v1", 64)  // degenerate but safe

// (Both steps use the same dh() output here, but the second KDF call still mixes
//  the result into a different chain key because of how HKDF works.)
```

The exact split of `sendCKInit` and `recvCKInit` is determined by the standard Signal "init" pattern: each side ends up with one chain for sending and one for receiving, both ready for the first KDF step.

**Initial `peerEphem` is `peerSess`.** Until the peer sends its first payload, the ratchet has no separate ephemeral for the peer; the static key stands in. This is the standard "Alice knows only Bob's static, Bob knows only Alice's static" bootstrapping.

### 4.5 Static session key (envelope layer)

The outer `SignedTransport` envelope is encrypted with a **non-ratcheting** key derived once at handshake. It protects the envelope shell (signature, metadata, padding, and the ratchet pubkey that travels inside `Metadata.RatchetDH`):

```
staticKey = HKDF-SHA512(rootKey0, nil, "kamune/ratchet/static/v1", 32)
```

Every frame — ratchet-path and control-plane — uses `staticKey` for the outer encryption. Control-plane frames are distinguished by their `Route`, not by their encryption.

The ratchet lives **inside** the envelope: a fresh 32-byte AEAD key + 24-byte nonce per message, applied to `st.Data` only.

### 4.6 ECDH usage

Every DH step in the ratchet is an **X25519 ECDH agreement** per RFC 7748. The ratchet uses `pkg/exchange.ECDH` directly — the only `ECDH` consumer in the codebase is the ratchet, so the wrapper is shaped to its needs.

`pkg/exchange.ECDH` is a thin wrapper around the Go standard library `crypto/ecdh` package (`ecdh.X25519()` curve). The wire format is **raw 32 bytes** for both private and public keys, with no PKIX-DER or ASN.1 wrapping:

```go
// Generation
priv, err := exchange.NewECDH()       // returns *ECDH; the only error is rand.Reader failure
pub := priv.PublicKey.Bytes()         // raw 32 bytes; safe to put on the wire

// Agreement (raw 32-byte peer public key)
secret, err := priv.Exchange(peerRaw32) // 32-byte output; the only error is "key is invalid"
//         = priv.PrivateKey().ECDH(ecdh.X25519().NewPublicKey(peerRaw32))
```

Error handling rules (the same way `*ECDH` reports them, surfaced through the ratchet):

- `NewECDH` failures mean `crypto/rand` is broken; this is fatal — the ratchet cannot function. Surface as a wrapped error from `Ratchet.New` and `Ratchet.NextSend`.
- `Exchange` failures mean the peer sent a malformed or out-of-curve public key. Surface as `ErrRatchetDiverged` from the transport. The handshake's `validateRatchetKey` (32-byte length check) and `Exchange`'s own key construction catch the common case, but the cryptographic agreement is the final check.

On the wire, X25519 pubkeys are stored and passed as `[]byte` of length 32. The protobuf field is `bytes RatchetDH = 3`. The transport validates length (32 for ratchet-path, 0 for control-plane) before calling into the ratchet; the ratchet itself does **not** re-validate (trust boundary is the transport).

**Why a wrapper at all?** The wrapper has three small benefits over calling `crypto/ecdh` directly: (a) it picks the X25519 curve once, so the ratchet never types `ecdh.X25519()`; (b) it gives `MarshalPublicKey` / `MarshalPrivateKey` symmetry with `pkg/attest.Attest`, which the rest of the codebase already uses; (c) it gives a single place to add length-validation and key-type checks if a future consumer needs them. None of this is load-bearing for the ratchet's correctness — the ratchet would work either way.

---

## 5. Wire protocol changes

### 5.1 Protobuf changes

`internal/box/box.proto` — `Metadata` is reduced to three fields:

```protobuf
message Metadata {
  Route  Route        = 1;
  uint64 RatchetIndex = 2;
  bytes  RatchetDH    = 3;  // raw 32-byte X25519 pubkey; zero-length for control-plane routes
}
```

`ID`, `Timestamp`, and `Sequence` are removed. Field numbers 1/2/3 are reused; nothing else reads them. **This is a wire-incompatible hard cut**: any v0.4.x client will reject these messages (signature verification on the new envelope shape will fail) and v0.5.0 clients will reject v0.4.x envelopes (the new `Metadata` shape will not proto-marshal in the old layout). Pre-1.0 kamune's `checkVersion` (`version.go:67-71`) already treats minor-version differences on a `0.x.y` line as a hard reject, so the cut is consistent with the existing version policy.

`internal/box/model.proto` — `Handshake` gets two new fields:

```protobuf
bytes InitRatchetKey = 4;  // raw 32-byte X25519 ratchet pubkey from initiator
bytes RespRatchetKey = 5;  // raw 32-byte X25519 ratchet pubkey from responder
```

Field numbers 4 and 5 are unused in the current schema (it stops at 3) so there is no collision.

Regenerate via `make gen-proto`.

### 5.2 Routes

No new routes. The ratchet pubkey travels in `Metadata.RatchetDH`; no separate ratchet frame is needed.

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
4. Branches on `Metadata.Route`:
   - `RouteCloseTransport` → return `ErrPeerDisconnected`. No ratchet state touched.
   - `RoutePing` / `RoutePong` / `RouteSendChallenge` / `RouteVerifyChallenge` → skip the ratchet step entirely. The metadata's `RatchetIndex` and `RatchetDH` are zero. Return the decrypted `st.Data` and metadata to the caller.
   - Otherwise → hand `(Metadata.RatchetDH, Metadata.RatchetIndex)` to `Ratchet.NextRecv`, which detects any peer-ephemeral change, runs the DH step if needed, steps the receiving chain to the requested index, and returns the matching `mk` (current chain, skipped cache, or `ErrRatchetDiverged`).
5. Decrypt `st.Data` with `mk` and the embedded inner nonce; unmarshal into the destination `Transferable`.

---

## 6. Code changes

### 6.1 New files

**`internal/ratchet/doc.go`** — package overview, security claims, references to RFC 9180 (HPKE), RFC 5869 (HKDF), and the Signal double-ratchet specification, plus the SPEC sections it implements.

**`internal/ratchet/chain.go`** — types and primitives:

- `type ChainKey [32]byte`, `type RootKey [32]byte`, `type MessageKey [32]byte`
- `chainStep(ck ChainKey) (ChainKey, MessageKey)` — destructive KDF chain step
- `rootStep(rk RootKey, dhSecret []byte) (RootKey, ChainKey)` — DH-root step
- `deriveNonce(mk MessageKey, peerRatchetDH []byte, idx uint64) [24]byte` — per-message nonce
- `deriveStaticKey(root RootKey) [32]byte` — outer envelope key
- `deriveRootKey0(mlkemSecret, localSalt, remoteSalt []byte) RootKey` — initial ratchet root
- All `HKDF` calls pass `salt=nil`. Each function carries a one-line comment noting that RFC 5869 §2.2 treats a nil salt as a string of `HashLen` zero bytes.

**`internal/ratchet/skipped.go`** — `SkippedCache`:

A bounded cache of message keys we computed but haven't yet received the corresponding frame for. The cache absorbs the reorder/drop window between when a chain key is generated and when its message arrives.

**Data structure.** A `map[cacheKey]cacheEntry` plus a slice used as a FIFO insertion ring. The map gives O(1) lookup; the ring gives O(1) eviction. Cap is hard-coded to 1000 entries. `cacheKey` is a 40-byte struct:

```go
type cacheKey struct {
    dh   [32]byte  // peer's ratchet pubkey for this chain (raw, not heap slice)
    idx  uint64    // chain index
}
```

The fixed-size `[32]byte` array (not `[]byte`) makes the key a value type — no heap allocation per entry, no `bytes.Equal` overhead per lookup. `cacheEntry` holds the `MessageKey` plus a monotonic `seq` counter for FIFO ordering:

```go
type cacheEntry struct {
    key MessageKey
    seq uint64    // assigned at Put time; ring tracks the smallest seq still present
}
```

**Insertion API.**

```go
// Put stores (mk) under (dh, idx). If the cap is exceeded, evict the entry with
// the smallest seq (oldest insertion). Returns the number of entries evicted
// (always 0 or 1).
func (c *SkippedCache) Put(dh [32]byte, idx uint64, mk MessageKey) (evicted int)
```

`Put` is called from `Ratchet.NextRecv` only — specifically, in two places:

1. On a DH step, for each key in the *previous* receiving chain between the previous `recvCount` and the new peer-ephem's index, **if and only if** that range is contiguous (i.e., the DH step is a clean pivot, not a step that crossed a gap). The standard Signal pattern.
2. Never on out-of-order delivery. We compute the `mk` for the requested index, look it up, and forget about it.

**Eviction policy is "oldest insertion first", not "smallest index first".** This matters under adversarial conditions: if the cache fills up, we want to drop the *first* entries we put in, not necessarily the entries from the *oldest* DH chain. A peer that floods us with messages on a fresh DH chain cannot evict our cached keys from earlier chains by sheer volume — well, actually they can, because oldest-insertion == their chain was inserted last. **This is a known limitation**: the cap is a *fixed-window* defense, not a per-chain defense. Documented in §12 as deferred (per-chain caps would need more state).

**Lookup API.**

```go
// Get returns the cached MessageKey for (dh, idx), removing it from the cache
// (a key is consumed exactly once). The bool is true on hit.
func (c *SkippedCache) Get(dh [32]byte, idx uint64) (MessageKey, bool)
```

`Get` is destructive: a hit removes the entry, so a replay of the same `(dh, idx)` returns a miss on the second try. This is the right behavior — the cache exists for out-of-order delivery, not for replay tolerance. Replay protection is at the AEAD level (the `mk` is a one-shot AEAD key) and at the signature level (the peer's signed envelope is bound to the message bytes, not the index).

**Concurrency.** A single `sync.Mutex` guards both the map and the FIFO ring. `Put` and `Get` are atomic with respect to each other. The transport's `Receive` runs in one goroutine, and the ratchet's state is only mutated from `Transport.Send` / `Transport.Receive` (which serialize through `Transport.mu`), so the lock is held briefly. No read-write split: per AGENTS.md, the codebase uses `sync.Mutex`, not `sync.RWMutex`.

**No attacker-controlled key reuse.** A peer cannot induce a cache hit on a chain they don't own because (a) the cache key includes the 32-byte `dh` which is authenticated via the Ed25519 signature on the envelope, and (b) `mk` values from different chains are domain-separated by the chain key that produced them. A hit either matches a real (signed, AEAD-decrypted) message or it doesn't exist.

**Cap constant.** Exposed as `const skippedCap = 1000` at the top of the file. Hard-coded; no public knob.

**`internal/ratchet/ratchet.go`** — state machine:

- `Ratchet` struct (see §7.1)
- `New(rootKey RootKey, mySess *exchange.ECDH, peerSessPub []byte) (*Ratchet, error)` — full init from handshake outputs. `mySess` is the local session-static X25519 keypair (generated in the handshake); `peerSessPub` is the peer's session-static pubkey, raw 32 bytes. Performs the initial DH step (§4.4) using `mySess.Exchange(peerSessPub)` and primes both chains. Initializes `curEphemPriv` / `curEphemPub` to a fresh `*exchange.ECDH` (see §7.1) and `peerEphem` to `peerSessPub`.
- `NextSend() (MessageKey, []byte, uint64, error)` — generate a fresh `*exchange.ECDH` for the new outgoing ephemeral (the previous one is discarded; the local ephemeral is used once for a DH step, never stored long-term), run a DH step if the peer has rotated since the last `NextSend` (using `mySess.Exchange(peerEphem)` if no step is needed, or `curEphem.Exchange(peerEphem)` if a step is needed), walk the sending chain forward one step, return `(mk, ephemPub, sendCount)`.
- `NextRecv(peerEphem []byte, idx uint64) (MessageKey, bool, error)` — if `peerEphem` differs from the current peer ephemeral, run a DH step (`mySess.Exchange(peerEphem)`), cache the in-between receiving-chain keys, and step the receiving chain forward to `idx`. Returns `(mk, wasSkipped, error)`. `wasSkipped` is `true` if the message was decrypted from the skipped cache rather than the current chain.
- Unexported helpers: `cacheChainRange(dh []byte, fromIdx, toIdx uint64)`. The `dh()` and `parseEphemPub()` helpers from the previous draft are gone — `*exchange.ECDH.Exchange` does both jobs.

**Tests** — see §9.

### 6.2 Modified files (root)

| File                       | Change                                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `internal/box/box.proto`   | Reduce `Metadata` to `{Route, RatchetIndex, RatchetDH}` (fields 1/2/3); drop `ID`, `Timestamp`, `Sequence`. Remove the `google/protobuf/timestamp.proto` import if no other message uses it.                                                                                                                                                                                                                                         |
| `internal/box/model.proto` | Add `InitRatchetKey` (4), `RespRatchetKey` (5) to `Handshake`. Remove `google/protobuf/timestamp.proto` if `Introduce` / `Peer` no longer need it (they do, so keep the import).                                                                                                                                                                                                                                                     |
| `internal/box/pb/*.pb.go`  | Regenerated.                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `routes.go`                | No new routes; existing `String` / `ToProto` / `RouteFromProto` / `IsValid` unchanged.                                                                                                                                                                                                                                                                                                                                               |
| `errors.go`                | Add `ErrRatchetSkipped`, `ErrRatchetDiverged`, `ErrInvalidRatchetKey`. **Remove `ErrOutOfSync`** (no remaining callers).                                                                                                                                                                                                                                                                                                             |
| `kamune.go`                | Add `ratchetInfo`, `staticSessionInfo`, `ratchetNonceInfo`, `ratchetRootInfo` constants. Drop `time` and `timestamppb` imports. Replace `Metadata.ID()`, `Metadata.Timestamp()`, `Metadata.SequenceNum()` with `Metadata.RatchetIndex()`, `Metadata.RatchetDH()`. Add `Metadata.Skipped() bool` (returns the cached flag from the ratchet).                                                                                          |
| `handshake.go`             | (a) carry the new `InitRatchetKey`/`RespRatchetKey` in the `pb.Handshake` payloads; (b) validate 32-byte lengths via a new `validateRatchetKey` helper; (c) after ML-KEM decapsulation, generate an X25519 session keypair, derive `rootKey0` and `staticKey`, and pass them into `newTransport` along with the peer's X25519 ratchet key from the handshake; (d) drop the `sequence uint64` parameter from `serde.serialize` calls. |
| `transport.go`             | Replace `encoder`/`decoder` `*enigma.Enigma` pair with `*ratchet.Ratchet` + `staticKey`; rework `Send`/`Receive` per §7.2. **Remove `sendSequence` and `recvSequence` fields and the strict gap-fatal validation block.** Validate `Metadata.RatchetDH` length on receive: anything other than 0 (control-plane) or 32 (ratchet-path) returns `ErrInvalidRatchetKey`.                                                                |
| `serde.go`                 | `serialize`/`deserialize` accept a `*ratchet.Ratchet` and a `staticKey`; encrypt/decrypt the outer envelope with `staticKey`; encrypt/decrypt `st.Data` with the per-message `mk` and inner nonce from the ratchet; **drop `ID` and `Timestamp` from the envelope**; **drop the `sequence uint64` parameter**; drop `crypto/rand` and `timestamppb` imports.                                                                         |
| `server.go`                | Plumb ratchet init from handshake into `Transport`. No orchestrator change needed for routes.                                                                                                                                                                                                                                                                                                                                        |
| `dial.go`                  | Same as `server.go`.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `handshake_test.go`        | New cases: ratchet-key length validation, both sides construct equal `rootKey0`, both sides construct equal `staticKey`. Replace `SequenceNum()` / `ID()` / `Timestamp()` assertions with `RatchetIndex()`.                                                                                                                                                                                                                          |
| `routes_test.go`           | No new routes; existing tests cover all routes.                                                                                                                                                                                                                                                                                                                                                                                      |
| `transport_test.go` (new)  | End-to-end Send/Receive with ratchet over a `net.Pipe`; out-of-order delivery; dropped message; double-send rejection; close/ping/pong still work; verify `RatchetIndex` / `RatchetDH` round-trip on the wire; verify a `staticKey` mismatch aborts the session.                                                                                                                                                                     |

No changes to `version.go`. `AppVersion` stays `"0.5.0"`.

---

## 7. Detailed design

### 7.1 `Ratchet` struct

```go
import "github.com/kamune-org/kamune/pkg/exchange"

type Ratchet struct {
    mu sync.Mutex

    // KDF state
    rootKey     RootKey
    sendChain   ChainKey
    recvChain   ChainKey
    sendCount   uint64
    recvCount   uint64

    // Session-static DH key (X25519, long-lived for the session)
    mySess       *exchange.ECDH    // my session-static keypair; generated at handshake
    peerSessPub  []byte            // peer's session-static pubkey, raw 32 bytes

    // DH ratchet state
    curEphemPriv  *exchange.ECDH   // my *current* outgoing ephemeral; rotated on every NextSend
    curEphemPub   []byte           // my *current* ephemeral pubkey, raw 32 bytes
    peerEphem     []byte           // peer's most recent ephemeral pubkey, raw 32 bytes; initialized to peerSessPub at construction

    // Per-message "did this come from the skipped cache?" flag
    skipped bool

    // Skipped-message cache
    cache *SkippedCache
}
```

All fields are private. The only ways to drive the ratchet are `NextSend` and `NextRecv`. The transport reads `curEphemPub` after `NextSend` to populate `Metadata.RatchetDH` on the outgoing frame. `skipped` is reset at the start of each `NextRecv` and read by `Metadata.Skipped()`.

`mySess` and `peerSessPub` are populated from the handshake. `curEphemPriv` is initialized in `Ratchet.New` to a fresh `*exchange.ECDH` and overwritten on every `NextSend` (the previous one is discarded; the local ephemeral is used at most once for a DH step, then a new one is generated for the next outgoing frame). The ratchet holds the current `curEphemPriv` only until the next `NextSend` overwrites it.

`mySess.Exchange(peerEphem)` is the only DH agreement path on `NextRecv`; `curEphemPriv.Exchange(peerEphem)` is the only DH agreement path on `NextSend` when a step fires. When `NextSend` does *not* fire a step (peer hasn't rotated since the last `NextSend`), no ECDH agreement runs — only the KDF chain advances.

### 7.2 `Transport.Send` / `Transport.Receive` (post-ratchet)

**`Send(msg, route)`:**

1. Validate route (any non-`IsValid` value returns `ErrInvalidRoute`).
2. Under `Transport.mu`:
   a. If `route` is one of the **control-plane routes** (`RouteCloseTransport`, `RoutePing`, `RoutePong`), set `Metadata.RatchetIndex = 0`, `Metadata.RatchetDH = nil` and skip the ratchet call. (The receiver will detect these and skip the ratchet step.)
   b. Otherwise call `ratchet.NextSend()` to get `(mk, ephemPub, sendCount)`, set `Metadata.RatchetIndex = sendCount`, `Metadata.RatchetDH = ephemPub`.
    c. Build `SignedTransport` with the chosen route, sign the plaintext `Data` with the identity key, encrypt the `Data` field with `mk` and `deriveNonce(mk, ephemPub, sendCount)`, then serialize the envelope.
    d. Encrypt the serialized envelope with `staticKey` and a fresh random 24-byte nonce.
    e. Length-prefix and write to the conn.

**`Receive(dst)`:**

1. Read length-prefixed bytes.
2. Decrypt the outer ciphertext with `staticKey` and the embedded nonce. Failure returns a wrapped AEAD error.
3. Parse the `SignedTransport` and verify the Ed25519 signature.
4. Branch on `Metadata.Route`:
   - `RouteCloseTransport` → return `ErrPeerDisconnected` (no ratchet advance).
   - `RoutePing` / `RoutePong` / `RouteSendChallenge` / `RouteVerifyChallenge` → skip the ratchet step; if `Metadata.RatchetDH` is non-zero or `Metadata.RatchetIndex` is non-zero, return `ErrInvalidRatchetKey` (defense in depth; control-plane routes must carry zero values).
   - Otherwise → validate `len(Metadata.RatchetDH) == 32` (else `ErrInvalidRatchetKey`), then call `ratchet.NextRecv(Metadata.RatchetDH, Metadata.RatchetIndex)`. The ratchet detects a new `peerEphem` and runs the DH step internally if needed; resolves the message key from the current chain, the skipped cache, or surfaces `ErrRatchetDiverged`.
5. Decrypt `st.Data` with `mk` and the embedded inner nonce; unmarshal into `dst`.
6. Return metadata.

### 7.3 Ordering and replay

The ratchet's `(RatchetIndex, RatchetDH)` pair is the **sole** source of ordering and replay protection. There is no envelope-level sequence counter.

- A message whose `RatchetIndex` is behind `recvCount` is consulted against the skipped cache; cache miss returns `ErrRatchetDiverged`.
- A message whose `RatchetIndex` is ahead of `recvCount` triggers a forward chain step; intermediate message keys are computed (but not cached, since they are consumed in order). Only the _old_ chain's in-between keys are cached on a DH change.
- A message whose `RatchetDH` differs from the current `peerEphem` triggers a DH step _before_ the index is resolved; the previous receiving chain's remaining keys are stored in the skipped cache under the _old_ `peerEphem`.
- A message that cannot be reconciled (gap > 1000, unknown DH epoch, replay past the cache window) is rejected with `ErrRatchetDiverged`.

### 7.4 Skipped cache

See §6.1 for the full data-structure and API specification. The interface as seen from `Ratchet.NextRecv` is:

```go
// On a DH step triggered by a new peerEphem in NextRecv:
//   for each chain key mk at indices [oldRecvCount, newPeerEphem.index):
//     skippedCache.Put(prevPeerEphem, idx, mk)
//
// On a NextRecv with a forward gap (idx > recvCount):
//   step the receiving chain forward to idx (consuming the keys in order, NOT caching them).
//   return the mk for idx.
//
// On a NextRecv with a backward lookup (idx < recvCount):
//   if mk, ok := skippedCache.Get(peerEphem, idx); ok:
//       Ratchet.skipped = true
//       return mk, nil
//   return MessageKey{}, ErrRatchetDiverged
```

The cache is populated **only on DH-step pivots** and **only for keys in the previous chain that the peer is about to "skip over"** (i.e., keys at indices between `oldRecvCount` and the first new-chain index the peer sends us). It is never populated for out-of-order deliveries within a single chain — those keys are computed on demand and consumed immediately.

**Cap = 1000** (hard-coded `const skippedCap = 1000`). This bounds memory at ~41 KB worst case (1000 × `(32+8+32+8)` bytes for key+entry+overhead) and bounds the reorder window to ~1000 messages per chain. Past the window, `ErrRatchetDiverged` is returned.

**Eviction under adversarial load is a known limitation.** A peer that floods the cache via a single chain can evict earlier chains' keys. The fixed-cap is a *defense-in-depth* measure against memory exhaustion, not a *per-chain fairness* property. Per-chain caps are deferred to a future revision (§12).

### 7.5 Control-plane routes

`RouteCloseTransport`, `RoutePing`, `RoutePong` use the same `staticKey` for outer encryption as every other frame. The receiver detects them by `Route` and skips the ratchet step entirely. They carry `RatchetIndex = 0` and `RatchetDH = nil` on the wire; the receiver treats any non-zero values in those fields as `ErrInvalidRatchetKey` (defense in depth).

This decouples liveness / shutdown from ratchet state — close, ping, and pong work even if the ratchet has been desynchronized, because the ratchet is not consulted for them.

The challenge phase (`RouteSendChallenge` / `RouteVerifyChallenge`) is used only during the handshake phase, before the ratchet is wired in. Once the ratchet takes over, those routes never appear on the wire; the receiver still handles them defensively (skip the ratchet step, require zero ratchet fields) as a safety net.

---

## 8. Error handling

New sentinels in `errors.go`:

- `ErrRatchetSkipped` — a message arrived out of order and was decrypted via the skipped cache. **Not returned as an error.** Surfaced as an informational flag on the returned `*Metadata` via `Metadata.Skipped() bool`. Callers that want to detect it can do so without breaking the receive loop.
- `ErrRatchetDiverged` — chain advance could not be reconciled: skipped-cache miss, unknown DH epoch, replay past the cache window, or receive of a malformed `RatchetDH`. Returned by `NextRecv`; mapped to a `Transport.Receive` error.
- `ErrInvalidRatchetKey` — `Metadata.RatchetDH` is the wrong length (anything other than 0 for control-plane or 32 for ratchet-path) or carries inconsistent ratchet fields for its route. Returned directly by `Transport.Receive` before the ratchet is consulted.

Removed sentinels:

- `ErrOutOfSync` — the strict gap-fatal envelope sequence counter is gone; the ratchet's chain index replaces it.

Existing sentinels continue to apply unchanged: `ErrInvalidSignature`, `ErrVerificationFailed`, `ErrUnexpectedRoute`, `ErrInvalidRoute`, `ErrMessageTooLarge`, `ErrConnClosed`, `ErrPeerDisconnected`, `ErrReceiveTimeout`, `ErrVersionMismatch`, `ErrClosedServer`.

---

## 9. Testing strategy

| Test file                          | Coverage                                                                                                                                                                                                                                  |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal/ratchet/chain_test.go`   | KDF chain determinism; chain step is destructive (re-running it gives a different `mk`); nonce derivation uniqueness across `(dh, idx)` pairs                                                                                             |
| `internal/ratchet/skipped_test.go` | Put/Get/eviction; cap honored under overflow; concurrent Put/Get safety                                                                                                                                                                   |
| `internal/ratchet/ratchet_test.go` | Alice↔Bob roundtrip; out-of-order delivery (sender N+1, then N); dropped message (cache hit); DH step symmetry; replay rejection; 1000+ skipped message handling                                                                          |
| `internal/ratchet/vectors_test.go` | Golden vectors committed in-tree for the chain step, the DH-root step, and the nonce derivation                                                                                                                                           |
| `handshake_test.go`                | Ratchet-key init validates lengths (must be exactly 32 bytes); rejects mismatched lengths; both sides construct equal `rootKey0` and equal `staticKey`; replace `SequenceNum()` / `ID()` / `Timestamp()` assertions with `RatchetIndex()` |
| `routes_test.go`                   | No new routes; existing tests cover all routes                                                                                                                                                                                            |
| `transport_test.go` (new)          | End-to-end Send/Receive with ratchet over a `net.Pipe`; ping/pong still works; close still works; verify `RatchetIndex` / `RatchetDH` round-trip on the wire; verify a `staticKey` mismatch aborts the session                            |

A test helper `func newTestRatchetPair(t *testing.T) (*Ratchet, *Ratchet)` constructs two ratchets from a shared `mlkemSecret` and two independent X25519 session keypairs. The ratchet itself is symmetric; the test just instantiates both sides from the same secret.

All tests use real implementations (no mocks) per AGENTS.md.

---

## 10. Documentation updates (`docs/SPEC.md`)

- **§4.2 Signed Transport Envelope** — drop the bullets for `ID` and `Timestamp` in `Metadata`. Show the new minimal `Metadata { Route, RatchetIndex, RatchetDH }`. Call out the wire-incompatible hard cut.
- **§6.8 Ratchet Init (new)** — handshake carries `InitRatchetKey` and `RespRatchetKey`; every outbound message carries the sender's current ratchet pubkey in `Metadata.RatchetDH`.
- **§7.4 Enigma Cipher** — keep; document the new ratchet wrapper that sits on top.
- **§7.5 Key Hierarchy Summary (new rows)** — ratchet root key (`rootKey0`), chain key, message key, static session key.
- **§8 Message Integrity and Replay Protection** — rewrite as three short subsections: §8.1 Signatures, §8.2 Ratchet Ordering (`(RatchetIndex, RatchetDH)` + skipped cache), §8.3 AEAD. The old §8.2 "Sequence Numbers" subsection is replaced.
- **§12.4 Forward Secrecy** — replace "per-session, not per-message" with the per-message + per-DH-step guarantee. State the precise DH cadence: "a fresh DH agreement is established each time the peer's ratchet pubkey is observed in a new message, which mixes a new X25519 secret into the next chain key."
- **§12.6 Replay Protection** — replace with: "The ratchet's skipped cache provides bounded out-of-order tolerance; messages that cannot be reconciled (gap > 1000 or unknown DH epoch) are rejected with `ErrRatchetDiverged`."
- **§13 Protobuf Schema Reference** — show the new `Metadata` and the new `Handshake` fields. No new routes.
- **§14 Constants and Limits** — add `ratchetSkippedCacheCap = 1000`, `ratchetKeySize = 32`, `ratchetNonceSize = 24`, `ratchetDHStepThreshold = 1` (always 1; the DH step happens on the first Send after the peer rotates).
- **§15 Error Conditions** — add `ErrRatchetSkipped`, `ErrRatchetDiverged`, `ErrInvalidRatchetKey`. **Remove `ErrOutOfSync`.**

**Do not** bump `AppVersion` in `version.go`. Per the locked rollout decision, the change ships inside v0.5.0 as a hard cut.

---

## 11. Commit order (per `AGENTS.md`)

1. `kamune: add internal/ratchet package with KDF chain, skipped cache, and DH ratchet`
2. `kamune: extend Handshake and Metadata proto with ratchet fields`
3. `kamune: integrate ratchet into Transport Send/Receive`
4. `kamune: wire ratchet init through handshake orchestrators`
5. `docs: document ratchet in SPEC.md`

Each commit is self-contained, builds, and passes `go test ./... -v` from the root. Commit 1 can land even if the rest is abandoned — the new package is unused by the rest of the codebase. Commit 2 must land before commit 3 (the new `Metadata` fields are referenced by the ratchet frames). Commits 3 and 4 together form the wire-protocol change and must not be bisected by a release.

---

## 12. Out of scope (deliberately deferred)

- **ML-KEM-based DH ratchet.** X25519 is sufficient; using raw 32-byte X25519 pubkeys via `pkg/exchange.ECDH` keeps frames small (one 32-byte field per outbound message). ML-KEM encapsulation per DH step would add ~1KB of overhead per message and is unnecessary for the threat model.
- **Header encryption (X3DH-style).** The static envelope key already protects metadata at the AEAD layer.
- **Multiple concurrent sessions sharing a root key (out-of-band re-keying).** v0.5.0 keeps one ratchet per `Transport`.
- **Per-message DH step (every Send).** Tested and rejected: it replaces the receiving chain on every message, defeating the skipped cache and the chain abstraction. The DH step runs on the first Send after the peer rotates, which preserves chain semantics.
- **Asynchronous out-of-order delivery from a worker pool.** Cache lookups are O(1) on hit, O(1) amortized on miss; no worker pool needed.
- **A public `pkg/ratchet/` API.** The ratchet is implementation detail; `Transport` is the only consumer.
- **Application-visible message IDs and timestamps.** Dropped per §1 — if a future need arises, add them inside the `Transferable` payload, not in `Metadata`.
- **A separate `controlKey`.** Considered and rejected: a single `staticKey` for the outer envelope, with `Route`-based dispatch, is simpler and avoids a constant-time leak from trying one key then the other.
