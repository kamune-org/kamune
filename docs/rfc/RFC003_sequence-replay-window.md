# RFC: Sliding-Window Sequence Validation

**Status:** Draft — for discussion, not yet merged into SPEC.md

**Target:** Kamune Protocol Specification v0.7.0

**Relates to:** Transport layer (§9), Signed Transport envelope (§4)

## 1. Summary

Replace the current strict sequence invariant (`seq == receiveCounter + 1`,
connection-terminating on any deviation) with a bounded sliding-window replay
filter. The new model tolerates message loss and limited reordering without
tearing down the session, while still rejecting duplicate and stale sequence
numbers.

## 2. Current Behavior

Each direction of a session maintains a monotonically increasing send counter
and a receive counter. On send, `Sequence` is set to the next counter value. On
receive, the peer requires:

```
seq == receiveCounter + 1
```

Any other value — lower (duplicate/replay) or higher (gap) — is classified as
an out-of-sync condition. Per §14, an out-of-sync condition is fatal: the
connection MUST be terminated.

`Sequence` lives in the `Metadata` portion of the `SignedTransport` envelope
(§4.2). The Ed25519 signature covers only the `Data` field; `Sequence` is not
independently signed. Integrity of `Sequence` currently relies entirely on the
AEAD tag, since the full serialized `SignedTransport` payload — envelope and all
— is what gets encrypted (§4.3). Nonces for XChaCha20-Poly1305 are independently
random per message (§7.4) and are not derived from `Sequence`.

## 3. Problem Statement

The strict `+1` invariant assumes the receive path only ever observes frames in
exact send order with zero loss. In practice this has proven too fragile: any
deviation — a dropped frame, a reordering event, a race on the send path — kills
the session outright, even though the underlying issue may be transient and
recoverable.

This is disproportionate. A single missed or reordered frame does not indicate a
compromised session; it indicates ordinary network conditions (or, in some cases,
a local bug such as an unsynchronized concurrent writer). Terminating the
connection in response is the wrong failure mode.

## 4. Requirements

### 4.1 Functional requirements

- R1: The receiver MUST accept a message whose sequence number is higher than
  any previously seen value, regardless of gaps below it.
- R2: The receiver MUST accept a message whose sequence number is lower than the
  highest seen value, provided it falls within a bounded window and has not
  already been accepted.
- R3: The receiver MUST reject a message whose sequence number has already been
  accepted (duplicate).
- R4: The receiver MUST reject a message whose sequence number falls outside the
  bounded window (too old).
- R5: Rejections under R3 and R4 MUST NOT be connection-fatal. The frame is
  dropped; the session continues.
- R6: Per-session state for sequence tracking MUST be fixed-size, independent of
  session duration or message volume.

### 4.2 Non-functional requirements

- R7: The change MUST NOT weaken the existing replay/integrity guarantees
  provided by the AEAD layer (§8.4). Sequence validation remains an additional
  layer on top of, not a substitute for, AEAD authentication.
- R8: The change SHOULD require no modification to `Metadata` framing (§4.2) —
  this is a receive-side validation change only.
- R9: The change SHOULD preserve the existing `Transport.Receive()` call
  contract: one call returns either a newly accepted message or a genuine
  (fatal) error, not a "try again" sentinel.

### 4.3 Non-goals

- This RFC does not define reorder-safe delivery to the application layer (i.e.,
  buffering to hand messages to the caller in original send order). Frames are
  accepted and surfaced in the order they are validated, not the order they were
  sent.
- This RFC does not address transport-level retransmission or loss recovery;
  that remains the responsibility of the underlying transport (§9).

## 5. Proposed Design

### 5.1 State

Per receive direction, maintain:

- `highestSeq`: the highest sequence number accepted so far.
- `window`: a fixed-size bitmap of length `W`, tracking which of the last `W`
  sequence numbers relative to `highestSeq` have been accepted.

This replaces the single `receiveCounter` field. State size is `O(W)` and
constant for the life of the session.

### 5.2 Validation algorithm

On receipt of a frame with sequence number `seq`:

| Condition                                                    | Classification         | Action                                                                                              |
| ------------------------------------------------------------ | ---------------------- | --------------------------------------------------------------------------------------------------- |
| `seq > highestSeq`                                           | New, in-order or ahead | Slide `window` forward by `seq - highestSeq`, mark `seq`'s bit, set `highestSeq = seq`. **Accept.** |
| `seq <= highestSeq` and `highestSeq - seq < W` and bit unset | New, reordered         | Mark the bit. **Accept.**                                                                           |
| `seq <= highestSeq` and `highestSeq - seq < W` and bit set   | Duplicate              | **Reject** (non-fatal, drop frame).                                                                 |
| `seq <= highestSeq - W`                                      | Outside window         | **Reject as too-old** (non-fatal, drop frame).                                                      |

### 5.3 Window size (`W`)

Default: `W = 64`, represented as a single `uint64` bitmask. Rationale: the
transport layer (TCP or KCP, §9.1–9.2) is itself reliable and ordered, so
genuine reordering at this layer should be rare and shallow. `W = 64` is
generous headroom for that case while keeping state trivially small. `W` MAY be
made configurable per deployment if experience shows it needs to be larger (e.g.
if a future transport without in-order delivery guarantees is introduced).

### 5.4 Forward-jump sanity bound

Because only a holder of the session's derived key can produce a frame that
passes AEAD decryption at all, an attacker without that key cannot forge a
`Sequence` value to manipulate the window — this is a robustness measure against
local bugs (e.g. counter corruption, overflow), not an external threat.

Recommendation: reject (as a fatal error, not a silent drop) any frame where
`seq - highestSeq` exceeds a large constant bound (e.g. `2^20`). A jump of that
magnitude cannot occur under normal operation and most likely indicates a
corrupted local counter rather than a legitimate message.

### 5.5 Error semantics and API contract

`Receive()` currently returns either a message or a fatal error. Under this
design:

- Fatal errors (signature failure, AEAD failure, malformed frame, unexpected
  route, forward-jump bound exceeded) remain fatal and are returned to the
  caller as before.
- Non-fatal rejections (duplicate, too-old) are handled internally: `Receive()`
  loops past the dropped frame and continues waiting for the next one, rather
  than surfacing an error to the caller.

This preserves the existing one-call-one-message contract (R9) without
introducing a new "drop, retry" state that every call site needs to handle.

Whether non-fatal drops should additionally be surfaced as an observability
event (metric/log callback) for debugging purposes is an open question — see §7.

## 6. Security Considerations

- Sequence numbers are not independently authenticated (no per-field signature);
  their integrity depends on the AEAD tag over the full envelope. This is
  unchanged by this RFC — it was already true under the strict-counter model.
- Accepting a bounded range of "past" sequence numbers does not reintroduce
  nonce reuse risk, since AEAD nonces are independently random per message
  (§7.4) and never derived from `Sequence`.
- The threat model for sequence manipulation is unchanged: an attacker without
  the session key cannot produce a validly-decrypting frame, so cannot exploit
  the widened acceptance window. The only realistic source of anomalous sequence
  numbers is the legitimate peer itself (bug, race condition).
- Widening acceptance from a single valid value to a window of `W` values does
  increase, by a bounded and small constant factor, the space of sequence
  numbers a _legitimate_ but buggy or compromised peer could replay before
  detection. This is judged acceptable given `W` is small (64) and replay of an
  already-processed application message is a data-duplication concern, not a
  confidentiality or authentication one.

## 7. Open Questions

- Default value of `W` — is 64 sufficient, or should it be configurable from the
  start?
- Should non-fatal drops (duplicate/too-old) be surfaced to the application
  layer as an observability event, or handled silently within the transport?
- Exact value of the forward-jump sanity bound in §5.4.

## 8. Updated §14 Error Table (proposed)

Replaces the current single "out-of-sync → terminate" row:

| Condition                                     | Fatal?  | Action                           |
| --------------------------------------------- | ------- | -------------------------------- |
| `seq > highestSeq`                            | No      | Accept, slide window.            |
| `seq` within window, already marked           | No      | Reject as duplicate; drop frame. |
| `seq` outside window (too old)                | No      | Reject as too-old; drop frame.   |
| `seq - highestSeq` exceeds forward-jump bound | **Yes** | Terminate connection.            |
