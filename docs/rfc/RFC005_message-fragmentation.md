# RFC: Message Fragmentation

**Status:** Draft — for discussion, not yet merged into SPEC.md

**Target:** Kamune Protocol Specification v0.7.0

**Relates to:** §4 (Wire Format), §5 (Routes), §9 (Transport Layer),
§13 (Constants and Limits), §14 (Error Conditions)

---

## 1. Summary

The current protocol limits a single user message to `maxTransportSize`
(~60 KiB), the largest payload that fits inside one length-prefixed wire frame
after protocol overhead. This is sufficient for text but blocks multimedia and
larger structured payloads. This RFC proposes transparent message fragmentation:
the transport layer automatically splits an oversized message into multiple
frames and reassembles them on receipt, with no API changes for callers.

## 2. Current Behavior

Per §4.1, every message is transmitted as a single length-prefixed frame:

```
+------------------+--------------------+
| Length (2 bytes)  | Payload (N bytes) |
+------------------+--------------------+
```

The wire-format ceiling is 65,535 bytes (`math.MaxUint16`). The protocol
further limits user messages to `maxTransportSize` = 61,439 bytes (§13), the
wire maximum minus `reservedProtocolOverhead` (signature, metadata, padding,
AEAD tag).

Messages exceeding `maxTransportSize` are rejected at two enforcement points:

1. **Protocol level** — `signedSerde.serialize()` compares the serialized
   message length against `maxTransportSize` and returns `ErrMessageTooLarge`
   if it exceeds the limit.
2. **Wire level** — `Conn.WriteBytes()` compares the encrypted payload against
   `math.MaxUint16` and returns `ErrMessageTooLarge` if it would overflow the
   2-byte length prefix.

The model is strictly one logical message = one wire frame. There is no
infrastructure for splitting a message across frames or reassembling fragments
on receipt.

## 3. Problem Statement

The 60 KiB limit is a hard ceiling on individual messages. Application-layer
workloads that routinely produce larger payloads — image transfers, file
sharing, structured data exports, voice/video fragments — are blocked at the
protocol level. Requiring applications to implement their own chunking, session
management, and reassembly duplicates effort across every client and introduces
incompatible, application-specific conventions that the protocol cannot reason
about (e.g. no per-fragment integrity, no sequence-number discipline).

The limit exists because a single wire frame cannot express payloads larger than
65,535 bytes (the 2-byte length prefix). The natural solution is to transmit a
large message as a sequence of smaller frames that the receiver reassembles into
the original message.

## 4. Requirements

### 4.1 Functional requirements

- R1: A message whose serialized size exceeds `maxTransportSize` MUST be
  automatically split into multiple fragments by the transport layer. Callers
  MUST NOT need to implement any chunking logic.
- R2: The receiver MUST transparently reassemble fragments into the original
  message. `Transport.Receive()` MUST return the complete reassembled message
  to the caller, not individual fragments.
- R3: Each fragment MUST be a self-contained `SignedTransport` envelope,
  independently signed and encrypted, with its own `Metadata` (ID, timestamp,
  sequence number). This preserves per-frame integrity and is consistent with
  the existing signing scheme (§8.1).
- R4: The original message's route (e.g. `RouteExchangeMessages`) MUST be
  preserved and returned to the caller in the synthesized metadata after
  reassembly.
- R5: Fragmentation MUST be bounded. A maximum fragment count per message MUST
  be enforced to prevent memory exhaustion from adversarial or malformed
  traffic.
- R6: Incomplete fragment groups MUST be discarded after a bounded timeout to
  free reassembly state.

### 4.2 Non-functional requirements

- R7: The relay (`§9.3`) MUST require no changes. Each fragment is a
  standard `SignedTransport` and is forwarded opaquely.
- R8: Non-fragmented messages (size ≤ `maxTransportSize`) MUST NOT be affected
  — no additional overhead, no path change, no API change.
- R9: This is a wire-incompatible change: peers that do not understand the new
  fragment route MUST NOT be mixed with peers that do. The change MUST be
  accompanied by a spec version bump.

### 4.3 Non-goals

- This RFC does not define retransmission or reliability for individual
  fragments. The underlying transport (TCP, §9.1) provides reliable delivery.
  Fragment loss at this layer is treated as a session-level timeout, not a
  per-fragment NACK.
- This RFC does not address flow control or back-pressure for large messages.
  The sender transmits all fragments without waiting for receiver
  acknowledgement.

## 5. Proposed Design

### 5.1 Fragment envelope

A new protobuf message wraps each chunk of the original serialized message:

```protobuf
message Fragment {
  bytes  MessageID = 1;   // Groups fragments of the same logical message
  uint32 Index     = 2;   // 0-based fragment index
  uint32 Total     = 3;   // Total number of fragments in this message
  Route  Route     = 4;   // Original route from the sender
  bytes  Data      = 5;   // Chunk of the original serialized message
}
```

- `MessageID` is a random identifier (`rand.Text()`) generated once per logical
  message. It is unguessable and unique, and disambiguates interleaved
  fragments from concurrent large messages.
- `Index` is 0-based. Fragments are ordered: `Index` 0 contains the first
  chunk of the serialized message, `Index` `Total-1` contains the last.
- `Total` is the total fragment count. Every fragment in the same group carries
  the same `Total` value.
- `Route` is the caller's original route (e.g. `RouteExchangeMessages`). The
  `SignedTransport.Metadata.Route` for every fragment is set to
  `RouteFragment`; the original route is preserved inside the signed `Data`
  field and recovered after reassembly.
- `Data` is a prefix of the original serialized message: fragment `i` carries
  bytes `[i * chunkSize, (i+1) * chunkSize)` of the original payload.

### 5.2 New route

```
RouteFragment = 14
```

`RouteFragment` is a transport-internal route. It is never passed to the
application layer; `Transport.Receive()` handles it internally and returns the
reassembled message with the original route.

### 5.3 Fragment size

Each chunk is at most `maxTransportSize` minus the overhead introduced by the
`Fragment` envelope and the `BytesValue` wrapper that carries it through
`signedSerde.serialize()` — roughly 41 bytes of protobuf framing in total. In
practice each fragment carries approximately 61,398 bytes of the original
message, negligible relative to the 60 KiB budget.

The last fragment may carry fewer bytes than the full chunk size. If the
original message's serialized length is exactly divisible by the chunk size, the
last fragment carries a full chunk (i.e. there is no zero-length final fragment).

### 5.4 Send path

When `Transport.Send()` is called:

1. The application message is serialized to bytes (`Data`).
2. If `len(Data) ≤ maxTransportSize`: send as a single frame via the existing
   path (no change).
3. Otherwise:
   a. Generate a random `MessageID`.
   b. Compute `Total = ceil(len(Data) / chunkSize)`.
   c. For each chunk index `i` from `0` to `Total-1`:
   - Extract the `i`-th chunk from `Data`.
   - Build `Fragment{MessageID, Index: i, Total, Route: originalRoute, Data: chunk}`.
   - Wrap the `Fragment` in `kamune.Bytes()`.
   - Call `signedSerde.serialize(fragment, RouteFragment, seq)` to produce a
     signed, padded, encrypted `SignedTransport`.
   - Write the frame to the connection.
   - Increment the send counter.
     d. Return synthesized metadata to the caller (route = original route).

### 5.5 Receive path

When `Transport.Receive()` reads a frame:

1. Decrypt and deserialize the `SignedTransport` as usual.
2. If `metadata.Route() == RouteFragment`:
   a. Decode the `Fragment` from `Data`.
   b. Validate: `Index < Total`, `Total ≤ maxFragmentCount`.
   If invalid, discard the fragment.
   c. Add the fragment to the reassembly buffer, keyed by `MessageID`.
   d. If all `Total` fragments for this `MessageID` have arrived:
   - Concatenate the `Data` fields in index order to reconstruct the
     original serialized message.
   - Decode the original route from the first fragment's `Fragment.Route`.
   - Remove the reassembly entry.
   - Return the reassembled message with synthesized metadata using the
     original route.
     e. If not all fragments have arrived yet, continue reading the next frame
     (do not return to the caller).
3. If the route is not `RouteFragment`: process normally (existing path).

### 5.6 Reassembly state

Per pending (incomplete) message, the receiver maintains:

- `MessageID`: the fragment group identifier.
- `Total`: expected fragment count.
- `Route`: original route (from the first fragment received).
- `Fragments`: a map of `Index → Data` for received chunks.
- `Received`: count of distinct chunks received so far.
- `FirstSeen`: timestamp of the first fragment in this group.

The reassembly buffer is bounded by `maxPendingFragments` (default: 16). If a
new `MessageID` arrives and the buffer is full, the oldest incomplete entry is
discarded silently to make room.

Entries are discarded when:

- All `Total` fragments have arrived (successful reassembly).
- The time since `FirstSeen` exceeds `fragmentReassemblyTimeout` (default: 30
  seconds).

### 5.7 Constants

| Constant                    | Value | Description                                                                   |
| --------------------------- | ----- | ----------------------------------------------------------------------------- |
| `maxFragmentCount`          | 256   | Maximum fragments per logical message. Caps max message at ~15 MiB.           |
| `fragmentReassemblyTimeout` | 30 s  | Time to wait for all fragments before discarding. Matches `handshakeTimeout`. |
| `maxPendingFragments`       | 16    | Maximum concurrent incomplete fragment groups in the reassembly buffer.       |

## 6. Security Considerations

- Each fragment is independently signed (§8.1) and encrypted (§8.4). An
  attacker without the session key cannot inject, modify, or replay individual
  fragments — the same guarantees that apply to non-fragmented messages apply
  to each fragment.
- The `MessageID` is a random, unguessable identifier. An attacker cannot
  inject a fragment into an existing fragment group without knowing this ID.
- `maxFragmentCount` (256) bounds the number of reassembly entries a single
  message can consume. Combined with `maxPendingFragments` (16), total
  reassembly state is bounded at approximately 16 × 256 × 60 KiB = ~240 MiB
  in the worst case. In practice, incomplete entries time out after 30 seconds,
  and legitimate messages rarely approach the maximum fragment count.
- The `fragmentReassemblyTimeout` prevents indefinite accumulation of partial
  state from stalled or adversarial traffic.
- Padding is applied per-fragment, preserving the traffic-analysis resistance
  of the existing bucketed-padding scheme (§12.7). A small final fragment is
  padded to at least the smallest bucket (512 bytes).
- This change is a hard protocol cut: peers that do not understand
  `RouteFragment` will reject fragment frames as unexpected routes. Both sides
  of a session MUST run a compatible version. The version-bump requirement (R9)
  enforces this via the existing pre-1.0 compatibility rules (§6.2).

## 7. Error Conditions

### 7.1 New sentinel

| Sentinel             | Meaning                                                                    |
| -------------------- | -------------------------------------------------------------------------- |
| `ErrFragmentTimeout` | Reassembly timed out: not all fragments arrived within the timeout window. |

### 7.2 Updated §14 Error Table (proposed additions)

| Condition                                | Fatal? | Action                                                  |
| ---------------------------------------- | ------ | ------------------------------------------------------- |
| Fragment `Index ≥ Total`                 | No     | Discard fragment; continue reading.                     |
| Fragment `Total > maxFragmentCount`      | No     | Discard fragment; continue reading.                     |
| Reassembly buffer full (new `MessageID`) | No     | Discard oldest incomplete entry; add new entry.         |
| Reassembly timeout (missing fragments)   | No     | Discard incomplete entry; surface `ErrFragmentTimeout`. |
| Successful reassembly                    | —      | Deliver reassembled message to caller.                  |

All fragment-level errors are non-fatal to the session. A missing or malformed
fragment discards that fragment (or its entire group on timeout) but does not
terminate the connection.
