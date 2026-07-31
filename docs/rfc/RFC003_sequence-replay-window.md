# RFC: Sliding-Window Sequence Validation (Withdrawn)

**Status:** Withdrawn

**Decision:** The proposed sliding-window replay filter is not part of the
Kamune protocol.

**Relates to:** §4 (Signed Transport envelope), §8.1 (Digital Signatures),
§8.2 (Sequence Numbers), §9.4 (Connection Contract), §14 (Error Conditions)

---

## 1. Decision

This RFC proposed accepting a bounded range of reordered sequence numbers and
silently dropping duplicates or stale frames. It is withdrawn.

Kamune requires every `Conn` to provide reliable, in-order frame delivery.
TCP, KCP, and the relay transports satisfy this contract. A duplicate or a gap
therefore indicates a violated connection contract, corrupted peer state, or an
implementation defect. It invalidates the session rather than representing a
recoverable network event.

## 2. Correct Current Behavior

Each transport direction uses a strictly increasing sequence number. The first
received message has sequence `1`; every later message MUST have the previous
received sequence plus one. A lower number is a duplicate and a higher number
is a gap. Both conditions are fatal: the transport closes and all session state
that depends on ordered delivery is discarded.

The `SignedTransport` signature covers the domain-separated signing input:

```
"kamune/transport-sign/v1" || varint(len(MetadataBytes)) ||
MetadataBytes || Data
```

`MetadataBytes` contains the sequence number, route, timestamp, and ID. The
sequence number is therefore protected by both the Ed25519 signature and, for
established sessions, the AEAD authentication tag.

Outbound sequence allocation, serialization, and frame writes are serialized
so a local concurrent sender cannot put later sequence numbers on the wire
before earlier ones.

## 3. Rationale

Accepting a later frame while an earlier one is missing would silently omit an
unknown protocol or application action. It could be a session control message,
a cancellation, or other stateful data. Delivering later frames first would
also change the application delivery contract.

An unordered transport is not a valid `Conn` implementation. Supporting one
would require a separately negotiated protocol with bounded reordering buffers,
ordered application delivery, and explicit loss handling. It is outside this
RFC and the current connection contract.

## 4. Specification Updates

The protocol specification now explicitly requires reliable, in-order inbound
frames from every `Conn` implementation and requires the session to close on a
duplicate or gap. No wire format or version change results from withdrawing
this proposal.
