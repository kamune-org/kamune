# RFC: Consent-Based File Transfer

**Status:** Draft — Third Revision

**Target:** Kamune Protocol Specification v0.7.0

**Relates to:** §4 (Wire Format), §5 (Routes), §6.2 (Introduction),
§9 (Transport Layer), §13 (Constants and Limits), §14 (Error Conditions)

---

## 1. Summary

Kamune frames are limited to `maxTransportSize` (~60 KiB). This RFC adds a
consent-based protocol for transferring files larger than one frame without
changing the semantics of `Transport.Send` or `Transport.Receive`.

A sender first transmits a small offer containing the file's metadata and
SHA-512 digest. The receiver explicitly accepts or declines the offer. Only an
accepted offer permits the sender to stream signed and encrypted chunks. The
receiver streams chunks to application-owned storage and reports completion
only after it verifies the declared size and digest.

This RFC deliberately does not add transparent fragmentation for arbitrary
application messages. A large message remains too large unless it is sent as a
file transfer defined by this RFC.

## 2. Current Behavior

Per §4.1, a single wire frame has a two-byte length prefix and cannot carry
more than 65,535 bytes. `signedSerde.serialize()` rejects a serialized message
larger than `maxTransportSize`; `Conn.WriteBytes()` rejects an encrypted frame
that exceeds the wire maximum.

`RouteSessionData` is the existing extension route. It currently carries the
generic `SessionData` protobuf message. There is no file offer, transfer
approval, chunking, or whole-file integrity protocol.

## 3. Requirements

- R1: File transfer control messages and chunks MUST use `RouteSessionData`.
  No new transport route is introduced.
- R2: A sender MUST send a `FileOffer` before it sends any `FileChunk` for a
  transfer.
- R3: A receiver MUST explicitly accept an offer before it retains or writes a
  chunk for that transfer. The default policy is to accept no offers.
- R4: Every control message and chunk MUST remain an ordinary signed,
  encrypted, sequence-validated transport message.
- R5: The sender MUST provide the exact file size and SHA-512 digest in the
  offer. The receiver MUST verify both before reporting success.
- R6: The protocol MUST stream accepted chunks to application-owned storage;
  it MUST NOT require reassembling a complete file in memory.
- R7: A receiver MUST apply the size limit supplied when it accepts an offer.
  It MUST reject a chunk that would exceed the offered or accepted size.
- R8: Chunks MUST be ordered and indexed from zero. Duplicate, missing, late,
  malformed, or out-of-order chunks MUST fail the transfer.
- R9: The protocol MUST support cancellation and bounded offer and idle
  transfer timeouts. It MUST NOT support resumption after reconnect in v1.
- R10: Terminal transfers MUST ignore duplicate or late control messages and
  chunks.
- R11: The relay MUST require no changes; it forwards the standard encrypted
  frames opaquely.
- R12: The protocol change is wire-incompatible. Implementations MUST bump the
  pre-1.0 minor version so compatible and incompatible peers cannot establish a
  session together.

## 4. Wire Protocol

### 4.1 Transfer envelope

`RouteSessionData` carries a protobuf `TransferEnvelope` with exactly one of
the following payloads:

```protobuf
message TransferEnvelope {
  oneof Payload {
    FileOffer    Offer    = 1;
    FileDecision Decision = 2;
    FileChunk    Chunk    = 3;
    FileCancel   Cancel   = 4;
    FileComplete Complete = 5;
  }
}

message FileOffer {
  bytes  TransferID = 1; // exactly 32 cryptographically random bytes
  string Name       = 2; // display name only; never a filesystem path
  string MediaType  = 3; // optional media type
  uint64 Size       = 4; // exact number of file bytes
  bytes  SHA512     = 5; // exactly 64 bytes
}

message FileDecision {
  bytes TransferID = 1;
  bool  Accept     = 2;
}

message FileChunk {
  bytes  TransferID = 1;
  uint64 Index      = 2;
  bytes  Data       = 3;
}

message FileCancel {
  bytes TransferID = 1;
  enum Reason {
    REASON_UNSPECIFIED = 0;
    REASON_CANCELLED = 1;
    REASON_REJECTED = 2;
    REASON_TIMEOUT = 3;
    REASON_SIZE_MISMATCH = 4;
    REASON_HASH_MISMATCH = 5;
    REASON_IO_FAILURE = 6;
    REASON_PROTOCOL_ERROR = 7;
  }
  Reason Reason = 2;
}

message FileComplete {
  bytes TransferID = 1;
}
```

`TransferID` identifies one transfer for the lifetime of its transport. An
implementation MUST generate it from a cryptographically secure random source.
It MUST reject a transfer ID that is not exactly 32 bytes.

`Name` is descriptive metadata. The protocol neither interprets it as a path
nor selects a receive destination from it.

### 4.2 Chunk size

`FileChunk` MUST be small enough that its complete protobuf encoding fits in
`maxTransportSize`, including the `TransferEnvelope` encoding. Implementations
MUST derive the usable data length from the encoded envelope and MUST NOT rely
on a fixed overhead estimate.

Each `FileChunk.Data` MUST be non-empty. The sender emits consecutive indexes
starting at zero. The last chunk may be smaller than preceding chunks; no
zero-length final chunk is permitted.

## 5. Transfer Flow

### 5.1 Offer and decision

1. The sender determines the complete file size and SHA-512 digest before
   creating an offer.
2. It sends `FileOffer` and starts the offer timeout.
3. The receiver validates the offer fields and exposes its metadata to the
   application. It does not allocate file storage or accept chunks yet.
4. The application either declines or accepts the offer, supplying an
   application-owned writer and an explicit maximum size for this offer.
5. A decline sends `FileDecision{Accept: false}`. The sender MUST send no
   chunks and both peers mark the transfer terminal.
6. An acceptance sends `FileDecision{Accept: true}`. The sender may then begin
   streaming chunks.

The receiver MUST reject an offer whose size exceeds the maximum passed to its
accept operation. A zero-value receiver policy accepts no offer.

### 5.2 Streaming and completion

1. After receiving an accepting decision, the sender reads its source in order,
   emits indexed chunks, and maintains a running SHA-512 digest and byte count.
2. The receiver accepts only the next expected index for an active, accepted
   transfer. It writes the chunk to the supplied writer and updates its own
   running digest and byte count.
3. The sender sends `FileComplete` only after it has emitted exactly the
   offered size and verified its source digest against the offered SHA-512.
4. The receiver accepts completion only when it has received exactly the
   offered size, verified the SHA-512 digest, and observed no protocol error.
5. On successful verification, the receiver reports completion to the
   application and marks the transfer terminal.

The caller owns the writer and its lifecycle. Callers requiring atomic delivery
MUST write to staging storage and promote it only after successful completion.

### 5.3 Cancellation and expiry

Either peer MAY send `FileCancel` for an active transfer. On cancellation,
timeout, disconnect, writer failure, hash mismatch, size mismatch, or protocol
error, the local peer marks the transfer terminal and reports the reason to its
application. It SHOULD send `FileCancel` when the transport remains usable.

The offer timeout and idle-transfer timeout are both 30 seconds. A transfer is
not resumable: a disconnect terminates it, and a new connection requires a new
offer and transfer ID.

## 6. Receiver and Library Model

The core library provides a `TransferManager` that exclusively owns the
transport receive loop while it is active. It decodes `TransferEnvelope`
messages, exposes typed incoming offers and transfer events, and forwards
authenticated non-transfer frames through a generic inbound-message stream.

The manager offers explicit operations to accept or decline a transfer. Its
accept operation takes an `io.Writer` and a per-offer size limit. It does not
perform filesystem path handling, choose a destination, or automatically accept
offers.

The manager retains only bounded control state: active offers, active transfer
metadata, expected chunk indexes, byte counts, and hash state. File contents
are streamed to the caller's writer and are not retained by the manager.

## 7. Error Conditions

| Condition                                          | Action                                                   |
| -------------------------------------------------- | -------------------------------------------------------- |
| Invalid offer or envelope                          | Reject or cancel the transfer; do not create file state. |
| Chunk before acceptance                            | Cancel the transfer; do not write the chunk.             |
| Unknown, duplicate, missing, or out-of-order chunk | Cancel the transfer.                                     |
| Chunk exceeds accepted or offered size             | Cancel the transfer.                                     |
| Writer failure                                     | Cancel the transfer and report the local error.          |
| `FileComplete` with incorrect size or SHA-512      | Cancel the transfer; never report success.               |
| Offer or idle-transfer timeout                     | Mark terminal and report timeout.                        |
| Disconnect                                         | Mark every active transfer terminal; no resumption.      |
| Late message for a terminal transfer               | Ignore it.                                               |

Transfer failures are scoped to the transfer. Authentication, decryption, and
transport sequence failures retain their existing session-level behavior.

## 8. Security Considerations

- Transport encryption and signatures protect every offer, decision, chunk,
  cancellation, and completion message. SHA-512 additionally verifies that the
  complete received object matches the sender's declared content.
- Explicit acceptance prevents a peer from forcing file storage allocation or
  writes before the receiver's application consents.
- A receiver validates fixed-size IDs and digests, exact byte totals, indexes,
  and its explicit accepted-size limit before completing a transfer.
- Random transfer IDs prevent accidental cross-transfer association. They are
  not relied on as an authorization mechanism; authenticated session transport
  provides that protection.
- Display names are untrusted metadata. Implementations MUST NOT treat them as
  paths or permit them to control destination selection.
- Active offer and transfer counts MUST be bounded by the implementation. The
  protocol stores only control state in memory; file bytes are streamed.
- The existing pre-1.0 minor-version check prevents a peer that does not
  understand `TransferEnvelope` from establishing a session with one that does.

## 9. Non-Goals

- Transparent fragmentation of arbitrary `Transport.Send` messages.
- Transfer resumption after a reconnect.
- Automatic file destination selection, persistence, cleanup, or atomic rename.
- Daemon events, bus UI, progress display, and application-specific storage
  policy.
