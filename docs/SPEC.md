# Kamune Protocol Specification

**Version:** 0.6.0

**Status:** Experimental

**Suite:** `Ed25519_MLKEM768_HKDF-SHA512_ChaCha20-Poly1305X`

**Authors:** Kamune core team

---

## Table of Contents

1. [Overview](#1-overview)
2. [Terminology](#2-terminology)
3. [Cipher Suite](#3-cipher-suite)
4. [Wire Format](#4-wire-format)
   - 4.1 [Length-Prefixed Framing](#41-length-prefixed-framing)
   - 4.2 [Envelope Fields](#42-envelope-fields)
   - 4.3 [Encrypted Messages](#43-encrypted-messages)
5. [Routes](#5-routes)
   - 5.1 [Route Validation Rules](#51-route-validation-rules)
6. [Protocol Flow](#6-protocol-flow)
   - 6.1 [Exchange](#61-exchange)
   - 6.2 [Introduction](#62-introduction)
   - 6.3 [Handshake](#63-handshake)
   - 6.4 [Challenge Exchange](#64-challenge-exchange)
   - 6.5 [Communication](#65-communication)
   - 6.6 [Session Teardown](#66-session-teardown)
   - 6.7 [Keep-Alive](#67-keep-alive)
   - 6.8 [Session Resumption](#68-session-resumption)
7. [Encryption and Key Derivation](#7-encryption-and-key-derivation)
   - 7.1 [Exchange Phase Keys](#71-exchange-phase-keys)
   - 7.2 [Handshake Phase Key Derivation](#72-handshake-phase-key-derivation)
   - 7.3 [Challenge Tokens](#73-challenge-tokens)
   - 7.4 [Enigma Cipher](#74-enigma-cipher)
   - 7.5 [Key Hierarchy Summary](#75-key-hierarchy-summary)
   - 7.6 [Resumption Token Derivation](#76-resumption-token-derivation)
8. [Message Integrity and Replay Protection](#8-message-integrity-and-replay-protection)
   - 8.1 [Digital Signatures](#81-digital-signatures)
   - 8.2 [Sequence Numbers](#82-sequence-numbers)
   - 8.3 [AEAD Authentication](#83-aead-authentication)
   - 8.4 [Multi-Layer Integrity](#84-multi-layer-integrity)
9. [Transport Layer](#9-transport-layer)
   - 9.1 [TCP](#91-tcp)
   - 9.2 [UDP (via KCP)](#92-udp-via-kcp)
   - 9.3 [Relay](#93-relay)
   - 9.4 [Connection Contract](#94-connection-contract)
10. [Server and Dialer](#10-server-and-dialer)
    - 10.1 [Server (Responder Role)](#101-server-responder-role)
    - 10.2 [Dialer (Initiator Role)](#102-dialer-initiator-role)
    - 10.3 [Role Summary](#103-role-summary)
11. [Storage and Persistence](#11-storage-and-persistence)
    - 11.1 [Database](#111-database)
    - 11.2 [Database Encryption](#112-database-encryption)
    - 11.3 [Stored Entities](#113-stored-entities)
    - 11.4 [Peer Expiration](#114-peer-expiration)
12. [Security Properties](#12-security-properties)
    - 12.1 [Confidentiality](#121-confidentiality)
    - 12.2 [Integrity](#122-integrity)
    - 12.3 [Authentication](#123-authentication)
    - 12.4 [Forward Secrecy](#124-forward-secrecy)
    - 12.5 [Post-Quantum Resistance](#125-post-quantum-resistance)
    - 12.6 [Replay Protection](#126-replay-protection)
    - 12.7 [Traffic Analysis Resistance](#127-traffic-analysis-resistance)
13. [Constants and Limits](#13-constants-and-limits)
14. [Error Conditions](#14-error-conditions)
15. [Merged RFCs](#15-merged-rfcs)

---

## 1. Overview

Kamune is a peer-to-peer communication protocol designed for secure, real-time
messaging over untrusted networks. It provides end-to-end encryption with
post-quantum resistance, forward secrecy, mutual authentication, and message
integrity.

The protocol operates in four sequential stages — **Exchange**, **Introduction**,
**Handshake**, and **Communication** — establishing a cryptographically secured
bidirectional channel between two peers without requiring an intermediary server.
When the session ends, a **Session Teardown** phase sends a close notification
before closing the transport, allowing peers to distinguish a graceful
disconnect from a network failure.

<picture>
  <img alt="Protocol Overview" src="../assets/diagrams/protocol-overview.svg">
</picture>

---

## 2. Terminology

| Term                     | Definition                                                                                                                                                                                                                         |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Initiator (Client)**   | The party that opens the connection and begins the protocol exchange.                                                                                                                                                              |
| **Responder (Server)**   | The party that accepts the connection and responds to protocol messages.                                                                                                                                                           |
| **Attester**             | The cryptographic identity holder; signs messages with its private key.                                                                                                                                                            |
| **Identifier**           | The verification counterpart of an Attester; verifies signatures with a public key.                                                                                                                                                |
| **Peer**                 | A remote party identified by its public key, name, and timestamps.                                                                                                                                                                 |
| **Transport**            | The encrypted, session-aware communication channel between two peers.                                                                                                                                                              |
| **Underlying Transport** | The encrypted connection used during Introduction and Handshake.                                                                                                                                                                   |
| **HPKE**                 | Hybrid Public Key Encryption (RFC 9180). Performs key encapsulation and key schedule derivation in a single operation during the Exchange phase. Configured with MLKEM768-X25519 KEM, HKDF-SHA512 KDF, and ChaCha20-Poly1305 AEAD. |
| **Enigma**               | The symmetric encryption/decryption engine wrapping XChaCha20-Poly1305 with keys derived via HKDF-SHA512.                                                                                                                          |
| **Route**                | A typed tag on each message's Metadata identifying its purpose and protocol phase.                                                                                                                                                 |
| **Fingerprint**          | A human-readable representation of a public key (emoji, hex, base64, or pseudonym).                                                                                                                                                |
| **Transcript Hash**      | A SHA-256 hash over the inner handshake field values, bound into challenge derivation to prevent replay and downgrade attacks.                                                                                                     |
| **Resumption Token**     | A single-use, 32-byte cryptographic value derived from the session's shared secret, presented by the initiator to authorize session resumption without repeating the Introduction phase.                                           |
| **Resumption Window**    | The 24-hour period after a session is established during which its resumption tokens remain valid.                                                                                                                                 |
| **Resumption Root**      | A secret derived once at session establishment from the shared secret and session ID, used solely to derive the resumption token set. Never exposed to the application.                                                            |

---

## 3. Cipher Suite

Kamune provides `Ed25519_MLKEM768_HKDF-SHA512_ChaCha20-Poly1305X` cipher suite.

<picture>
  <img alt="Cipher Suite Architecture" src="../assets/diagrams/cipher-suite.svg">
</picture>

| Component                | Algorithm          | Purpose                                                                                                                        |
| ------------------------ | ------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| **Identity Signing**     | Ed25519            | Digital signatures for authentication and message integrity during Introduction, Handshake, and all signed transports.         |
| **Key Establishment**    | MLKEM768           | Performs key encapsulation and derives the shared key schedule in a single operation. Ephemeral keypairs are used per session. |
| **Key Derivation**       | HKDF-SHA512        | HMAC-based extract-and-expand function to bind derived secrets to the session.                                                 |
| **Transport Encryption** | ChaCha20-Poly1305X | Extended-nonce AEAD cipher for bidirectional message encryption and authentication during the Communication phase.             |

---

## 4. Wire Format

<picture>
  <img alt="Wire Format" src="../assets/diagrams/wire-format.svg">
</picture>

### 4.1 Length-Prefixed Framing

All messages are transmitted using a **length-prefixed framing** protocol over
the underlying transport. The protocol is transport-agnostic; see §9.4 for the
connection contract that any transport must satisfy:

```
+------------------+--------------------+
| Length (2 bytes)  | Payload (N bytes) |
+------------------+--------------------+
```

- **Length**: A 2-byte unsigned integer in **big-endian** byte order indicating
  the size of the payload in bytes.
- **Payload**: The serialized message, exactly `Length` bytes long.
- **Wire format maximum**: 65,535 bytes (uint16 max). The length prefix is a
  2-byte unsigned integer, so payloads larger than 65,535 bytes cannot be
  expressed on the wire.
- **Protocol limit (`maxTransportSize`)**: A separate, smaller value that bounds
  the user-message size. Defined as 65,535 minus `reservedProtocolOverhead`.
  See §13 for current values.

Peers MUST reject any frame whose declared length exceeds 65,535 bytes, and MUST
reject any user message whose size would exceed `maxTransportSize`.

The length prefix is always written and read atomically. The receiver MUST
consume exactly `Length` bytes for the payload before processing it; partial
payloads are not a valid message boundary.

### 4.2 Envelope Fields

Every protocol message is wrapped in a `SignedTransport` envelope:

```
SignedTransport {
  bytes    Data      = 1;   // Serialized inner message
  bytes    Signature = 2;   // Digital signature over Data
  Metadata Metadata  = 3;   // Message metadata (ID, timestamp, sequence, route)
  bytes    Padding   = 4;   // Random padding (bucketed; see §12.7)
}
```

| Field       | Type       | Role                                                                                                                                                                 |
| ----------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Data`      | bytes      | The serialized inner message (for example, an `Introduce` or `Handshake` message, or application data).                                                              |
| `Signature` | bytes      | Ed25519 signature over the raw `Data` bytes, produced with the sender's identity private key.                                                                        |
| `Metadata`  | `Metadata` | Message metadata: unique ID, timestamp, sequence number, and route.                                                                                                  |
| `Padding`   | bytes      | Random bytes that pad the marshaled envelope up to a bucketed target size (see §12.7). Padding is part of the signed envelope and is verified alongside the message. |

The `Metadata` field is itself a structured message:

```
Metadata {
  string                    ID        = 1;
  google.protobuf.Timestamp Timestamp = 2;
  uint64                    Sequence  = 3;
  Route                     Route     = 4;
}
```

| Field       | Type      | Role                                                          |
| ----------- | --------- | ------------------------------------------------------------- |
| `ID`        | string    | Unique message identifier (random text).                      |
| `Timestamp` | Timestamp | Sender's claimed send time.                                   |
| `Sequence`  | uint64    | Monotonically increasing per-session send counter (see §8.2). |
| `Route`     | `Route`   | Identifies the message's purpose and protocol phase (see §5). |

### 4.3 Encrypted Messages

Once a session is established (after the Handshake and Challenge Exchange), the
entire serialized `SignedTransport` payload is encrypted before transmission:

```
Wire format for encrypted messages:
+------------------+--------------------------------------+
| Length (2 bytes)  | XChaCha20-Poly1305 Ciphertext       |
+------------------+--------------------------------------+

Ciphertext layout:
+-------------------+---------------------------+---------+
| Nonce (24 bytes)  | Encrypted SignedTransport | Tag     |
+-------------------+---------------------------+---------+
```

The 24-byte nonce is generated randomly for each encryption operation and
prepended to the ciphertext. The Poly1305 authentication tag is appended by the
AEAD construction.

The same encryption scheme (XChaCha20-Poly1305) is also used for the HPKE
Exchange phase, which establishes an encrypted tunnel for the Introduction and
Handshake messages.

---

## 5. Routes

Routes are typed tags embedded in every `SignedTransport` message. They identify
the message's purpose and enforce the expected protocol state-machine
transitions.

```
enum Route {
  ROUTE_INVALID            = 0;
  ROUTE_IDENTITY           = 1;
  ROUTE_REQUEST_HANDSHAKE  = 2;
  ROUTE_ACCEPT_HANDSHAKE   = 3;
  ROUTE_FINALIZE_HANDSHAKE = 4;
  ROUTE_SEND_CHALLENGE     = 5;
  ROUTE_VERIFY_CHALLENGE   = 6;
  ROUTE_EXCHANGE_MESSAGES  = 7;
  ROUTE_CLOSE_TRANSPORT    = 8;
  ROUTE_PING               = 9;
  ROUTE_PONG               = 10;
  ROUTE_RESUME_REQUEST     = 11;
  ROUTE_RESUME_ACCEPT      = 12;
}
```

| Value | Name                       | Phase         | Direction             | Purpose                                      |
| ----- | -------------------------- | ------------- | --------------------- | -------------------------------------------- |
| `0`   | `ROUTE_INVALID`            | —             | —                     | Invalid/unset route. MUST be rejected.       |
| `1`   | `ROUTE_IDENTITY`           | Introduction  | Bidirectional         | Identity exchange (`Introduce` message).     |
| `2`   | `ROUTE_REQUEST_HANDSHAKE`  | Handshake     | Initiator → Responder | ML-KEM public key, salt, and session prefix. |
| `3`   | `ROUTE_ACCEPT_HANDSHAKE`   | Handshake     | Responder → Initiator | KEM ciphertext, salt, and session suffix.    |
| `4`   | `ROUTE_FINALIZE_HANDSHAKE` | Handshake     | —                     | Reserved for future handshake finalization.  |
| `5`   | `ROUTE_SEND_CHALLENGE`     | Challenge     | Bidirectional         | Challenge token (encrypted).                 |
| `6`   | `ROUTE_VERIFY_CHALLENGE`   | Challenge     | Bidirectional         | Challenge response echo (encrypted).         |
| `7`   | `ROUTE_EXCHANGE_MESSAGES`  | Communication | Bidirectional         | Application-layer messages.                  |
| `8`   | `ROUTE_CLOSE_TRANSPORT`    | Communication | Bidirectional         | Graceful session teardown.                   |
| `9`   | `ROUTE_PING`               | Keep-Alive    | Bidirectional         | Ping message with 8-byte random token.       |
| `10`  | `ROUTE_PONG`               | Keep-Alive    | Bidirectional         | Pong response echoing the ping token.        |
| `11`  | `ROUTE_RESUME_REQUEST`     | Resumption    | Initiator → Responder | Session ID and resumption token.             |
| `12`  | `ROUTE_RESUME_ACCEPT`      | Resumption    | Responder → Initiator | Acceptance or rejection of resume request.   |

### 5.1 Route Validation Rules

- Routes `1–6` are **handshake routes** and MUST only appear during session
  establishment.
- Routes `7–8` are **session routes** and MUST only appear after a session is
  fully established.
  - Route `8` (`ROUTE_CLOSE_TRANSPORT`) signals a **graceful teardown**.
    Upon receiving this route, the receiver MUST close the session and surface
    a peer-disconnected condition to the application layer. No further
    messages should be processed for this session.
- Routes `9–10` are **keep-alive routes** for application-level ping/pong.
  The `Transport` layer automatically responds to `ROUTE_PING` messages with a
  `ROUTE_PONG` echo.
- Routes `11–12` are **resumption routes** and MUST only appear during session
  resumption, after the Exchange phase but before the Handshake. If the server
  does not support resumption, receiving `ROUTE_RESUME_REQUEST` MUST be treated
  as an unexpected-route condition.
- Route `4` (`ROUTE_FINALIZE_HANDSHAKE`) is defined in the enum but is
  **reserved** and not currently used by the protocol.
- Any message with `ROUTE_INVALID` (`0`) or an unrecognized route value MUST
  be rejected.

---

## 6. Protocol Flow

A new session establishment consists of three sub-protocols executed in
sequence: Introduction, Handshake, and Challenge Exchange. The Exchange phase
precedes all three to provide an encrypted tunnel for the handshake messages.
Peers who have previously established a session may alternatively use the
resumption path described in §6.8, which replaces the Introduction phase with
a token-based authorization exchange.

<picture>
  <img alt="Session Phases" src="../assets/diagrams/session-phases.svg">
</picture>

### 6.1 Exchange

The Exchange phase establishes an encrypted tunnel over the raw connection
using HPKE (Hybrid Public Key Encryption, RFC 9180) with the MLKEM768-X25519
hybrid KEM. This protects the subsequent Introduction and Handshake messages
from eavesdropping.

The HPKE domain-separation info string is empty (null).

```
Initiator (Client)             Responder (Server)
       |                            |
       |  ------ frame -----------> |
       |      HPKE Public Key       |
       |                            |
       |  <------ frame ----------  |
       |      enc || HPKE Public Key|
       |      (length-prefixed)     |
       |                            |
       |  ------ frame -----------> |
       |      enc                   |
       |                            |
```

**Step-by-step (Initiator):**

1. Generate an ephemeral HPKE key pair using the MLKEM768-X25519 KEM and send
   the public key to the responder.
2. Receive the merged message (a 2-byte length prefix for `enc`, followed by
   `enc`, followed by the responder's public key), create an HPKE recipient
   context using the local private key and the responder's `enc`, and create
   an HPKE sender context from the responder's public key.
3. Generate and send the encapsulated ciphertext (`enc`) to the responder.

**Step-by-step (Responder):**

1. Receive the initiator's public key, create an HPKE sender context, and
   generate an ephemeral HPKE key pair.
2. Send the encapsulated ciphertext (`enc`) and public key as a single merged
   message (2-byte length prefix + ciphertext + public key).
3. Receive the initiator's encapsulated ciphertext (`enc`) and create an HPKE
   recipient context using the local private key and the initiator's `enc`.

Both sides now hold a paired sender and recipient, enabling bidirectional
authenticated encryption. The encrypted tunnel carries the remaining handshake
messages transparently.

### 6.2 Introduction

The Introduction phase establishes mutual awareness of each peer's identity.

```
Introduce {
  string Name       = 1;  // Human-readable peer name
  bytes  PublicKey  = 2;  // Identity public key (PKIX/DER)
  string AppVersion = 3;  // Application semver
}
```

| Field        | Type   | Role                                                                                           |
| ------------ | ------ | ---------------------------------------------------------------------------------------------- |
| `Name`       | string | Human-readable peer name. Defaults to a SHA-256 fingerprint of the public key, base64-encoded. |
| `PublicKey`  | bytes  | The peer's identity public key (Ed25519), serialized in PKIX/DER format.                       |
| `AppVersion` | string | The peer's application semver (for example, `"0.5.0"`).                                        |

```
Initiator (Client)                          Responder (Server)
       |                                           |
       |  ---- SignedTransport[IDENTITY] ------>   |
       |        Introduce { ... }                  |
       |                                           |
       |   <---- SignedTransport[IDENTITY] -----   |
       |         Introduce { ... }                 |
       |                                           |
```

**Step-by-step:**

1. **Initiator sends `Introduce`** (route: `ROUTE_IDENTITY`):
   - The `SignedTransport` envelope's signature is computed over the serialized
     `Introduce` message using the initiator's identity private key.

2. **Responder receives and validates**:
   - Parses the `PublicKey` using the appropriate identity-algorithm parser.
   - Verifies the signature over `Data` using the parsed public key.
   - If signature verification fails, the connection MUST be terminated.
   - Checks `AppVersion` against its own version using semver comparison.
     Version matching follows a three-tier policy:

     | Condition                        | Action                                                                                                                                                                                              |
     | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
     | Major differs                    | **Hard reject** — connection terminated as an incompatible version. Different major versions imply incompatible protocol semantics.                                                                 |
     | Minor differs (pre-1.0, major=0) | **Hard reject** — treated as a breaking change before v1.0. Connection terminated as an incompatible version.                                                                                       |
     | Minor differs (major ≥ 1)        | **Warning** — the connection proceeds, but a structured warning is recorded. Client applications SHOULD surface this warning to the user, as the remote peer may have a newer or older feature set. |
     | Only patch differs               | **Silent ignore** — patch versions are always compatible and the difference is not checked.                                                                                                         |

   - The responder's **Remote Verifier** is invoked — a pluggable callback
     that decides whether to accept or reject the peer. The default
     implementation displays the peer's emoji and hex fingerprints and prompts
     for interactive confirmation. Known peers are looked up in persistent
     storage; new peers may be stored upon acceptance.

3. **Responder sends its own `Introduce`** (route: `ROUTE_IDENTITY`):
   - Same structure as step 1, but with the responder's identity.

4. **Initiator receives and validates**:
   - Same verification as step 2, applied to the responder's introduction.

After both introductions are verified and accepted, both sides hold each
other's authenticated public key and proceed to the Handshake.

### 6.3 Handshake

<picture>
  <img alt="Handshake Flow" src="../assets/diagrams/handshake-flow.svg">
</picture>

The Handshake phase uses post-quantum MLKEM768 to establish a shared key and
derive session-specific symmetric encryption keys. The HPKE-encrypted tunnel
from the Exchange phase is used as transport.

```
Handshake {
  bytes  Key        = 1;  // MLKEM768 public key or KEM ciphertext
  bytes  Salt       = 2;  // 16 bytes of random salt
  string SessionKey = 3;  // 10-char base32 session prefix or suffix
}
```

| Field        | Type   | Role                                                                                       |
| ------------ | ------ | ------------------------------------------------------------------------------------------ |
| `Key`        | bytes  | MLKEM768 public key (request) or KEM ciphertext (response).                                |
| `Salt`       | bytes  | 16 bytes of cryptographically random salt generated by the sender.                         |
| `SessionKey` | string | 10-character base32 half of the session ID — prefix from initiator, suffix from responder. |

```
Initiator                                    Responder
    |                                            |
    |  ---- SignedTransport[REQUEST_HS] ----->   |
    |        Handshake {                         |
    |          Key:  MLKEM PublicKey             |
    |          Salt: 16 random bytes,            |
    |          SessionKey: 10-char prefix        |
    |        }                                   |
    |                                            |
    |   <---- SignedTransport[ACCEPT_HS] -----   |
    |         Handshake {                        |
    |          Key: KEM enc (encapsulated key)   |
    |          Salt: 16 random bytes,            |
    |          SessionKey: 10-char suffix        |
    |         }                                  |
    |                                            |
```

**Step-by-step:**

1. **Initiator generates an ephemeral MLKEM key pair**:
   - A fresh key pair is generated. This key pair is **ephemeral** — used for
     this session only and discarded afterward.

2. **Initiator generates session parameters**:
   - `localSalt`: 16 bytes of cryptographically random data.
   - `sessionPrefix`: 10 characters of random base32 text (uppercase A-Z,
     2-7), generated from the custom alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`.

3. **Initiator sends `Handshake` request** (route: `ROUTE_REQUEST_HANDSHAKE`):
   - `Key`: The MLKEM public key bytes.
   - `Salt`: The initiator's local salt.
   - `SessionKey`: The session-ID prefix.
   - Wrapped in a `SignedTransport` envelope signed with the initiator's
     identity key.

4. **Responder receives and validates the request**:
   - The `SignedTransport` signature is verified using the initiator's public
     key (from the Introduction phase).
   - The route is validated to be `ROUTE_REQUEST_HANDSHAKE`.
   - The salt length and the session-key length are validated; any other size
     is rejected.

5. **Responder generates session parameters**:
   - `localSalt`: 16 bytes of cryptographically random data.
   - `sessionSuffix`: 10 characters of random base32 text.
   - `sessionID`: Concatenation of `sessionPrefix + sessionSuffix` (20
     characters total).

6. **Responder performs MLKEM encapsulation**:
   - Encapsulates against the initiator's public key, deriving the shared
     secret and producing the encapsulated key (`enc`).

7. **Responder creates per-direction symmetric ciphers**:
   - **Outbound (responder → initiator)**:
     derived from the shared secret, the responder's local salt, and
     `sessionID + "kamune/handshake/server-to-client/v1"`.
   - **Inbound (initiator → responder)**:
     derived from the shared secret, the initiator's salt, and
     `sessionID + "kamune/handshake/client-to-server/v1"`.
   - The domain-separated directional info strings and per-side salts ensure
     the two directions use distinct keys.

8. **Responder sends `Handshake` response** (route: `ROUTE_ACCEPT_HANDSHAKE`):
   - `Key`: The KEM encapsulated key (`enc`).
   - `Salt`: The responder's local salt.
   - `SessionKey`: The session-ID suffix.

9. **Initiator receives the response and derives the secret**:
   - Verifies the signature and route.
   - Validates the salt length and the session-key length.
   - Constructs `sessionID = sessionPrefix + sessionSuffix`.
   - Decapsulates the responder's `enc` to derive the same shared secret.

10. **Initiator creates per-direction symmetric ciphers** (mirrored):
    - **Outbound (initiator → responder)**:
      derived from the shared secret, the initiator's salt, and
      `sessionID + "kamune/handshake/client-to-server/v1"`.
    - **Inbound (responder → initiator)**:
      derived from the shared secret, the responder's salt, and
      `sessionID + "kamune/handshake/server-to-client/v1"`.

11. **Both compute the transcript hash**:
    - `transcriptHash = SHA-256("kamune/handshake/v1" || for each field in {req.Key, req.Salt, req.SessionKey, resp.Key, resp.Salt, resp.SessionKey} { uint32_be(len(field)) || field })`.
    - The hash binds both inner handshake payloads together, in the order
      they appear above, and is used in the subsequent Challenge Exchange.

At this point, both parties hold the same shared secret, matching per-direction
cipher pairs, and a shared transcript hash. The ephemeral MLKEM private key is
discarded.

### 6.4 Challenge Exchange

The Challenge phase is a mutual proof-of-possession protocol that confirms
both parties can correctly encrypt and decrypt using their derived session
keys.

```
Initiator                                     Responder
    |                                             |
    |  ---- Encrypted[SEND_CHALLENGE] -------->   |
    |        challenge_c                          |
    |                                             |
    |  <---- Encrypted[VERIFY_CHALLENGE] ------   |
    |        echo(challenge_c)                    |
    |                                             |
    |  <---- Encrypted[SEND_CHALLENGE] --------   |
    |        challenge_s                          |
    |                                             |
    |  ---- Encrypted[VERIFY_CHALLENGE] ------>   |
    |        echo(challenge_s)                    |
    |                                             |
    |       [Both: Phase = Established]           |
```

**Step-by-step:**

1. **Initiator generates and sends challenge**:
   - Derives a 32-byte challenge token:
     `HKDF-SHA512(secret, nil, sessionID + "|" + handshakeC2SInfo + "|" + transcriptHash, 32)`.
     The `secret` is the shared secret from the Handshake phase and
     `handshakeC2SInfo` is `"kamune/handshake/client-to-server/v1"`.
   - The transcript hash binds the challenge to the specific handshake
     payloads, preventing replay and downgrade attacks.
   - Encrypts and sends the token (route: `ROUTE_SEND_CHALLENGE`). This is
     the first message encrypted with the session's symmetric keys.

2. **Responder receives, decrypts, and echoes**:
   - Receives and decrypts the challenge.
   - Re-encrypts the same challenge bytes with its outbound cipher.
   - Sends the echo back (route: `ROUTE_VERIFY_CHALLENGE`).

3. **Initiator verifies the echo**:
   - Decrypts the response and performs a **constant-time comparison** against
     the original challenge.
   - If the comparison fails, the handshake MUST be aborted.

4. **Responder generates and sends its own challenge**:
   - Derives a 32-byte challenge token:
     `HKDF-SHA512(secret, nil, sessionID + "|" + handshakeS2CInfo + "|" + transcriptHash, 32)`
     where `handshakeS2CInfo` is `"kamune/handshake/server-to-client/v1"`.
   - Encrypts and sends it (route: `ROUTE_SEND_CHALLENGE`).

5. **Initiator receives, decrypts, and echoes**:
   - Same echo protocol as step 2.

6. **Responder verifies the echo**:
   - Same verification as step 3.

7. **Both parties enter the `Established` phase**.

The challenge exchange proves that:

- The initiator can decrypt messages encrypted by the responder (and vice
  versa).
- Both parties derived the same shared secret and exported identical keys.
- The session ID is agreed upon.

### 6.5 Communication

Once the session is `Established`, peers exchange application messages using
the `Transport`:

<picture>
  <img alt="Message Pipeline" src="../assets/diagrams/message-pipeline.svg">
</picture>

**Sending a message:**

1. The sender increments its send counter (starting from 0; the first message
   is sequence 1).
2. The application message is serialized.
3. The serialized message is signed with the sender's identity key.
4. The signature, message bytes, and metadata (ID, timestamp, sequence, and
   route) plus random padding are assembled into a `SignedTransport` envelope.
5. The entire `SignedTransport` is serialized to bytes.
6. The bytes are encrypted using the sender's outbound cipher
   (XChaCha20-Poly1305 with a fresh 24-byte random nonce).
7. The ciphertext is written to the connection using length-prefixed framing.

**Receiving a message:**

1. The receiver reads the length prefix and then the full ciphertext payload.
2. The ciphertext is decrypted using the receiver's inbound cipher.
3. The decrypted bytes are deserialized into a `SignedTransport` envelope.
4. The signature is verified against the remote peer's public key.
5. The sequence number is validated: it MUST equal the last received
   sequence + 1.
   - If the sequence is **less than** expected, the message is a duplicate and
     MUST be rejected.
   - If the sequence is **greater than** expected, messages have been lost and
     an out-of-sync condition MUST be surfaced.
6. The receive counter is updated.
7. The inner message is deserialized into the expected type.
8. The route and metadata are returned to the application layer.

### 6.6 Session Teardown

When a peer decides to close a session, it performs a **graceful teardown**:

1. The peer sends a `ROUTE_CLOSE_TRANSPORT` message with an empty payload,
   encrypted as a regular session message.
2. After the close message is written, the underlying transport connection
   is closed.
3. The receiving peer decrypts the message, detects `ROUTE_CLOSE_TRANSPORT`,
   and surfaces a peer-disconnected condition from its receive operation.
4. The receiving peer's receive loop exits cleanly, and the application may
   surface a "Peer disconnected" notification.

If the transport connection is dropped without a `ROUTE_CLOSE_TRANSPORT` message
(for example, network failure, crash), the receiving peer surfaces a
connection-closed condition instead. This allows applications to distinguish:

| Condition         | Meaning                                            |
| ----------------- | -------------------------------------------------- |
| Peer disconnected | Remote peer closed the session gracefully.         |
| Connection closed | The connection was dropped (network issue, crash). |

The close message is sent **best-effort** — if the connection is already broken,
the send is skipped and the transport is closed directly.

### 6.7 Keep-Alive

Peers may probe liveness using an application-level ping/pong exchange over
routes `9` and `10`. Ping/pong messages follow the same sequence-number space
and encryption as session messages.

**Ping flow:**

1. The caller generates 8 random bytes as a freshness token.
2. Sends the token with route `ROUTE_PING`.
3. Sets a read deadline on the connection to the provided timeout.
4. Waits for a response.
5. Verifies the received route is `ROUTE_PONG` and the echoed data matches
   the original token.
6. If the token does not match, the ping is treated as failed.
7. Clears the read deadline.

**Pong handler:**

The peer's application code SHOULD register a handler for `ROUTE_PING` that
echoes the data back with `ROUTE_PONG`.

### 6.8 Session Resumption

Resumption allows two peers who have previously completed a full session to
re-establish communication without repeating the Introduction phase. The
underlying connection and all in-memory transport state are destroyed on
disconnect; resumption produces a **new session** — fresh handshake, fresh keys,
fresh sequence counters — distinguished from a cold start only by reusing the
original session ID and skipping the remote-verifier callback. (RFC001)

Resumption tokens are derived from the MLKEM768 shared secret established during
the session's handshake (§7.6). The protocol flow is as follows:

```
Initiator                                   Responder
    |                                            |
    |  ------- Exchange (HPKE tunnel) -------->  |   (§6.1, unchanged)
    |                                            |
    |  ---- SignedTransport[RESUME_REQUEST] -->  |
    |        ResumeRequest {                     |
    |          SessionID: <original ID>          |
    |          Token: token_n                    |
    |        }                                   |
    |                                            |
    |  <--- SignedTransport[RESUME_ACCEPT] ----  |
    |        ResumeAccept { Accepted: true }     |
    |                                            |
    |  ---- SignedTransport[REQUEST_HS] ------>  |   (§6.3, both sides
    |        Handshake {                         |    send the full session
    |          SessionKey: <full sessionID>      |    ID instead of random
    |        }                                   |    halves)
    |                                            |
    |  <--- SignedTransport[ACCEPT_HS] --------  |
    |        Handshake {                         |
    |          SessionKey: <full sessionID>      |
    |        }                                   |
    |                                            |
    |  ============ Challenge Exchange =======>  |   (§6.4, unchanged)
    |                                            |
    |       [Both: Established]                  |
    |       [Both: regenerate token set]         |
```

#### 6.8.1 Token Lifecycle

- **Single-use, any-order.** Each token may be consumed exactly once. There is
  no requirement to consume tokens in a specific order. This avoids a
  synchronization hazard: an any-order, mark-on-use scheme has no such
  dependency.
- **Regeneration on success.** When a resumption completes (the resumed session
  reaches `Established`), both peers discard the entire previous token set and
  derive a fresh set from the new session's shared secret (§7.6). A token stolen
  from session _k_ is worthless after session _k+1_'s handshake completes, since
  it is not derivable from the new shared secret.
- **Expiration.** A session's tokens become invalid after the resumption window
  (24 hours) elapses from the session's `Established` timestamp, regardless of
  how many tokens remain unused. A session with no unused tokens or past its
  window is **unresumeable** — the initiator must fall back to a full
  Introduction.

#### 6.8.2 Wire Messages

Both messages are sent inside the HPKE-encrypted tunnel established during the
Exchange phase — the same tunnel that protects Introduction and Handshake
messages. The raw token value is therefore never sent in the clear.

```
ResumeRequest {
  string SessionID = 1;
  bytes  Token     = 2;
}

ResumeAccept {
  bool   Accepted = 1;
  string Reason   = 2;
}
```

| Field       | Type   | Role                                                                    |
| ----------- | ------ | ----------------------------------------------------------------------- |
| `SessionID` | string | The original session ID being resumed.                                  |
| `Token`     | bytes  | One unused resumption token for that session.                           |
| `Accepted`  | bool   | Whether the resume request was accepted.                                |
| `Reason`    | string | Populated only when `Accepted` is false; describes the rejection cause. |

#### 6.8.3 Responder Validation

On receiving a resume request, the responder:

1. Looks up the session ID in persistent storage. If not found, the request is
   rejected.
2. Verifies the signature against the stored public key of the initiator. If
   invalid, the request is rejected and the connection is terminated.
3. Checks the resumption window has not elapsed. If expired, the request is
   rejected.
4. Checks the presented token is present in the session's unused token set. If
   not found (already used, or never valid), the request is rejected.
5. On success: marks the token used, sends a resume-accept with
   `Accepted: true`, and proceeds directly into the Handshake phase (§6.3) —
   skipping the Introduction phase and the remote-verifier callback entirely.
6. On any rejection: sends a resume-accept with `Accepted: false` and a reason
   string. The initiator may retry with a cold Introduction (§6.2).

#### 6.8.4 Resumption Asymmetry

Resumption is always initiated by the dialer. The server accepts incoming resume
requests but never sends one. If the server disconnects, it simply waits for the
dialer to reconnect and attempt resumption. Role reversal — the original server
dialing the original client — does not occur in practice; dialer and server
roles are fixed for the lifetime of the application.

The server MAY disable resumption, in which case incoming `ROUTE_RESUME_REQUEST`
messages are treated as unexpected-route conditions, forcing a full Introduction
from the dialer. Resumption is enabled by default.

#### 6.8.5 Session ID Semantics

The session ID continues to mean exactly what it means in a cold session: the
cryptographic handle for one Transport's lifetime. Resumption does not change
this — it lets both sides agree on the session ID in advance instead of
generating it randomly.

The practical effect of the shared session ID is purely at the storage layer:
the application's session message log (§11.3) keys on session ID, so messages
from the resumed session append to the same log entry rather than opening a new
one. During the Handshake phase, both sides send the full predetermined session
ID instead of each side generating a random half.

---

## 7. Encryption and Key Derivation

<picture>
  <img alt="Key Derivation Schedule" src="../assets/diagrams/key-derivation.svg">
</picture>

### 7.1 Exchange Phase Keys

During the Exchange phase, HPKE with the MLKEM768-X25519 hybrid KEM produces
paired sender and recipient contexts directly. No additional key derivation
is performed — the HPKE library handles key scheduling internally using
HKDF-SHA512 (KDF) and ChaCha20-Poly1305 (AEAD).

### 7.2 Handshake Phase Key Derivation

The MLKEM768 encapsulation produces a 32-byte shared secret. Per-direction
symmetric cipher keys are derived using HKDF-SHA512:

```
encoderKey = HKDF-SHA512(secret, localSalt, sessionID + directionInfo, 32)
decoderKey = HKDF-SHA512(secret, remoteSalt, sessionID + oppositeInfo, 32)
```

Where:

- `secret`: 32-byte MLKEM768 shared secret.
- `localSalt`: 16 random bytes from the local party.
- `remoteSalt`: 16 random bytes from the remote party.
- `sessionID`: 20-character concatenation of prefix + suffix.
- Direction info strings are domain-separated:
  - Client-to-server: `"kamune/handshake/client-to-server/v1"`
  - Server-to-client: `"kamune/handshake/server-to-client/v1"`

### 7.3 Challenge Tokens

Challenge tokens are derived using the same HKDF-SHA512:

```
challenge = HKDF-SHA512(secret, nil, sessionID + "|" + directionInfo + "|" + transcriptHash, 32)
```

The transcript hash binds the challenge to the specific session's handshake
payloads, preventing replay and downgrade attacks.

### 7.4 Enigma Cipher

The `Enigma` wrapper provides XChaCha20-Poly1305 AEAD encryption:

- `NewEnigma(secret, salt, info)`: Derives a 32-byte key via HKDF-SHA512 and
  creates an XChaCha20-Poly1305 AEAD cipher.
- `Encrypt(plaintext)`: Generates a fresh 24-byte random nonce, encrypts with
  the AEAD, and prepends the nonce to the ciphertext.
- `Decrypt(ciphertext)`: Extracts the 24-byte nonce, decrypts with the AEAD.

### 7.5 Key Hierarchy Summary

| Phase             | Key Material                   | Derivation                                                                         |
| ----------------- | ------------------------------ | ---------------------------------------------------------------------------------- |
| Exchange          | HPKE sender/recipient contexts | HPKE internal key schedule (MLKEM768-X25519 + HKDF-SHA512 + ChaCha20-Poly1305)     |
| Handshake         | 32-byte shared secret          | MLKEM768 Encapsulate/Decapsulate                                                   |
| Cipher keys       | 32-byte per-direction keys     | HKDF-SHA512(secret, salt, domainInfo)                                              |
| Challenge tokens  | 32-byte tokens                 | `HKDF-SHA512(secret, nil, sessionID + " \| " + dirInfo + " \| " + transcriptHash)` |
| Resumption tokens | 32-byte per-token values       | `HKDF-SHA512(resumptionRoot, nil, "kamune/resumption/token/" + index)`             |

### 7.6 Resumption Token Derivation

At session establishment, after the Challenge Exchange succeeds, a resumption
root is derived from the shared secret and session ID using HKDF-SHA512 with
the info string `"kamune/resumption-root/v1"`. The root is never stored or
exposed to the application.

From the root, N resumption tokens (each 32 bytes) are derived using
sequential indices as HKDF info strings with the prefix
`"kamune/resumption/token/"`. Both sides independently derive the same token
set without any additional message exchange — this mirrors the existing pattern
where challenge tokens (§7.3) are derived independently rather than
transmitted. (RFC001, §4)

---

## 8. Message Integrity and Replay Protection

### 8.1 Digital Signatures

Every `SignedTransport` message includes a digital signature over the `Data`
field. The signature is computed using the sender's long-term identity key
(Ed25519). The receiver verifies the signature using the sender's public key
obtained during the Introduction phase.

This provides:

- **Authentication**: Proof that the message was created by the claimed sender.
- **Integrity**: Any modification to `Data` invalidates the signature.
- **Non-repudiation**: The sender cannot deny having sent the message (though
  this is a peer-to-peer context, so non-repudiation is limited to the two
  parties).

### 8.2 Sequence Numbers

Each `Transport` maintains two monotonically increasing 64-bit unsigned
counters:

- A **send counter**: Incremented before each outgoing message. The first
  message has sequence `1`.
- A **receive counter**: Tracks the last received sequence number. Starts at
  `0`.

**Validation rules on receive:**

| Condition                    | Action                                                                    |
| ---------------------------- | ------------------------------------------------------------------------- |
| `seq == receive counter + 1` | Accept; update the receive counter.                                       |
| `seq < receive counter + 1`  | Reject as **duplicate**. An out-of-sync condition is surfaced.            |
| `seq > receive counter + 1`  | Reject as **gap/missing messages**. An out-of-sync condition is surfaced. |

Sequence numbers provide ordering guarantees and replay protection within a
session.

### 8.3 AEAD Authentication

The XChaCha20-Poly1305 AEAD cipher provides ciphertext authentication. Any
tampering with the encrypted payload (including the nonce) will cause
decryption to fail, ensuring that only the holder of the derived symmetric key
can produce valid cipher texts.

### 8.4 Multi-Layer Integrity

Kamune employs defense-in-depth with three independent integrity mechanisms:

1. **AEAD tag** (Poly1305): Authenticates the ciphertext at the encryption
   layer.
2. **Digital signature** (Ed25519): Authenticates the plaintext message
   at the signing layer.
3. **Sequence number**: Provides ordering and replay protection at the session
   layer.

---

## 9. Transport Layer

The transport layer carries the length-prefixed frames of §4.1 between the two
endpoints of a session. Kamune supports several transport backends out of the
box and is open to others through the connection contract of §9.4.

### 9.1 TCP

TCP is the default transport. It provides the reliable, ordered byte-stream
delivery the protocol assumes, and the length-prefixed framing of §4.1 operates
directly over the TCP stream.

### 9.2 UDP (via KCP)

For environments where TCP is unavailable or undesirable, kamune supports
UDP-based transport using KCP, which provides reliable, ordered delivery over
UDP. The same framing and protocol messages are used identically over KCP.

KCP provides ARQ for reliability, Reed-Solomon forward error correction, and
congestion control.

### 9.3 Relay

For NAT traversal or peers that cannot reach each other directly, kamune ships a
relay transport. The relay is a blind, stateless, token-based session switch: a
listener connects, receives a short random token, and shares it out of band; the
dialer connects with the same token. End-to-end authentication and encryption
are unchanged from §6; the relay only forwards encrypted frames.

See [`docs/RELAY.md`](RELAY.md) for the wire format, threat model, and
operational details.

### 9.4 Connection Contract

Every transport — TCP, UDP/KCP, relay, or a custom backend — exposes the same
minimal contract to the protocol:

- **Read one frame**: Read a 2-byte big-endian length prefix and then exactly
  that many bytes of payload. The read must consume the full declared length
  before returning; partial payloads are not a valid message boundary.
- **Write one frame**: Write a 2-byte big-endian length prefix followed by the
  payload. The full length prefix and payload must be written atomically; the
  write loops until all bytes are flushed.
- **Set deadline**: Apply a deadline that bounds subsequent read and write
  operations.
- **Close**: Release the underlying transport.

The contract is the only requirement the protocol imposes. An implementation may
additionally expose the underlying connection object (for example, a `net.Conn`
in environments that provide one) for callers that need transport-specific
metadata.

This contract is also the plug-in point for custom transports. The transport
layer exposes a Listener (accepts incoming connections and yields byte-stream
values satisfying the contract) and a Dial function (opens outgoing connections
and returns one). Any backend that can express itself in those two shapes is a
valid kamune transport.

---

## 10. Server and Dialer

### 10.1 Server (Responder Role)

A server listens for incoming connections and, for each one, runs the
Introduction → Handshake → Challenge Exchange sequence in the responder role.

Server flow per connection:

1. Run the Exchange phase as responder (§6.1).
2. Receive the initiator's `Introduce`, verify its signature and version.
3. Invoke the remote-verifier callback to accept or reject the peer.
4. Send the responder's own `Introduce`.
5. Run the Handshake phase as responder, including the Challenge Exchange.
6. Hand the established `Transport` to the application's session handler.

Configuration parameters (with their defaults):

- **Handshake timeout**: 30 seconds.
- **Transport**: pluggable. The Server accepts TCP connections by default, and
  the same interface accepts a custom listener or connection factory for UDP/KCP,
  relay, or any other transport satisfying the connection contract (§9.4).
- **Session handler**: A user-supplied callback invoked once per established
  session, receiving the `Transport`.

### 10.2 Dialer (Initiator Role)

A dialer opens outgoing connections and runs the same handshake sequence in
the initiator role.

Dialer flow:

1. Establish the underlying connection. The default is a TCP dial to the given
   address; a custom dial function may be supplied for UDP/KCP, relay, or any
   other transport satisfying the connection contract (§9.4).
2. Run the Exchange phase as initiator (§6.1).
3. Send the initiator's `Introduce`.
4. Receive and verify the responder's `Introduce`.
5. Run the Handshake phase as initiator, including the Challenge Exchange.
6. Return the established `Transport` to the caller.

Configuration parameters (with their defaults):

- **Dial timeout**: 10 seconds.
- **Handshake timeout**: 30 seconds.
- **Transport**: pluggable. The Dialer opens a TCP connection by default, and
  the same interface accepts a custom dial function for UDP/KCP, relay, or any
  other transport satisfying the connection contract (§9.4).

### 10.3 Role Summary

| Role           | Behaviour                                                                                   |
| -------------- | ------------------------------------------------------------------------------------------- |
| **Server**     | Listens for connections, runs the handshake as responder, hands off to a session handler.   |
| **Dialer**     | Opens a connection, runs the handshake as initiator, returns the `Transport` to the caller. |
| **Transport**  | Encrypted, session-aware bidirectional channel returned once the session is `Established`.  |
| **Connection** | The framing-aware byte transport feeding the protocol; see §9.4.                            |

---

## 11. Storage and Persistence

<picture>
  <img alt="Storage Key Hierarchy" src="../assets/diagrams/storage-hierarchy.svg">
</picture>

### 11.1 Database

Kamune persists its state in an embedded key-value store located at
`~/.config/kamune/db` by default. The location is overridable via the
`KAMUNE_DB_PATH` environment variable.

### 11.2 Database Encryption

The database contents are encrypted at rest using a key hierarchy:

1. **Passphrase** → `HKDF-SHA512(passphrase, deriveSalt, "derived-passphrase-key", 32)` → `derivedPass`.
2. `derivedPass` → `Enigma(derivedPass, wrappedSalt, "key-encryption-key")` → **KEK** (Key Encryption Key cipher).
3. A random 32-byte **secret** is encrypted by the KEK and stored as the
   wrapped key material.
4. `secret` → `Enigma(secret, secretSalt, "data-encryption-key")` → **DEK** (Data Encryption Key cipher).
5. All sensitive data (the local identity, peers, sessions, chat history) is
   encrypted and decrypted using the DEK.

The four salts (`deriveSalt`, `wrappedSalt`, `secretSalt`) and the wrapped key
are stored as plaintext metadata. The passphrase itself is never stored.

If the deployment disables the passphrase requirement
(`KAMUNE_DB_PASSPHRASE` empty and the no-passphrase option set), the
key-hierarchy is collapsed: a fixed derivation replaces step 1 and no human
passphrase is required. This mode is intended for embedded and test scenarios
and SHOULD NOT be used where the database file may be exposed.

### 11.3 Stored Entities

| Entity                       | Contents                                                                                                    | Encryption      |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------- | --------------- |
| **Local identity**           | The local attester's Ed25519 private key.                                                                   | Encrypted (DEK) |
| **Peers**                    | One record per known peer: name, identity public key, application version, first-seen time, last-seen time. | Encrypted (DEK) |
| **Session metadata**         | Per-session display name.                                                                                   | Encrypted (DEK) |
| **Session message log**      | Per-session ordered list of message payloads with sender and timestamp.                                     | Encrypted (DEK) |
| **Session resumption state** | Per-session: unused resumption tokens, the initiator's public key, and the established-at timestamp.        | Encrypted (DEK) |

Peer records are identified by a stable hash of their public key
(SHA3-512 of the PKIX/DER-encoded public key). The session message log
preserves the per-session ordering of messages and is keyed so that messages
sharing the same timestamp do not collide.

The resumption root itself is not stored — only the derived token set. A
database compromise exposes only the remaining unused tokens for sessions
within their resumption window, not a generator capable of producing tokens
for future sessions. (RFC001, §9)

### 11.4 Peer Expiration

Peer records have a configurable expiration duration (default: 7 days). On
lookup, if `firstSeen + expiryDuration < now`, the peer is automatically
deleted and a peer-expired condition is surfaced. Expired peers are also
pruned during full-iteration listings.

---

## 12. Security Properties

### 12.1 Confidentiality

All application messages are encrypted with ChaCha20-Poly1305X using
session-specific keys established with the post-quantum MLKEM768 KEM. Only
the two session participants can decrypt the messages.

### 12.2 Integrity

Messages are protected by three independent mechanisms: AEAD authentication
tags, digital signatures, and sequence-number validation.

### 12.3 Authentication

Both peers are authenticated during the Introduction phase via digital
signatures over their identity messages. The Challenge Exchange confirms
that both parties derived the same shared secret and can operate the
symmetric ciphers.

### 12.4 Forward Secrecy

Each session uses an ephemeral MLKEM key pair. The shared key is derived from
this ephemeral key encapsulation, not from the long-term identity keys.
Compromise of a long-term identity key does not reveal past session keys.

Within a single session, the same symmetric keys are used for all messages
(no per-message ratcheting). Forward secrecy is per-session, not per-message.

### 12.5 Post-Quantum Resistance

The MLKEM768 KEM provides resistance against quantum-computer attacks on the
key establishment. It ensures that the protocol remains secure as long as
ML-KEM-768 remains unbroken, providing defense in depth against quantum
adversaries.

With the default Ed25519 signing, the key establishment is quantum-resistant
but the identity signatures are not. An attacker with a quantum computer
could forge signatures but could not recover session keys from observed key
encapsulations.

### 12.6 Replay Protection

Monotonically increasing sequence numbers prevent message replay, duplication,
and reordering. AEAD nonces are randomly generated per encryption, preventing
nonce reuse.

### 12.7 Traffic Analysis Resistance

Every `SignedTransport` envelope MUST be padded to a bucketed target size
before encryption. Padding is applied uniformly across all routes.

**Buckets.** The sender pads the envelope to the smallest bucket that fits
the serialized size, then probabilistically bumps it up one or more levels.

| Bucket | Target size (pre-encryption)                                                                     |
| ------ | ------------------------------------------------------------------------------------------------ |
| 1      | 512 B                                                                                            |
| 2      | 1 KB                                                                                             |
| 3      | 4 KB                                                                                             |
| 4      | 16 KB                                                                                            |
| 5      | 32 KB                                                                                            |
| 6      | 65,495 B (the maximum that, after AEAD expansion, fits in a single 2-byte length-prefixed frame) |

**Cross-bucket randomness.** After selecting the natural bucket, the sender
bumps it with the following probability distribution:

| Bump     | Probability |
| -------- | ----------- |
| 0 (stay) | 80%         |
| +1       | 15%         |
| +2       | 4%          |
| +3       | 1%          |

The bump is selected independently per message and capped at bucket 6.

---

## 13. Constants and Limits

| Constant                   | Value                                  | Description                                                                                                             |
| -------------------------- | -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `maxTransportSize`         | 61,439 bytes (~60 KiB)                 | Maximum user-message size. The user-message cap is the wire-format maximum (65,535) minus a reserved protocol overhead. |
| `reservedProtocolOverhead` | 4,096 bytes (4 KiB)                    | Reserved bytes per message for signature + metadata + padding + AEAD tag.                                               |
| `wireFormatMax`            | 65,535 bytes                           | Wire format's hard upper bound (uint16 max).                                                                            |
| `paddingBuckets`           | {512, 1024, 4096, 16384, 32768, 65495} | Bucketed padding target sizes (pre-encryption). See §12.7.                                                              |
| `bumpProbabilities`        | {80%, 15%, 4%, 1%}                     | Cross-bucket bump distribution (stay, +1, +2, +3). See §12.7.                                                           |
| `handshakeSaltSize`        | 16 bytes                               | Size of random salts for handshake key derivation                                                                       |
| `handshakeChallengeSize`   | 32 bytes                               | Size of handshake challenge tokens                                                                                      |
| `sessionIDLength`          | 24 characters                          | Total session-ID length (12 prefix + 12 suffix)                                                                         |
| `nonceSize`                | 24 bytes                               | XChaCha20-Poly1305 nonce size                                                                                           |
| `keySize`                  | 32 bytes                               | ChaCha20-Poly1305 / HKDF output key size                                                                                |
| `defaultReadTimeout`       | 5 minutes                              | Default read deadline applied to the underlying transport                                                               |
| `defaultWriteTimeout`      | 1 minute                               | Default write deadline applied to the underlying transport                                                              |
| `defaultDialTimeout`       | 10 seconds                             | Default connection establishment timeout                                                                                |
| `defaultPeerExpiry`        | 7 days                                 | Default peer identity expiration                                                                                        |
| `lengthPrefixSize`         | 2 bytes                                | Size of the big-endian message length header                                                                            |
| `sessionPrefixLength`      | 12 characters                          | Length of the session-ID prefix emitted by the initiator                                                                |
| `sessionSuffixLength`      | 12 characters                          | Length of the session-ID suffix emitted by the responder                                                                |
| `handshakeTimeout`         | 30 seconds                             | Maximum time for the complete handshake                                                                                 |
| `pingDataSize`             | 8 bytes                                | Size of the random token in each ping message                                                                           |
| `resumptionGracePeriod`    | 24 hours                               | Time window after session establishment during which resumption tokens are valid                                        |
| `resumptionTokenCount`     | 20                                     | Number of resumption tokens derived per session                                                                         |
| `resumptionTokenSize`      | 32 bytes                               | Size of each resumption token (HKDF-SHA512 output)                                                                      |

---

## 14. Error Conditions

The following table lists the conditions under which the protocol reports an
error to the application layer. Each row describes a single observable
condition and the action the implementation takes.

| Condition                                                                                                                 | Action                                                                     |
| ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| An operation is attempted on a server that has already shut down.                                                         | Surfaced as a server-closed error.                                         |
| An operation is attempted on a connection that has already been closed.                                                   | Surfaced as a connection-closed error.                                     |
| The remote peer sends a `ROUTE_CLOSE_TRANSPORT` frame.                                                                    | Surfaced as a peer-disconnected error; the receive loop exits cleanly.     |
| A read deadline is exceeded.                                                                                              | Surfaced as a receive-timeout error. Non-fatal; the caller may retry.      |
| A signature on a received message fails verification.                                                                     | Surfaced as a signature error; the connection is terminated.               |
| A challenge echo does not match the original challenge, or the remote-verifier callback rejects the peer.                 | Surfaced as a verification error; the connection is terminated.            |
| A user message exceeds the user-message cap (~60 KiB), or its encoded frame would exceed the wire-format maximum.         | Surfaced as a message-too-large error; the message is not sent.            |
| A received sequence number does not equal the expected value (duplicate or gap).                                          | Surfaced as an out-of-sync error; the connection is terminated.            |
| A received route does not match the route expected for the current protocol phase.                                        | Surfaced as an unexpected-route error; the connection is terminated.       |
| A received message uses `ROUTE_INVALID` (0) or any unrecognized route value.                                              | Surfaced as an invalid-route error; the message is rejected.               |
| The remote peer's application version is incompatible with the local version (major mismatch, or pre-1.0 minor mismatch). | Surfaced as a version-mismatch error; the connection is terminated.        |
| A peer's identity has exceeded the configured expiry duration.                                                            | Surfaced as a peer-expired error; the peer record is removed on lookup.    |
| A resume request references a session ID not found in storage.                                                            | The request is rejected; the initiator may retry with a cold Introduction. |
| A resume request signature fails verification against the stored public key.                                              | The request is rejected; the connection is terminated.                     |
| A resume request references a session whose resumption window has elapsed.                                                | The request is rejected; the initiator may retry with a cold Introduction. |
| A resume request presents a token not present in the session's unused token set.                                          | The request is rejected; the initiator may retry with a cold Introduction. |

---

## 15. Merged RFCs

This section lists RFCs that have been accepted into the protocol
specification. Each entry records the RFC identifier, title, target
version, and the SPEC sections it affects. Draft or withdrawn RFCs
are not listed here.

| RFC    | Title              | Target Version | SPEC Sections                       |
| ------ | ------------------ | -------------- | ----------------------------------- |
| RFC001 | Session Resumption | v0.6.0         | §2, §5, §6.8, §7.6, §11.3, §13, §14 |
