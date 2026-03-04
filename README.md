# Kamune

Communication over untrusted networks.

Kamune provides `Ed25519_HPKE_MLKEM768_ChaCha20-Poly1305X` security suite.
Optionally, `ML-DSA` can be used for full quantum safety.

![demo](assets/demo.gif)

> [!NOTE]
> This is an experimental project. All suggestions and feedbacks are welcome and
> greatly appreciated.

For a comprehensive technical specification, see [SPEC.md](SPEC.md).

## Features

- Message signing and verification using **Ed25519**, with support for
  quantum safe **ML-DSA-65**
- Encrypted handhsake using **HPKE** ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180))
- Ephemeral, quantum-resistant key encapsulation with **ML-KEM-768**, providing
  **Forward secrecy**.
- End-to-End, bidirectional symmetric encryption using **ChaCha20-Poly1305X**
- Key derivation via **HKDF-SHA512** (HMAC-based extract-and-expand)
- Lightweight, custom protocol implemented in both **TCP and UDP** for minimal
  overhead and latency
- **Real-time, instant messaging** over socket-based connection
- **Direct peer-to-peer communication**, no intermediary server required
- **Protobuf** for fast, compact binary message encoding

## Roadmap

The following is a list of features that are currently planned or have been
conceived of. It is by no means exhaustive, and does not imply a commitment to
fully implement any or all of them. It will be updated as the project progresses.

Items marked with `*` are subject to edits, changes, and even partial or total
removal.

- [x] Settle on the cipher suite
- [x] Write the core functionality
- [x] Implement a minimal TUI
- [x] Stabilize the package API
- [x] Bind ciphers to session-specific info
- [x] Network protocols support
  - [x] TCP
  - [x] UDP
  - [ ] QUIC, WebRTC, or others? *
- [x] Better timeout and deadline management
- [x] Routes and session reconnection
- [x] Relay server
  - [x] IP discovery
  - [x] Message conveying
  - [x] Queue persistence
- [x] Handling remotes, connection retries, and session management
  - [x] QR code generation
  - [x] Peer name
  - [x] Remote's public key expiration
  - [ ] Key rotation
- [x] Saving and restoring chat history
- [x] Daemon server
- [x] Native clients via Fyne
- [ ] Provide NAT traversal and/or hole punching strategies
- [ ] Messaging Layer Security (MLS) and group chats *
- [ ] Replace Protobuf with a custom encoding\decoding protocol *

## How does it work?

There are three stages. In the following terminology, server is the party who is
accepting connections, and the client is the party who is trying to establish a
connection to the server.

> For a comprehensive technical specification, see [SPEC.md](SPEC.md).

<picture>
  <img alt="Cipher Suite Architecture" src="assets/diagrams/cipher-suite.svg">
</picture>

## Exchange

Both parties exchange HPKE public keys and agree on a shared secret, which will
be used to encrypt the following handshake steps. Afterwards, separate ciphers
will be used for encryption of user messages.

### Introduction

Client sends its public key (think of it like an ID card) to the server and
server, in return, responds with its own public key (ID card). If both parties
**verify** the other one's identity, handshake process gets started.

### Handshake

Client creates a new, **ephemeral** (one-time use) keypair using the 
post-quantum **MLKEM768** KEM. The public key, alongside a randomly generated
salt and ID prefix, are sent to the server.

Server parses the received public key and performs KEM encapsulation and derives
the full secret key internally. The encapsulated key (`enc` or `ciphertext`), a
newly generated ID suffix, and salt are sent back to the client.

Client receives the encapsulated key and decapsulates the key and derives the 
same shared secret. Both sides then create bidirectional symmetric encryption
ciphers for the transport layer — one key for client-to-server and one for 
server-to-client.

To make sure everyone is on the same page, each party performs a **challenge**
to verify that the other party can decipher our messages, and if we can
decipher their messages as well.  
A challenge token is derived from the shared secret and the agreed upon session
ID (which was created by concatenating the ID prefix and suffix). It is 
encrypted and sent to the other party. They should decrypt the message, encrypt 
it again with their own encryption cipher, and send it back.  
If each side receives and successfully verifies their token, the handshake is
deemed successful!

<details>
<summary>Handshake flow diagram</summary>

<picture>
  <img alt="Handshake Flow" src="assets/diagrams/handshake-flow.svg">
</picture>
</details>

### Communication

Imagine a post office. When a cargo is accepted, A unique signature is generated
based on its content and the sender's identity. Everyone can verify the
signature, but only the sender can issue a new one.  
The cargo, the signature, and some other info such as timestamp and a number
(sequence) are placed inside a box. Then, the box will be locked and sealed.
Shipment will be done via a custom gateway specifically designed for this, and
it will deliver the package straight to the recipient.

At destination, the parcel will be checked for any kind of temperaments or
changes. Using pre-established keys from the handshake phase, smallest
modifications will be detected and the package is rejected. If all checks pass
successfully, the cargo will be delivered and opened.
