# Kamune

Communication over untrusted networks.

Kamune provides `Ed25519_ML-KEM-768_HKDF_SHA512_ChaCha20-Poly1305X` security
suite. Optionally, `ML-DSA` can be used for full quantum safety.

![demo](.assets/demo.gif)

> [!NOTE]
> This is an experimental project. All suggestions and feedbacks are welcome and
> greatly appreciated.

## Features

- Message signing and verification using **Ed25519**, with support for
  quantum safe **ML-DSA-65**
- Ephemeral, quantum-resistant key encapsulation with **ML-KEM-768**
- Key derivation via **HKDF-SHA512** (HMAC-based extract-and-expand)
- End-to-End, bidirectional symmetric encryption using **ChaCha20-Poly1305X**
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
- [ ] Better timeout and deadline management via context
- [ ] Handling remotes, connection retries, and session management
  - [ ] Remote's public key expiration
  - [ ] QR code generation
  - [ ] Key rotation *
  - [ ] Peer name *
- [ ] Relay server
  - [ ] IP discovery
  - [ ] Message conveying *
  - [ ] Queue persistence *
- [ ] Provide NAT traversal and/or hole punching strategies *
- [ ] Saving and restoring chat history *
- [ ] Considering FFI or an intermediary server for non-Go clients *
- [ ] Native and/or web clients *
- [ ] Replace Protobuf with a custom encoding\decoding protocol *

## How does it work?

There are three stages. In the following terminology, server is the party who is
accepting connections, and the client is the party who is trying to establish a
connection to the server.

### Introduction

Client sends its public key (think of it like an ID card) to the server and
server, in return, responds with its own public key (ID card). If both parties
**verify** the other one's identity, handshake process gets started.

### Handshake

Client creates a new, **ephemeral** (one-time use) ml-kem key. Its public key,
alongside randomly generated salt and ID prefix are sent to the server.

Server uses the received public key to derive a secret (also called shared 
secret; as well as a ciphertext that we'll get to in a minute). With that secret,
a decryption cipher is created to decrypt incoming messages. By deriving another
key from the shared secret, an encryption cipher is also created to encrypt 
outgoing messages. The ciphertext plus newly generated ID suffix and salt are
sent back to the client.

Client uses the received ciphertext and their private key (that was previously
generated), to derive the same exact shared secret. Then, encryption and
decryption ciphers are created likewise.

To make sure everyone are on the same page, each party performs a **challenge** 
to verify that the other party (them) can decipher our messages, and if we can
decipher their messages as well.  
A random text is created by driving a new key from the shared secret and the
agreed upon session ID (which was created by concatenating the ID prefix and
suffix). It is encrypted and sent to the other party. They should decrypt the
message, encrypt it again with their own encryption cipher, and send it back.  
If each side receive and successfully verify their text, the handshake is deemed
successful!

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
