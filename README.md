# Kamune

![Go version](https://img.shields.io/badge/Go-1.26-00ADD8)
[![GitHub release](https://img.shields.io/github/v/release/kamune-org/kamune)](https://github.com/kamune-org/kamune/releases)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Communication over untrusted networks.

Kamune provides `Ed25519_MLKEM768_HKDF-SHA512_ChaCha20-Poly1305X` security
suite.

![demo](assets/demo.gif)

> [!NOTE]
> This is an experimental project. All suggestions and feedback are welcome and
> greatly appreciated.

## Features

- Message signing and verification using **Ed25519**
- Encrypted handshake using **HPKE** ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180))
- Ephemeral, quantum-resistant key encapsulation with **ML-KEM-768**, providing
  **Forward secrecy**.
- End-to-End, bidirectional symmetric encryption using **ChaCha20-Poly1305X**
- Key derivation via **HKDF-SHA512** (HMAC-based extract-and-expand)
- Lightweight, custom protocol implemented in both **TCP and UDP** for minimal
  overhead and latency
- **Real-time, instant messaging** over socket-based connection
- **Direct peer-to-peer communication**, with optional relay fallback
- **Protobuf** for fast, compact binary message encoding

## Modules

| Directory                    | Purpose                | Description                                                                                                                      |
| ---------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `.` (root)                   | Core library           | Protocol, transport, cipher suite, session management, and storage abstraction                                                   |
| [`cmd/bus/`](cmd/bus/)       | Desktop GUI client     | Wails + Svelte desktop app with relay transport UI, session management, and encrypted history                                    |
| [`cmd/relay/`](cmd/relay/)   | Relay server           | Stateless blind relay that routes encrypted sessions between peers without decrypting traffic — supports WebSocket, TCP, and TLS |
| [`cmd/daemon/`](cmd/daemon/) | JSON-over-stdio daemon | Headless IPC wrapper for integrating kamune into external applications                                                           |
| [`cmd/tui/`](cmd/tui/)       | Terminal chat client   | Interactive Bubble Tea TUI with direct TCP, relay, peer verification (emoji/hex fingerprint), and chat history browsing          |

## Roadmap

- [x] Application-level ping/pong keep-alive
- [x] Client-side minor version warning — surface the core warning to users in clients
- [x] Generate connection QR code in clients
- [x] NAT traversal / hole punching
- [x] Session resumption — reconnect without full re-handshake
- [ ] Chunked reads/writes for large messages
- [ ] Key rotation
- [ ] Custom encoding protocol (replace Protobuf)
- [ ] QUIC, WebRTC, or other transport protocols
- [ ] Messaging Layer Security (MLS) / group chats
- [ ] Android/iOS native applications

## How does it work?

Communication happens in five phases:

1. **Exchange**: Parties set up an HPKE channel, with the hybrid
   MLKEM768-X25519 KEM, that encrypts the messages of the next three phases.
2. **Introduction**: Each peer sends its name, Ed25519 identity public key and
   version, signed with that key. The application's verifier decides whether
   to accept the peer.
3. **Handshake**: An ephemeral ML-KEM-768 key exchange gives a shared secret,
   from which both sides derive the session keys. Each side contributes half
   of the session ID.
4. **Challenge**: Each side sends a challenge under the new keys and checks
   that the other echoes it back, which confirms that both derived the same
   keys.
5. **Communication**: Signed, encrypted, and sequenced message frames with
   replay protection.

A dialer can resume a session within 24 hours of its first handshake. The
resumption skips the Introduction and the verifier, and runs the Handshake and
Challenge again with new keys (see
[SPEC §6.8](docs/SPEC.md#68-session-resumption)).

For a comprehensive technical specification, see [SPEC.md](docs/SPEC.md).

<picture>
  <img alt="Cipher Suite Architecture" src="assets/diagrams/cipher-suite.svg">
</picture>

<details>
<summary>Handshake flow diagram</summary>

<picture>
  <img alt="Handshake Flow" src="assets/diagrams/handshake-flow.svg">
</picture>
</details>

## Verifying a peer

Kamune checks that a peer holds the identity key it introduces, but not whose
key it is. The application's verifier decides that, for example by asking the
user to compare a fingerprint of the key with the peer over another channel.
`pkg/fingerprint` computes these from the key's PKIX encoding, which both
peers see:

- `Numeric`: 40 digits in eight groups of five, from the SHA-512 of the key.
  It carries about 132.9 bits; this is the one to compare.
- `Emoji`: 8 emojis out of 96, from the SHA-256 of the key. About 52.7 bits is
  not enough on its own, since an attacker can search for a key that shows the
  same emojis.
- `Hex` and `Sum` (unpadded base64url of the SHA-256) are long to read out, and
  the hex form starts with the same 12 bytes for every Ed25519 key.
- `Pseudonym`: two adjectives, a noun and a number, about 29.6 bits. It is a
  nickname for display, not a fingerprint, and must not be used to verify a
  key.

The bus, tui and daemon clients in this repository do not use `Numeric` yet;
they use `Emoji` and `Hex` when they verify a peer.

See [SPEC §6.2.1](docs/SPEC.md#621-key-fingerprints).
