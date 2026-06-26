# Kamune

![Go version](https://img.shields.io/badge/Go-1.26-00ADD8)
[![Go Report Card](https://goreportcard.com/badge/github.com/kamune-org/kamune)](https://goreportcard.com/report/github.com/kamune-org/kamune)
[![GitHub release](https://img.shields.io/github/v/release/kamune-org/kamune)](https://github.com/kamune-org/kamune/releases)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Communication over untrusted networks.

Kamune provides `Ed25519_MLKEM768_ChaCha20-Poly1305X` security suite.

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
| `.` (root)                   | Core library           | Protocol, transport, cipher suite, session management, router, and storage abstraction                                           |
| [`cmd/bus/`](cmd/bus/)       | Desktop GUI client     | Wails + Svelte desktop app with relay transport UI, session management, and encrypted history                                    |
| [`cmd/relay/`](cmd/relay/)   | Relay server           | Stateless blind relay that routes encrypted sessions between peers without decrypting traffic — supports WebSocket, TCP, and TLS |
| [`cmd/daemon/`](cmd/daemon/) | JSON-over-stdio daemon | Headless IPC wrapper for integrating kamune into external applications                                                           |
| [`cmd/tui/`](cmd/tui/)       | Terminal chat client   | Interactive Bubble Tea TUI with direct TCP, relay, peer verification (emoji/hex fingerprint), and chat history browsing          |

## Roadmap

- [x] Application-level ping/pong keep-alive
- [x] Client-side minor version warning — surface the core warning to users in clients
- [x] Generate connection QR code in clients
- [ ] OS keychain integration (replace env var passphrase)
- [ ] Session resumption — reconnect without full re-handshake
- [ ] Chunked reads/writes for large messages
- [ ] Key rotation
- [ ] NAT traversal / hole punching
- [ ] Custom encoding protocol (replace Protobuf)
- [ ] QUIC, WebRTC, or other transport protocols
- [ ] Messaging Layer Security (MLS) / group chats
- [ ] Android/iOS native applications

## How does it work?

Communication happens in three phases:

1. **Exchange** — Parties agree on an HPKE shared secret to encrypt the handshake.
2. **Handshake** — Ephemeral ML-KEM-768 key exchange, session ID derivation, and mutual challenge-response verification.
3. **Communication** — Signed, encrypted, and sequenced message frames with replay protection.

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
