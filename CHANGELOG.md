## v0.3.0

### Core Library

- Custom transport seam (`Listener`, `DialWithFunc`, `DialWithTCP`, `DialWithUDP`).
- Remove `Transport.Store()`; inject `*storage.Storage` into `NewServer`/`NewDialer`.
- `ErrReceiveTimeout` sentinel — receive loops retry on timeout instead of closing.
- App version check during introduction phase (`ErrVersionMismatch`).
- HPKE encryption in introduction and handshake.
- Add `Channel` type in `pkg/exchange`; `encryptedConn` abstraction.
- Move `store` to `internal/`, expose only `pkg/storage`.
- Refactor storage API; add query functions.
- `fingerprint.Sum` (SHA-256); migrate from `golang.org/x/crypto/sha3` to stdlib `crypto/sha3`.
- Protect `Conn` with mutex; simplify `Option` type; improve dial/serve/resume error messages.
- `KAMUNE_DB_PASSPHRASE` and `KAMUNE_DB_PATH` env vars; `getDefaultDBDir()`.
- Remove dead code (`connType`, `ML-DSA`, incomplete Session/Double Ratchet).
- Fix db handle leak on cipher error; fix ECDH private key marshalling.
- Improve error messages and update dependencies.

### Relay

- First release with all planned features.
- Extract shared `pkg/relayconn` for reuse across clients.
- Fix WebSocket handler identity, hub management, and key encoding.

### Bus

- Fyne → Wails + Svelte rewrite.
- Add relay transport UI and inline DB editing.
- Fix race conditions, duplicate Wails events, and 3 keyboard shortcut bugs.
- Receive loops retry on read timeout.
- Cross-platform build script with ldflags version injection.
- Add history tab; improve design and aesthetics.

### TUI

- Move to `cmd/tui/`.
- Relay-dial and relay-serve commands.
- Receive loops retry on read timeout.

### Daemon

- Split into smaller files; adapt to new core API.
- Storage caching; receive loop retries on timeout.

### Documentation & Project Structure

- Add AGENTS.md with project conventions.
- Add SPEC.md with protocol definition and SVG flow illustrations.

### Testing & Quality

- Comprehensive storage tests (timestamps, session index, expiry, batch deletes).

### Miscellaneous

- Regenerate protobuf bindings (protoc v6.33.4)
- Add `Route` field to `SignedTransport`.
- Add `assets/logo.png`.
- Update README.

---

## v0.1.0 - Initial Release

Kamune is a secure, peer-to-peer communication library for real-time messaging
over untrusted networks. This first release delivers an experimental foundation
for quantum-resistant, authenticated, and encrypted messaging, with a custom
protocol designed for minimal latency and overhead.

### Features & Technical Highlights

**Security & Cryptography**

- **Hybrid Cipher Suite:**
  - Ed25519 for digital signatures and identity verification
  - ML-KEM-768 for quantum-resistant key encapsulation (PQ KEM)
  - HKDF-SHA512 for session key derivation
  - ChaCha20-Poly1305X for authenticated symmetric encryption
  - Optional ML-DSA for post-quantum digital signatures
- **Forward Secrecy:**
  - ECDH key exchange ensures session keys are ephemeral. Past communications
    remain secure even if long-term keys are compromised.
- **Ephemeral Keys:**
  - Each session uses one-time-use keys for handshake and encryption,
    minimizing exposure.

**Protocol Flow**

- **Introduction Phase:**
  - Clients and servers exchange public keys and verify identities using
    digital signatures and fingerprinting (emoji/hex).
- **Handshake Phase:**
  - Ephemeral ML-KEM keys are exchanged, and both sides derive a shared secret.
  - Session IDs are constructed from random prefixes/suffixes.
  - Mutual challenge-response ensures both parties possess the correct keys.
- **Communication Phase:**
  - Messages are signed, encrypted, and transmitted with metadata (timestamp,
    sequence number).
  - Integrity checks and replay protection are enforced.
  - Transport supports chunked reads/writes and message size limits.

**Transport & Networking**

- **TCP and UDP Support:**
  - Custom protocol implemented over both TCP and UDP sockets
  - Direct peer-to-peer connections; no central server required
  - Relay server available for IP discovery and NAT traversal (experimental)
- **Timeouts & Deadlines:**
  - Configurable read/write timeouts for robust connection management

**Messaging & Storage**

- **Protobuf Encoding:**
  - Efficient binary serialization for all protocol messages
- **Chat History:**
  - Encrypted chat history is stored per session, with support for retrieval
    and replay
  - Storage uses per-session buckets and random key suffixes to avoid
    collisions
- **Peer Management:**
  - Peer identities are stored with expiration; expired peers are
    automatically purged
  - Peer verification prompts with fingerprint display
