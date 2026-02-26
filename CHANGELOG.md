
## v0.2.0

### Session Resumption & Routing

- **Session Resumption:** Implement full client/server session resumption flow
  (`resume.go`) so that peers can reconnect and restore an existing session
  without repeating the handshake. Session state is persisted and restored
  automatically.

- **Router & Route Dispatching:** Introduce `Router` and `RouteDispatcher` with
  middleware support (`router.go`). Add a `Route` enum and thread route
  constants through `Transport.Send` and serialization for structured message
  routing.
- **Session Manager:** Add persistent `SessionManager` (`session.go`) with
  handshake tracking, session save/load, `ListSessions`, and `CreatedAt`
  preservation.

### Desktop GUI (Bus)

- **Fyne-based Chat GUI:** Add a cross-platform desktop client under `bus/`
  built with Fyne, including chat UI, custom widgets, peer verification dialog,
  and encrypted history viewer.
- **Session List & In-App Logs:** Display active sessions and live application
  logs inside the GUI.
- **App Icons:** Ship platform-specific app icons for macOS, Windows, and Linux.
- **Unified DB Path:** GUI and CLI now share a single default database path
  (`~/.config/kamune/db`), overridable via `KAMUNE_DB_PATH`.
- **File Logger:** Concurrent file logger (`bus/logger`) with `Init`, `Close`,
  `Info`/`Warn`/`Error`/`Errorf` helpers, plus tests and benchmarks.

### Daemon

- **JSON-over-stdio Daemon:** Add `cmd/daemon` — a headless wrapper that
  exposes Kamune operations over JSON-over-stdio IPC, with its own README and
  tests.

### Relay Improvements

- **Refactored Relay:** Switch `attest.Identity` → `attest.Algorithm` across
  the relay API and models. Improve client IP extraction and rate-limit error
  responses.
- **Queue Operations:** Extend relay storage API with queue ops
  (`storage/queue.go`, `services/queue.go`) and a new queue HTTP handler, with
  tests.
- **Centralized Parsing:** Add `handlers/parse.go` to share base64 and
  public-key parsing logic; remove duplicate code from handlers.

### Storage

- **`DeleteBatch`:** Remove multiple keys from a bucket in a single
  transaction; missing buckets produce `ErrMissingBucket`, non-existent keys
  are silently skipped.
- **Bucket Listing Helpers:** Add `ListBuckets` and `ListKeys` queries to
  `pkg/store`.
- **`PubKeySessionIndex`:** New protobuf model and storage index mapping public
  keys to session IDs.
- **Peer `LastSeen`:** Track and persist the last-seen timestamp on every
  `Peer`, with full test coverage.

### Cryptography & Fingerprinting

- **SHA-256 Fingerprint:** Add `fingerprint.Sum` (SHA-256) alongside the
  existing emoji/hex helpers.
- **stdlib `crypto/sha3`:** Replace `golang.org/x/crypto/sha3` with the Go
  standard library `crypto/sha3` package.

### Connection & Transport

- **Conn Mutex:** Protect `Conn` fields with a mutex for safe concurrent use;
  simplify `Option` type by removing its error return.
- **Improved Dial/Serve/Resume:** Better error messages, cleaner control flow,
  and style improvements across `dial.go`, `server.go`, and `resume.go`.

### Configuration & Environment

- **Environment Variables:** `KAMUNE_DB_PASSPHRASE` and `KAMUNE_DB_PATH` are
  now preferred over interactive prompts and hard-coded paths.
- **Default DB Directory:** `getDefaultDBDir()` resolves
  `KAMUNE_DB_PATH` → `~/.config/kamune/db` → `./db`.

### Testing & Quality

- **Testify Adoption:** Replace manual `t.Error`/`t.Fatalf` checks with
  `testify/assert` and `testify/require` across the entire test suite.
- **Comprehensive Storage Tests:** Add tests covering peer timestamps, session
  index persistence, expiry/cleanup, batch deletes, session update/info, and
  resume checks.
- **Per-Goroutine Done Channels:** Replace shared signal channels with
  individual done channels in concurrent tests; capture and assert goroutine
  errors after joining.
- **New Fingerprint Tests:** Expand fingerprint coverage including `Hex`
  empty-input edge case.

### Miscellaneous

- **Protobuf Regeneration:** Regenerate Go protobuf bindings (protoc v6.33.4);
  add `Route` field to `SignedTransport`, update `box.proto` and `model.proto`.
- **Logo & Assets:** Add `assets/logo.png`; move `demo.gif` from `.assets/` to
  `assets/`.
- **ECDH Private Key Marshal:** Fix ECDH private key marshalling in
  `pkg/exchange`.
- **README Updates:** Refresh feature checklist and fix demo image path.

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
