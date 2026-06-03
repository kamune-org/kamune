## v0.4.0

### Core Library

- `Conn` interface now embeds `ReadWriter`.
- Remove `Router` type; delete `router.go`, clean up `routes.go`.
- Centralize sentinel errors into root `errors.go`.
- Add `AppVersion` to `Peer` struct; consolidate `RemotePeer()` method.
- Add Ping/Pong routes with configurable keep-alive.
- Add `SettingsBucket`, `GetSettings`/`SetSettings` in storage (encrypted at rest).
- Add deterministic `Pseudonym(seed)` with expanded word pools.
- Expand fingerprint emoji pool from 64 to 96 entries.
- Delegate HPKE exchange from root to `pkg/exchange`; remove duplicate `exchange.go`.
- Merge ciphertext and public key into single exchange write (3 messages instead of 4).
- Add `ErrPeerDisconnected` sentinel; `Transport.Close()` returns gracefully instead of abrupt disconnect.
- Use local-time keys and versioned value envelope in chat storage.
- Remove QR code fingerprint display.
- Fix `uint16` overflow in `writeLen` (check `len(data)` before cast).
- Track current read/write deadlines to prevent Ping timeout from being overwritten by read timeout.
- Fix data race in `Server.ListenAndServe` (lock around `closed`/`listener` access).
- Fix panic recovery in `Dialer.handshake` and `Server.serve` (close conn and return error instead of nil).
- Fix `RelayListener.Close` data race (lock `mu` around `conn.Close`).
- Fix `RelayListener.closeFn` double-call guard with `sync.Once`.

### Relay

- Full service layer rewrite: replace with hub + session architecture.
- Remove old storage layer (command/logger/query/queue/store) and model packages.
- Add TCP adapter and TCP handler for direct connections.
- Extract `pkg/relayconn` with auth, dial, listener, transport modules.
- Add token+password authentication flow.
- Replace box proto with updated relay proto.
- Update config, router, and WebSocket handler for new architecture.
- Add `Stop()` method to `RelayListener` (prevents new accepts without killing active connections).
- Auto-generate self-signed TLS certificates as PEM; enable by default.
- Close peer channel on disconnect to prevent blocking.
- Add cross-platform build script; simplify Makefile.
- Simplify `--version` output to show kamune dependency version.
- Fix expired session goroutine leak (close listener/dialer channels before delete in `purgeExpired`).
- Fix TOCTOU in session `Recipient` (hold lock through switch instead of releasing early).
- Send TCP/TLS startup errors to `errCh` instead of only logging.
- Fix double-read from `exitCh` in TCP/TLS-only mode (read into variable).
- Add 30s context timeout for WebSocket handshake accept (`wsAdapter.SetDeadline` is a no-op).
- Enforce `MaxMessageSize` in TCP and TLS adapters.
- Log `handlePing` write errors instead of silent discard.
- Randomize self-signed TLS certificate serial number.
- Add `// TODO` for unimplemented rate limiting.

### Bus

- Fingerprint computed on demand from public key (remove stored emojiFP/b64FP/hexFP fields).
- Native OS menu bar with Fingerprint submenu (Copy as Hex/Sum/Base64) with toast feedback.
- Session naming and version display.
- Persist name and verification mode across restarts; add MyName editing.
- KAMUNE_DB_PATH and KAMUNE_DB_PASSPHRASE env var support.
- Keychain UX improvements for relay credentials.
- Update relay.go for new relayconn API (token + password).
- Redesign frontend for multi-token relay, inline rename, and continuous session management.
- Add multi-token relay support with start cancellation and TLS toggle.
- Add native dialog confirmations and server restart on setting changes.
- Restructure `onMount` event registration to fix duplicate Wails event handlers.
- Use `Stop()` for graceful relay token consumption.
- Add server transport tracking, verifying connection state, and log export to file.
- Refresh history session list on session close; add missing fields to session info dialog.
- Handle `ErrPeerDisconnected` in receive loop.
- Update build script output path; add `-s -w` linker flags.
- Add keychain error `default` case (log warning instead of silent fallthrough).
- Offload `ExportLogsToFile` to goroutine with error reporting.
- Extract `removeSession` helper (DRY, avoid nil-slice panic on shutdown).
- Guard stale verification channel send with `select`/`default` (prevent goroutine leak on slow consumer).
- Remove hardcoded `appVersion` test (version now references `kamune.AppVersion`).
- Modernize test style: `for i := range N`, `wg.Go` in place of manual `wg.Add`/`go`/`wg.Done`.

### TUI

- Full rewrite from CLI flag dispatch to interactive bubbletea menu TUI.
- Multi-state architecture (welcome, input, connecting, verify, chat, history).
- Interactive DB path and passphrase prompts before alt-screen.
- Direct TCP client/server, relay client/server, and chat history browsing.
- Peer verification screen with emoji + hex fingerprint display.
- Chat with viewport/textarea, message history loading, and send/receive.
- Version mismatch warning during connection.
- Handle `ErrPeerDisconnected` in receive loop.

### Daemon

- Initial protocol documentation in `docs/DAEMON.md`.
- Handle `ErrPeerDisconnected` in receive loop.
- Fix shutdown and connection lifecycle races.
- Use env var for passphrase instead of interactive prompt.
- Handle `RoutePing` with pong response.
- Consistent base64 encoding for public keys.

### Documentation

- SPEC.md updated to v0.4.0 with Ping/Pong, Server/Dialer, Keep-Alive.
- Add `docs/RELAY.md` with stateless relay architecture.
- Add `docs/DAEMON.md` with daemon protocol documentation.
- Update README with revised project status.

### Miscellaneous

- Regenerate protobuf bindings for relay and box schemas.
- Fix Zed debug launch configuration paths.
- Bump module version to v0.4.0.
- Add build targets for relay and bus in root Makefile.

---

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
