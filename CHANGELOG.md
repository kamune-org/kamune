## v0.5.0

### Core Library

- Add bucketed padding scheme to `SignedTransport` for traffic-analysis
  resistance; pre-encryption payload lands on a fixed bucket boundary
  (512 B / 1 KB / 4 KB / 16 KB / 32 KB / 65,495 B) with a probabilistic
  cross-bucket bump (80/15/4/1). Replace the previous random-length `[0, 256)`
  padding. Derive `maxTransportSize` as
  `math.MaxUint16 - reservedProtocolOverhead` and move the `uint16` overflow
  check into `writeLen`.
- Add godoc comments across packages: package-level docs for `enigma` and
  `attest`; docs for every sentinel in `errors.go`, `Conn` / `newConn`,
  `defaultRemoteVerifier`, the `storage` settings helpers, and the `fingerprint`
  sub-package. Centralize the per-error rationale in one place.
- `pkg/exchange`: accept raw 32-byte X25519 public keys in `ECDH.Exchange` and
  `RestoreECDH`; drop the redundant PKIX parse plus `*ecdh.PublicKey`
  type-assertion path. Wire format is now exactly what
  `ecdh.X25519().NewPublicKey` accepts.

### Relay

- Add `cmd/relay/internal/ratelimit` package implementing a sliding-window rate
  limiter backed by `hashicorp/golang-lru/v2/expirable`; bounded LRU plus TTL
  auto-eviction at `2 × time_window`. Enforce per-IP at TCP/TLS accept and at
  the WS upgrade (before HPKE, with a `policy violation` close code). New
  `[rate_limit] max_entries` config knob defaults to `max_concurrent_sessions`.
- Add `session_ttl` and `handshake_timeout` to the `[session]` config block;
  default `handshake_timeout` to 30 s. Thread both through `services.New` →
  `SessionManager` / `Hub`.
- Enforce `handshake_timeout` in the TCP handler via `conn.SetDeadline` and in
  the WS handler via a `time.AfterFunc` that closes with `StatusPolicyViolation`.
  Stop the WS handshake timer after successful registration.
- Send `session_ttl_seconds` in the `Registered` response; expose
  `Hub.SessionTTL()` and `Service.SessionTTL()` accessors.
- Add per-session `sessionExpiry` to `SessionManager`; cleanup loop purges
  paired sessions whose expiry is past. Bump the cleanup tick from 30 s to a
  5-minute interval gated by an 80 % fill ratio. Move `Close()` calls outside
  the session-manager mutex; pass a cancellable `context.Context` to
  `cleanupLoop` for deterministic shutdown.
- Always purge expired unpaired listener sessions on the cleanup tick (drop the
  `atCapacity` precondition so expired tokens are freed even when the session
  map is not full).
- Delegate TCP framing in `cmd/relay/internal/handlers` to `relayconn.Framing`;
  remove the duplicated length-prefixed read/write code. Rename local
  `tcpAdapter` → `rawTCPAdapter` to avoid collision with the new
  `relayconn.tcpAdapter`.
- Extract length-prefixed wire framing into a dedicated `Framing` type in
  `pkg/relayconn`; `tcpAdapter` and `tlsAdapter` now compose it via
  `newTCPAdapter` / `newTLSAdapter`. Add `DefaultMaxFrameSize = 65536` and an
  `framing_test.go` suite.
- Add `session_ttl_seconds` to the protobuf `Registered` message and surface it
  through `RelayListener.SessionTTL()` and `RelayConn.SessionTTL()`. Refactor
  `DialRelay*` / `ListenRelay*` to return a
  `*ListenResult{Listener, Token, TTL, SessionTTL}` instead of a 4-tuple.
  Centralize handshake error cleanup with a single
  `defer { if retErr != nil { ch.Close() } }` in both `relayHandshake` and
  `listenHandshake`.
- Add a `pkg/relayconn` package-level doc comment describing the rendezvous
  model, the wire format, the transport adapters, and the design rationale. Add
  `relayconn_test.go` covering listener/dial handshakes (success, empty token,
  bad unmarshal, auth, session TTL) and read/write with deadlines. Fix a data
  race in test setup goroutines.
- Add doc comments to `tcpAdapter`, `tlsAdapter`, `wsAdapter`, `WithPassword`,
  `sendAuth`, `relayHandshake`, `RelayConn`, and `readPump`.
- Add `Config.Validate()` rejecting non-positive `max_concurrent_sessions` /
  `token_ttl` and negative `session_ttl` / `max_message_size`. Wire validation
  into `services.New` with a wrapped `invalid config:` error.
- Add panic recovery in `handleRelayConn`; close both sender and recipient on a
  write failure in `Hub.handleMessage`. Refactor `Run()` shutdown into a reusable
  `shutdown` closure called from both the signal path and the startup-error path.
- Randomize self-signed TLS certificate serial numbers.
- Add a comprehensive test suite: `services/session_test.go` (478 lines) and
  `handlers/relay_test.go` (512 lines) cover handshake, auth, register, message
  forwarding, ping/pong, panic recovery, and rate-limiter LRU eviction.

### Bus

- Display session TTL countdown in the chat header and per-token sidebar.
  Propagate `SessionTTL` and `SessionStartedAt` from `SessionInfo` / `relayToken`
  through `app.go`, `network.go`, and `relay.go`; bind a 1-second `setInterval`
  in `ChatPanel.svelte` and a `formatSessionTTL` helper in `Sidebar.svelte`.
- Add an import-from-clipboard keyboard shortcut (Cmd/Ctrl+Shift+I) to the
  Connection menu. Rename "Share Connection Card…" → "Share Connection" and
  "Import Connection URL…" → "Import Connection" (Cmd/Ctrl+I) for consistency;
  update the on-screen shortcut list in `App.svelte`.
- Fix relay-token copy hijacking the fingerprint's `Copied` state:
  `Sidebar.handleCopyToken` now goes through the shared `toast` store. Reduce
  success-toast TTLs from 15 s → 4 s (server start) and 4 s → 2 s (token copy)
  so they fade promptly.
- Replace the global "Skip TLS Verification" menu checkbox with per-dialog
  checkboxes in the server and connect modals (visible only when the selected
  scheme is `wss` or `tls`); thread the flag through the connect URL as
  `?insecure=true`. Drop the `insecure_tls` setting, the `insecureMenuItem`, the
  `insecureTLS` field on `App`, and the `GetInsecureTLS` / `SetInsecureTLS`
  bindings. Removes the server-restart prompt that was previously required to
  apply a TLS change.

### TUI

- Display session TTL countdown in the chat view: relay-serve records
  `sessionExpiry` on `enterChat`; a 1-second `tickMsg` re-renders the header
  with the remaining time, switching to "Session expired" once
  `time.Until(sessionExpiry) <= 0`. Skip the countdown in direct-dial mode and
  guard `store.AddChatEntry` with a `store != nil` check.
- Add `tea_test.go` (311 lines) covering the TTL countdown rendering, `enterChat`
  expiry assignment for relay-serve only, `connectFailedMsg` state transitions,
  and several other model-level invariants.

### Daemon

- Decouple storage from per-connection lifetime: collapse
  `stores map[string]*storage.Storage` into a single `db *storage.Storage`
  guarded by `storeMu`. Add `open_storage` and `submit_passphrase` commands; the
  former replaces the old per-handler `storagePath` parameter, and the latter
  re-opens storage with a runtime-supplied passphrase. Rename internal `Session`
  → `liveSession` and pre-load the bus-style fields.
- Add the full network + messaging + verification layer: `start_server` /
  `stop_server` / `restart_server` / `cancel_start_server` / `get_server_status`
  / `get_status`, `dial` (with relay/TCP/UDP), `send_message`, `list_sessions` /
  `close_session` / `rename_session`,`generate_relay_token` /
  `remove_relay_token` / `list_relay_tokens`, `get_share_info`, and
  `verify_response` / `set_verification_mode` / `get_verification_mode`. The
  `VerificationMode` enum covers `Strict` (0), `Quick` (1, default), and
  `AutoAccept` (2). `serverHandler` and the dial path now mirror the bus client.
- Add `history.go` (387 lines) and the `history_updated` / `history_loaded`
  events. New commands: `get_history_sessions`, `get_history_messages`,
  `load_history`, `rename_history_session`, `delete_history_session`,
  `refresh_history`, `list_peers`, `delete_peer`, `get_fingerprint`,
  `get_my_name`, `set_my_name`, `get_version`, `get_library_version`. History
  sessions are cached in `d.histSessions` and refreshed from
  `store.ListSessionsByRecent()`.
- Add `cmd/daemon/integration_test.go` (158 lines) that drives the daemon over
  real stdin/stdout NDJSON and exercises `open_storage` → `dial` (local TCP) →
  `send_message` → `get_history_sessions` → `get_history_messages` end-to-end.
- Add `multilistener.go` and `relay.go` (212 lines): a `multiListener` that
  aggregates multiple `kamune.Listener` instances for concurrent relay tokens,
  plus the relay listen/dial plumbing (PSK, `?insecure=true` support, address
  parsing, error wrapping).

### Documentation

- Move `SPEC.md` from the repo root to `docs/SPEC.md`; update `README.md` and
  `docs/RATCHET.md` cross-references. Revise the moved file: expand the table of
  contents, correct terminology, fix diagram paths (`assets/diagrams/*.svg`),
  reformat the wire format and route tables, and add an "Authors: kamune core
  team" header. Flip the cipher-suite wording from "default" to "current"
  (`Ed25519_MLKEM768_ChaCha20-Poly1305X`).
- Restructure §9 (Transport Layer) into four subsections: TCP (default), UDP via
  KCP, Relay, and a transport-agnostic Connection Contract. The contract makes
  pluggability a property of the contract itself (any backend expressing a
  Listener and Dial function is valid) rather than an implementation detail.
  Update §4.1 to point at §9.4, reword §10.1 / §10.2 "Transport" parameters to
  "pluggable" with a reference to §9.4, update the §10.3 Connection row
  cross-reference, and reword the §13 timeout descriptions to "applied to the
  underlying transport".
- Document the bucketed padding scheme in `§12.7`: six buckets (512 B / 1 KB /
  4 KB / 16 KB / 32 KB / 65,495 B), 80/15/4/1 % cross-bucket bump,
  `paddingBuckets` / `bumpProbabilities` constants, and the
  `reservedProtocolOverhead` (4 KiB) / `maxTransportSize` (~60 KiB) values.
  Update the wire format limits in `§3.1` to distinguish `wireFormatMax =
math.MaxUint16` (65,535 B) from the protocol's `maxTransportSize`.
- Add a first-draft "Double-Ratchet Implementation Plan" to `docs/RATCHET.md`:
  locked decisions, package layout under `internal/ratchet/`, the KDF chain /
  per-message nonce / DH step crypto, the message-epoch DH ratchet, and the
  out-of-order cache semantics. Update `RATCHET.md` to a second draft with
  concrete wire types, storage layout, and sender/receiver state machines.
- Expand `docs/DAEMON.md` from ~50 lines to ~1,300: NDJSON wire format, all 34
  commands grouped by category, the `SessionInfo` shape, every event, and a
  pointer to `cmd/daemon/README.md` for build instructions.
- Update `docs/RELAY.md`: mark rate limiting (sliding-window, per-IP), session
  TTL, and handshake timeout as implemented in the threat-model mitigations
  table; document the rate-limiting implementation (sliding-window counter,
  storage, IP-keyed with proxy-header awareness for WS, accept / WS-upgrade
  enforcement).
- Update `AGENTS.md`: add the 80-char line-length convention; clarify the
  testify usage; expand the commit-conventions list (enumerate existing modules,
  add the `docs` prefix rule, call out `relayconn` as an outlier, mark the
  never-commit / push-without-prompting rule as **Important**); drop obsolete
  rules about `sync.RWMutex` and `slogger`.
- Update `README.md`: add badges (Go 1.26, Go Report Card, GitHub release, MIT
  license); make the release badge a hyperlink to the releases page; update the
  roadmap checklist.

### Miscellaneous

- Refresh the 8 protocol SVG diagrams: cipher-suite, handshake-flow,
  key-derivation, message-pipeline, protocol-overview, session-phases,
  storage-hierarchy, wire-format.
- Update `assets/demo.gif`.
- Remove `.zed/debug.json` debug launch configurations.

---

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
