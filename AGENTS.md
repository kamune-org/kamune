# Kamune — AGENTS.md

## Project structure

Monorepo with 5 Go 1.26 modules:

| Directory     | Module                                    | Purpose                                           |
| ------------- | ----------------------------------------- | ------------------------------------------------- |
| `.` (root)    | `github.com/kamune-org/kamune`            | Core library (protocol, transport, crypto)        |
| `cmd/relay/`  | `github.com/kamune-org/kamune/cmd/relay`  | Blind token-based session switch (WebSocket, TCP) |
| `cmd/tui/`    | `github.com/kamune-org/kamune/cmd/tui`    | TUI example client (Bubble Tea)                   |
| `cmd/bus/`    | `github.com/kamune-org/kamune/cmd/bus`    | GUI client (Wails)                                |
| `cmd/daemon/` | `github.com/kamune-org/kamune/cmd/daemon` | JSON-over-stdio daemon for external apps          |

All sub-modules use `replace github.com/kamune-org/kamune => ../../` in their `go.mod`.

## Commands

- **Test any module**: `go test ./... -v` (works in root, cmd/relay/, cmd/tui/, cmd/bus/)
- **Test single package**: `go test -v ./pkg/storage` (any sub-package)
- **Benchmarks**: `go test ./... -bench .`
- **Vet** (root only): `go vet ./...`
- **Format** (root only): `gofmt -s -w .` and `goimports -w .`
- **Align structs** (fieldalignment only): `make align-structs` in root or `golangci-lint run --fix`
- **Regenerate protobuf** (root or relay): `make gen-proto` requires `protoc` with Go plugin
- **Build relay**: `make relay` from root or `bash scripts/build.sh` in `cmd/relay/`
- **Run relay**: `go run ./cmd/relay -c <path>`
- **Build daemon**: `go build -o daemon ./cmd/daemon` (from root)
- **Build chat TUI**: `go build -o tui .` in `cmd/tui/`
- **Build bus GUI**: `wails build` in `cmd/bus/` (requires Wails CLI)

## Commits

- Format: `<module>: <lowercase description>` — e.g. `bus: fix duplicate Wails events`, `kamune: add ErrReceiveTimeout sentinel`
- Root module changes use `kamune:`; multi-module should be used sparsely. These
  changes use comma-separated names like `bus,tui,daemon:`
- Existing modules are: `kamune`, `bus`, `relay`, `tui` and `daemon`.
- Use `docs` exclusively for changes to markdown files. Stand-alone files, like
  readme or Makefile, may get their own prefix if the commit change include only
  that file.
- `relayconn` package is an outlier. Its changes should be committed separately,
  with the package name as prefix.
- Commits must be small and focused — one logical change per commit.
- Subject line must be 72 characters or fewer.
- **Important**: Never commit or push without prompting the user first.

## Architecture notes

- Core abstraction: `Server`, `Dialer`, `Transport`, `Conn` — bidirectional encrypted channels
- Protocol flow: Exchange (HPKE) → Introduction → Handshake (ML-KEM-768) → Challenge → Communication
- Session resumption: parallel path that skips the full handshake for reconnections
- Cipher suite: `Ed25519_MLKEM768_HKDF-SHA512_ChaCha20-Poly1305X`
- `pkg/` public packages: `attest`, `exchange`, `fingerprint`, `relayconn`, `storage`
- `internal/` private packages: `box/pb`, `clock`, `enigma`, `store`
- Relay is a stateless blind session switch with optional PSK auth

## Storage

- Root uses BoltDB with optional passphrase encryption
- Relay is stateless (in-memory session tokens only)

## Conventions

- Lines should be 80 characters wide or less. Excluding already committed lines,
  generated files, markdown tables, and test files.
- CHANGELOG.md is immutable, and entries should only be added or updated when
  **explicitly** stated.
- Go 1.26 style (no `//go:build` tags needed for tool directives)
- Error sentinels use `Err` prefix, defined in the package they belong to (e.g. `transport.go`, `router.go`, `pkg/storage/storage.go`, `pkg/attest/attest.go`)
- `ErrPeerDisconnected` returned by `Transport.Receive()` when the remote peer sends `RouteCloseTransport` (graceful close). `ErrConnClosed` indicates an abrupt/network drop.
- Logging uses `log/slog` with structured attributes (`slog.String`, `slog.Any`)
- No mock framework — tests use real implementations, interfaces, and standard
  `testing.T`. Use `require` from `testify` with the instance pattern:
  `a := require.New(t)`, then `a.Equal(...)`, `a.NoError(...)`, etc.
  Do not use `assert` or direct `require.Fn(t, ...)` calls.
- Table-driven tests preferred for multiple cases
- `internal/` packages are private to root module; sub-modules (relay, tui, bus, daemon) may have their own `internal/`
