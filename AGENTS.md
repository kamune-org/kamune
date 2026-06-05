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

All sub-modules use `replace github.com/kamune-org/kamune => ../../` in their `go.mod` (daemon uses `../`).

## Commands

- **Test any module**: `go test ./... -v` (works in root, cmd/relay/, cmd/tui/, cmd/bus/)
- **Test single package**: `go test -v ./pkg/storage` (any sub-package)
- **Benchmarks**: `go test ./... -bench .`
- **Vet** (root only): `go vet ./...`
- **Format** (root only): `gofmt -s -w .` and `goimports -w .`
- **Align structs** (fieldalignment only): `make align-structs` in root or `golangci-lint run --fix`
- **Regenerate protobuf** (root or relay): `make gen-proto` requires `protoc` with Go plugin
- **Build relay**: `make relay` from root or `bash scripts/build.sh` in `cmd/relay/`
- **Run relay**: `go run ./cmd/relay -config <path>`
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

- Root package exports: `Server`, `Dialer`, `Transport`, `Conn` interface
- `pkg/` contains public sub-packages: `attest`, `exchange`, `fingerprint`, `storage`
- `internal/` is private: `box/pb` (protobuf), `enigma` (XChaCha20-Poly1305), `store` (BoltDB wrapper)
- Relay is a stateless blind session switch with optional PSK auth; uses WebSocket and TCP transports
- Cipher suite: `Ed25519_HPKE_MLKEM768_ChaCha20-Poly1305X`
- Protocol flow: Exchange (HPKE) → Introduction → Handshake (ML-KEM-768) → Challenge → Communication

## Storage quirks

- Root DB is BoltDB at `~/.config/kamune/db` (override with `KAMUNE_DB_PATH`)
- Passphrase from `KAMUNE_DB_PASSPHRASE` env var, otherwise stdin prompt
- Use `storage.WithNoPassphrase()` for tests or `db_no_passphrase: true` in daemon
- Relay is stateless (in-memory session tokens, no storage)

## Conventions

- Go 1.26 style (no `//go:build` tags needed for tool directives)
- All lockable state uses `sync.Mutex`, not `sync.RWMutex`
- Error sentinels use `Err` prefix, defined in the package they belong to (e.g. `transport.go`, `router.go`, `pkg/storage/storage.go`, `pkg/attest/attest.go`)
- `ErrPeerDisconnected` returned by `Transport.Receive()` when the remote peer sends `RouteCloseTransport` (graceful close). `ErrConnClosed` indicates an abrupt/network drop.
- Handlers panic-recovered via `runtime/debug.Stack()` logging
- Logging uses `log/slog` with structured attributes (`slog.String`, `slog.Any`); the relay module also uses a custom `slogger` package for `slogger.Err` and `slogger.String`
- No mock framework — tests use real implementations, interfaces, and standard `testing.T`
- Table-driven tests preferred for multiple cases
- `internal/` packages are private to root module; sub-modules (relay, chat, bus) have their own `internal/`
