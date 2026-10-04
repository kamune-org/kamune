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

Each module builds and tests from its own directory. There is no `go.work`,
so a root command such as `go build ./cmd/daemon` fails.

- **Test any module**: `go test -race ./...` in root, `cmd/relay/`, `cmd/tui/`
  or `cmd/daemon/` (for `cmd/bus/`, see the bus notes below). `make test`
  runs it with `-v` in root (root module only) and in `cmd/relay/`
- **Test single package**: `go test -v ./pkg/storage` (any sub-package)
- **Benchmarks**: `go test ./... -bench .`
- **Fuzz** (root only): `make fuzz` runs each fuzz target for `FUZZ_TIME`
  (default `10s`)
- **Vet**: `go vet ./...` in any module
- **Format**: in root, `gofmt -s -w .` and
  `goimports -w $(git ls-files '*.go' | grep -v '\.pb\.go$')`. Both also
  format the `cmd/` modules. goimports would regroup the imports of the
  generated `*.pb.go` files, so the second command leaves them out, along
  with files git does not track yet
- **Lint and align structs**: `make align-structs` in root runs
  `golangci-lint run --enable=govet --fix` (golangci-lint v2) on the root
  module. `.golangci.yaml` turns on every govet analyzer except shadow, next
  to the default errcheck, ineffassign, staticcheck and unused. `--fix`
  applies every automatic fix, such as staticcheck quick fixes, not only
  fieldalignment, and the target fails while any issue is left
- **Regenerate protobuf** (root only): `make gen-proto` regenerates
  `internal/box/pb` and `pkg/relayconn/pb`; requires `protoc` and
  `protoc-gen-go`
- **Build relay**: `make relay` from root or `bash scripts/build.sh` in `cmd/relay/`
- **Run relay**: `go run . -c <path>` in `cmd/relay/` (`make run` there uses
  `assets/config.toml`)
- **Build daemon**: `go build -o daemon .` in `cmd/daemon/`, or `make daemon`
  from root for cross-platform release builds
- **Build chat TUI**: `go build -o tui .` in `cmd/tui/`
- **Build bus GUI**: `wails3 build` in `cmd/bus/` (requires Wails v3 CLI and
  npm)

Bus notes: `cmd/bus/frontend/bindings` and `cmd/bus/frontend/dist` are
generated and gitignored, and `wails3 build` makes both. Before `npm run check`
or `npm run build` in `cmd/bus/frontend/`, run `npm install` there and
`wails3 generate bindings -clean=true -time-type=Date` in `cmd/bus/`, as
`build/Taskfile.yml` does; the CLI default, `-time-type=string`, would type
`time.Time` fields as `string` instead of `Date`.
`wails3 task common:build:frontend` in `cmd/bus/` makes both without building
the app. `go test` and `go vet` in `cmd/bus/` need `frontend/dist`, which the
app embeds, and on Linux the GTK 4 and WebKitGTK 6.0 development packages that
Wails v3.0.0-beta.23 builds against.

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
- Session resumption: parallel path that skips Introduction for reconnections
  (still performs Handshake and Challenge)
- Cipher suite: `Ed25519_MLKEM768_HKDF-SHA512_ChaCha20-Poly1305X`
- `pkg/` public packages: `attest`, `exchange`, `fingerprint`, `relayconn`, `storage`
- `internal/` private packages: `box/pb`, `clock`, `engine`, `enigma`
- Key verification: verifiers should show `fingerprint.Numeric` (about 132.9
  bits) for users to compare. Bus and tui show it first on their verify
  screens, with `fingerprint.Emoji` and `fingerprint.Hex` below it, and the
  daemon sends all three in `verify_peer`.
  `fingerprint.Emoji` (about 52.7 bits) is not enough on its own, and
  `fingerprint.Pseudonym` (about 29.6 bits) is a display nickname, never a
  fingerprint
- Relay is a stateless blind session switch with optional PSK auth

## Storage

- Root uses BoltDB with optional passphrase encryption
- Relay keeps sessions and tokens in memory only; it writes to disk only its
  self-signed TLS certificate and key, kept in `server.data_dir`

## Conventions

- Lines should be 80 characters wide or less. Excluding already committed lines,
  generated files, markdown tables, and test files.
- CHANGELOG.md is immutable, and entries should only be added or updated when
  **explicitly** stated.
- Go 1.26 style (no `//go:build` tags needed for tool directives)
- Error sentinels use `Err` prefix, defined in the package they belong to
  (e.g. `errors.go` for the root package, `pkg/storage/storage.go`,
  `pkg/attest/attest.go`)
- `ErrPeerDisconnected` returned by `Transport.Receive()` when the remote peer sends `RouteCloseTransport` (graceful close). `ErrConnClosed` indicates an abrupt/network drop.
- Logging uses `log/slog` with structured attributes (`slog.String`, `slog.Any`)
- No mock framework — tests use real implementations, interfaces, and standard
  `testing.T`. Use `require` from `testify` with the instance pattern:
  `a := require.New(t)`, then `a.Equal(...)`, `a.NoError(...)`, etc.
  Do not use `assert` or direct `require.Fn(t, ...)` calls.
- Table-driven tests preferred for multiple cases
- `internal/` packages are private to root module; sub-modules (relay, tui, bus, daemon) may have their own `internal/`
