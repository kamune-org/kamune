# Bus — Kamune Chat GUI

A modern, cross-platform graphical chat client for the Kamune secure messaging protocol, built with [Wails](https://wails.io/) (WebView2).

## Features

- **Svelte Frontend** — Reactive UI built with Svelte, Vite, and CSS custom properties
- **Tabbed Sidebar** — Switch between active Sessions and session History tabs
- **Session History** — Browse past chat sessions from the database, load and view messages inline (read-only)
- **Live Sessions** — Start a server or connect to peers with real-time encrypted messaging
- **Message Bubbles** — Styled message bubbles with sender labels, timestamps, and alignment
- **Peer Fingerprint** — Emoji fingerprint display in the sidebar with copy-to-clipboard
- **Peer Verification** — Dialog-based emoji fingerprint verification with Strict, Quick, and Auto-Accept modes
- **Log Viewer** — Integrated log panel with real-time streaming and level-colored entries
- **Session Info** — Dialog with session metadata (peer name, message count, timestamps)
- **Rename & Delete** — Rename live or history sessions, delete history sessions
- **Keyboard Shortcuts** — Ctrl+N (connect), Ctrl+S (server), Ctrl+L (logs), and more
- **Cross-Platform** — macOS, Linux, Windows (WebView2 via Wails)

## Architecture

```
cmd/bus/
├── main.go           # Entry point, logger init, Wails app setup
├── app.go            # App struct, state management, storage, bindings
├── network.go        # Server start/stop, client connect, transport lifecycle
├── messaging.go      # Send/receive logic, message persistence
├── verifier.go       # Peer verification dialogs (Strict/Quick/AutoAccept)
├── app_test.go       # Unit tests
├── frontend/         # Svelte SPA (see frontend/src/)
│   ├── src/
│   │   ├── App.svelte        # Main app shell, dialogs, event wiring
│   │   ├── main.js           # Svelte entry point
│   │   └── lib/
│   │       ├── stores.js     # Svelte writable/derived stores
│   │       ├── ChatPanel.svelte  # Message display, input, info bar
│   │       ├── Sidebar.svelte    # Sessions/History tabs, server controls
│   │       ├── StatusBar.svelte  # Connection status, log toggle
│   │       ├── LogViewer.svelte  # Real-time log panel
│   │       └── *.svelte         # Dialogs (Rename, Verify, etc.)
│   ├── index.html
│   ├── vite.config.js
│   └── package.json
├── build/            # Wails build assets (icons, darwin/windows bundles)
├── wails.json        # Wails project config
├── go.mod
└── go.sum
```

## Prerequisites

- Go 1.26 or later
- Node.js 18+ and npm
- Wails v2 CLI: `go install github.com/wailsapp/wails/v2/cmd/wails@latest`

Platform-specific WebView dependencies (see [Wails docs](https://wails.io/docs/next/installation)):

- **macOS**: Xcode Command Line Tools (`xcode-select --install`)
- **Windows**: WebView2 runtime (included in Windows 11)
- **Linux**: `sudo apt install libgtk-3-dev libwebkit2gtk-4.0-dev`

## Development

### Run in dev mode (hot reload)

```bash
cd cmd/bus
wails dev
```

### Build

```bash
cd cmd/bus
wails build
```

The binary is output to `build/bin/`.

### Frontend only (dev server)

```bash
cd cmd/bus/frontend
npm install
npm run dev
```

The Vite dev server runs on port 5173. Point Wails to it with `wails dev --frontenddevserverurl http://localhost:5173`.

## Usage

### Starting a Server

1. Click **Start Server** in the sidebar or press `Ctrl+S`
2. Enter the listen address (e.g., `:8443`)
3. Click **Start**

Your emoji fingerprint will be displayed in the sidebar for peer verification.

### Connecting to a Peer

1. Click **Connect** in the sidebar or press `Ctrl+N`
2. Enter the server address (e.g., `192.168.1.100:8443`)
3. Click **Connect**

### Sending Messages

1. Select an active session from the **Sessions** tab
2. Type your message in the input area
3. Press **Enter** or click the send button

### Viewing Session History

1. Click the **History** tab in the sidebar
2. Browse past sessions — each shows message count and last activity
3. Click a session to load and view its messages (read-only)
4. Use **Refresh** to reload the list

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | Connect to server |
| `Ctrl+S` | Start server |
| `Ctrl+L` | Toggle log panel |
| `Ctrl+Shift+L` | Clear logs |

## Peer Verification

When connecting to peers, verification dialogs ensure secure communication:

| Mode | Description |
|------|-------------|
| **Strict** | Always shows a verification dialog for every connection |
| **Quick** | Auto-accepts known peers, shows dialog only for new peers |
| **Auto-Accept** | Accepts all connections without verification (testing only) |

### Verifying Peers

1. A verification dialog appears when a new peer connects
2. Compare the emoji fingerprint with the peer through a secure channel
3. Click **Accept** to allow the connection or **Reject** to deny it

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| Database path | `~/.config/kamune/db` | Override with `KAMUNE_DB_PATH` env var |
| Verification mode | Quick | Change via Settings menu |
| Passphrase | none | Set via `KAMUNE_DB_PASSPHRASE` env var |

## Security Notes

- All messages are end-to-end encrypted using the Kamune protocol
- Verify peer identity using emoji fingerprints through a separate secure channel
- Database is encrypted at rest
- Use **Strict** mode for sensitive communications
- Never use **Auto-Accept** mode in production or untrusted networks

## Testing

```bash
cd cmd/bus
go test ./... -v
```

## Related

- [Kamune Library](../../) — Core messaging library
- [Kamune Chat TUI](../tui/) — Terminal UI reference implementation
