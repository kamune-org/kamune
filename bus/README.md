# Bus — Kamune Chat GUI

A modern, cross-platform graphical chat client for the Kamune secure messaging protocol, built with [Fyne](https://fyne.io/).

## Features

- **Modern Dark Theme** — Clean, visually polished interface with an indigo-accented dark color scheme
- **Tabbed Sidebar** — Switch between active Sessions and session History tabs
- **Session History** — Browse past chat sessions from the database, load and view messages inline (read-only)
- **Live Sessions** — Start a server or connect to peers with real-time encrypted messaging
- **Message Bubbles** — Styled message bubbles with sender labels, timestamps, and alignment
- **Session Indicators** — Online dot, active bar, message count badges on session items
- **Peer Verification** — GUI-based emoji fingerprint verification with Strict, Quick, and Auto-Accept modes
- **Log Viewer** — Integrated log panel with real-time streaming, auto-scroll, and level-colored entries
- **Notifications** — Desktop notifications for new messages and connection events
- **Cross-Platform** — Works on macOS, Linux, and Windows

## Architecture

```
bus/
├── main.go           # Entry point, theme initialization, window setup
├── app.go            # ChatApp struct, state management, history session loading
├── ui.go             # Sidebar (tabs), chat panel, status bar, HistorySessionItem widget
├── session_item.go   # SessionItem widget with status dot, active bar, badge
├── bubble.go         # StyledMessageBubble widget for chat messages
├── messaging.go      # Send/receive logic, message refresh, overlay management
├── network.go        # Server start/stop, client connect, handler lifecycle
├── session.go        # Session state persistence, chat history loading
├── dialogs.go        # Server/connect dialogs, session info, clipboard helpers
├── menu.go           # Menu bar and keyboard shortcuts
├── history.go        # Standalone history viewer window (legacy, still available)
├── verifier.go       # GUI peer verification dialogs (Strict/Quick/AutoAccept)
├── context_menu.go   # Right-click context menus for sessions and messages
├── log_viewer.go     # LogViewer widget and LogEntryItem
├── status.go         # StatusIndicator widget
├── animated_dot.go   # AnimatedDot widget
├── theme.go          # Custom dark theme (colors, sizes, fonts)
├── colors.go         # Color palette constants
├── app_test.go       # Unit tests
├── logger/
│   ├── logger.go     # File + in-memory logger with subscriber support
│   └── logger_test.go
├── go.mod
└── go.sum
```

## Installation

### Prerequisites

- Go 1.24 or later
- Fyne dependencies (see [Fyne Getting Started](https://docs.fyne.io/started/))

On macOS:
```bash
xcode-select --install
```

On Ubuntu/Debian:
```bash
sudo apt-get install golang gcc libgl1-mesa-dev xorg-dev
```

On Fedora:
```bash
sudo dnf install golang gcc libXcursor-devel libXrandr-devel mesa-libGL-devel libXi-devel libXinerama-devel libXxf86vm-devel
```

### Building

```bash
cd bus
go mod tidy
go build -o bus .
```

### Running

```bash
./bus
```

## Usage

### Starting a Server

1. Click **Start Server** in the sidebar or press `Ctrl+S`
2. Enter the listen address (e.g., `127.0.0.1:9000`)
3. Enter the database path (default: `~/.config/kamune/db`)
4. Click **Start**

Your emoji fingerprint will be displayed in the sidebar for peer verification.

### Connecting to a Server

1. Click **Connect** in the sidebar or press `Ctrl+N`
2. Enter the server address (e.g., `127.0.0.1:9000`)
3. Enter the database path
4. Click **Connect**

### Sending Messages

1. Select an active session from the **Sessions** tab
2. Type your message in the input area
3. Press **Enter** or click the send button

### Viewing Session History

The **History** tab in the sidebar automatically loads past sessions from your database:

1. Click the **History** tab in the sidebar (or press `Ctrl+H`)
2. Browse past sessions — each shows message count and last activity
3. Click a session to load and view its messages (read-only)
4. Use **Refresh** to reload the list or **Change DB** to browse a different database

When viewing a history session, a banner indicates read-only mode and the input area is disabled.

### Standalone History Viewer

For advanced use, the standalone history viewer is still available via **File → View History...** which opens a separate window with export functionality.

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | Connect to server |
| `Ctrl+S` | Start server |
| `Ctrl+H` | Show History tab & refresh |
| `Ctrl+L` | Toggle log panel |
| `Ctrl+R` | Refresh history |
| `Ctrl+W` | Close application |
| `Enter` | Send message |
| `Escape` | Close log panel |

## Peer Verification

When connecting to peers, verification dialogs ensure secure communication:

| Mode | Description |
|------|-------------|
| **Strict** | Always shows a verification dialog for every connection |
| **Quick** | Auto-accepts known peers, shows dialog only for new peers |
| **Auto-Accept** | Accepts all connections without verification (testing only) |

Change the mode from **Settings → Verification** in the menu bar.

### Verifying Peers

1. A verification dialog appears when a new peer connects
2. Compare the emoji fingerprint with the peer through
 a secure channel
3. Click **Accept** to allow the connection or **Reject** to deny it

## UI Overview

### Sidebar (Left Panel)

- **Sessions tab** — Lists active live sessions with online indicators, active bars, and message count badges
- **History tab** — Lists past sessions from the database with message counts and last activity timestamps
- **Connection buttons** — Start Server, Connect, Stop Server
- **Fingerprint card** — Your emoji fingerprint with copy button

### Chat Panel (Center)

- **Session info bar** — Shows current session ID with copy/info/disconnect buttons; uses 🔒 for live and 📖 for history
- **History banner** — Amber banner shown when viewing a read-only history session
- **Message list** — Styled message bubbles with sender, timestamp, and word-wrapping
- **Welcome overlay** — Shown when no session is selected
- **Empty overlay** — Shown when a session has no messages yet
- **Message input** — Multi-line entry with send button (disabled in history view)

### Status Bar (Bottom)

- Connection status indicator (colored dot)
- Session/message info text
- Log toggle button
- Version label

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| Database path | `~/.config/kamune/db` | Override with `KAMUNE_DB_PATH` env var |
| Verification mode | Quick | Change via Settings menu |
| Notifications | Enabled | Desktop notifications for messages and connections |

## Security Notes

- All messages are end-to-end encrypted using the Kamune protocol
- Verify peer identity using emoji fingerprints through a separate secure channel
- Database is encrypted at rest (empty passphrase by default)
- Use **Strict** mode for sensitive communications
- Never use **Auto-Accept** mode in production or untrusted networks

## Development

### Running Tests

```bash
cd bus
go test ./... -v
```

### Building for Different Platforms

```bash
# macOS
GOOS=darwin GOARCH=amd64 go build -o bus-macos .

# Linux
GOOS=linux GOARCH=amd64 go build -o bus-linux .

# Windows
GOOS=windows GOARCH=amd64 go build -o bus.exe .
```

### Packaging

```bash
go install fyne.io/tools/cmd/fyne@latest
fyne package -name "Bus" -icon icon.png
```

## License

This project is part of the Kamune messaging library. See the main repository for license information.

## Related

- [Kamune Library](../) — Core messaging library
- [Kamune Chat TUI](../chat/) — Terminal UI reference implementation
- [Fyne Framework](https://fyne.io/) — UI toolkit