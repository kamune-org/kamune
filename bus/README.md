# Kamune Chat GUI

A modern, cross-platform graphical user interface for the Kamune secure messaging library, built with [Fyne](https://fyne.io/).

## Features

- **Modern Dark Theme**: Clean, visually appealing interface with custom color scheme
- **Session Management**: Support for multiple concurrent chat sessions
- **Server & Client Modes**: Start a server or connect to existing peers
- **Real-time Messaging**: Send and receive encrypted messages instantly
- **Chat History**: View and export stored chat history from the database
- **Emoji Fingerprints**: Visual verification of peer identity using emoji fingerprints
- **Cross-Platform**: Works on macOS, Linux, and Windows

## Screenshots

The application features:
- Left sidebar with session list and connection controls
- Central chat area with styled message bubbles
- Status bar with connection indicator
- Menu bar with keyboard shortcuts
- Peer verification dialogs with emoji fingerprints

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
cd chat-gui
go mod tidy
go build -o kamune-chat .
```

### Running

```bash
./kamune-chat
```

## Usage

### Starting a Server

1. Click "Start Server" in the sidebar or use `Ctrl+S`
2. Enter the listen address (e.g., `127.0.0.1:9000`)
3. Enter the database path (e.g., `./server.db`)
4. Click "Start"

The server will listen for incoming connections. Your emoji fingerprint will be displayed for verification.

### Connecting to a Server

1. Click "Connect" in the sidebar or use `Ctrl+N`
2. Enter the server address (e.g., `127.0.0.1:9000`)
3. Enter the database path (e.g., `./client.db`)
4. Click "Connect"

### Sending Messages

1. Select an active session from the sidebar
2. Type your message in the input area at the bottom
3. Press Enter or click "Send"

### Viewing Chat History

1. Go to File → View History or use `Ctrl+H`
2. Enter the database path
3. Enter the session ID
4. Click "Load"

You can export the history to text and copy it to your clipboard.

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | Connect to server |
| `Ctrl+S` | Start server |
| `Ctrl+H` | View chat history |
| `Enter`  | Send message |
| `Esc`    | Close dialogs |

## Menu Bar

### File Menu
- Start Server... - Open server configuration dialog
- Connect to Server... - Open client connection dialog
- View History... - Open chat history viewer
- Quit - Exit the application

### Edit Menu
- Clear Messages - Clear messages in current session (local only)

### Session Menu
- Disconnect - Close the current session
- Session Info - View current session details

### Settings Menu
- Verification: Strict - Always show verification dialog for all peers
- Verification: Quick - Auto-accept known peers, show dialog for new peers
- Verification: Auto-Accept - Accept all peers without dialog (testing only)

### Help Menu
- About Kamune Chat - Display application information

## Peer Verification

When connecting to peers, the application provides GUI-based verification dialogs to ensure secure communication. The verification system shows:

- **Peer name** - The advertised name of the connecting peer
- **Emoji fingerprint** - A visual representation of the peer's public key
- **Hex fingerprint** - The full cryptographic fingerprint (copyable)
- **Known peer status** - Whether this peer has been seen before

### Verification Modes

| Mode | Description |
|------|-------------|
| **Strict** | Always shows a verification dialog for every connection |
| **Quick** | Auto-accepts known peers, shows dialog only for new peers |
| **Auto-Accept** | Accepts all connections without verification (testing only) |

You can change the verification mode from Settings → Verification in the menu bar.

### Verifying Peers

1. When a new peer connects, a verification dialog appears
2. Compare the emoji fingerprint with the peer through a secure channel (phone, in-person)
3. Click "Accept" to allow the connection and save the peer
4. Click "Reject" to deny the connection

Known peers are stored locally and can be auto-accepted in Quick mode.

## Architecture

```
chat-gui/
├── main.go      # Application entry point and theme configuration
├── app.go       # Main ChatApp struct and UI construction
├── widgets.go   # Custom widgets (StyledMessageBubble, SessionItem, StatusIndicator)
├── history.go   # Chat history viewer functionality
├── verifier.go  # GUI-based peer verification dialogs
├── go.mod       # Go module definition
└── README.md    # This file
```

### Custom Widgets

- **StyledMessageBubble**: Message display with colored backgrounds
- **SessionItem**: Session list item with status indicators
- **StatusIndicator**: Connection status with colored dot

### Verifier

The `GUIVerifier` provides different verification strategies:
- `CreateRemoteVerifier()` - Full verification dialog
- `CreateQuickVerifier()` - Auto-accept known, dialog for new
- `CreateAutoAcceptVerifier()` - Accept all (testing)

## Configuration

The application uses the following default paths:
- Client database: `./client.db`
- Server database: `./server.db`

You can specify custom paths when starting a server or connecting.

## Security Notes

- All messages are end-to-end encrypted using the Kamune protocol
- Session keys use the Double Ratchet algorithm
- Verify peer identity using emoji fingerprints
- Database is encrypted at rest (empty passphrase by default in GUI)
- GUI-based peer verification prevents terminal-based MITM attacks

### Recommended Security Practices

1. **Use Strict mode** for sensitive communications
2. **Always verify** new peers through a separate secure channel
3. **Compare emoji fingerprints** visually with your peer
4. **Use Quick mode** only after initially verifying peers in Strict mode
5. **Never use Auto-Accept mode** in production or untrusted networks

For production use, consider implementing passphrase support by modifying the storage options.

## Development

### Building for Different Platforms

```bash
# macOS
GOOS=darwin GOARCH=amd64 go build -o kamune-chat-macos .

# Linux
GOOS=linux GOARCH=amd64 go build -o kamune-chat-linux .

# Windows
GOOS=windows GOARCH=amd64 go build -o kamune-chat.exe .
```

### Packaging

Use `fyne package` to create distributable packages:

```bash
# Install fyne CLI
go install fyne.io/fyne/v2/cmd/fyne@latest

# Package for current platform
fyne package -name "Kamune Chat" -icon icon.png
```

## License

This project is part of the Kamune messaging library. See the main repository for license information.

## Related

- [Kamune Library](../) - Core messaging library
- [Kamune Chat TUI](../chat/) - Terminal UI reference implementation
- [Fyne Framework](https://fyne.io/) - UI toolkit used for this application