# TUI Chat

Interactive terminal user interface for Kamune. Supports direct TCP and
relay-based connections, peer verification via emoji/fingerprint, and chat
history browsing.

## Usage

```
go run ./cmd/tui
```

On first launch you'll be prompted for:

1. **Database path** — defaults to `~/.config/kamune/db` (override with `KAMUNE_DB_PATH`)
2. **Passphrase** — unlocks the BoltDB store (override with `KAMUNE_DB_PASSPHRASE`)

## Menu

| Option               | Description                               |
| -------------------- | ----------------------------------------- |
| Direct Connect (TCP) | Dial a remote peer via raw TCP            |
| Start Server (TCP)   | Listen for incoming TCP connections       |
| Connect via Relay    | Dial through a blind relay session switch |
| Start Relay Server   | Host a relay session for incoming peers   |
| View Chat History    | Browse past sessions and their messages   |
| Quit                 | Exit the application                      |

## Controls

- **Tab / arrows** — navigate menu
- **Enter** — select / send chat message
- **Esc** — leave chat back to menu
- **Ctrl+C** — quit
- **Mouse wheel** — scroll chat viewport and history

## Environment

- `KAMUNE_DB_PATH` — override database path (default: `~/.config/kamune/db`)
- `KAMUNE_DB_PASSPHRASE` — passphrase for database access (skips prompt)
