# TUI Chat

Interactive terminal user interface for Kamune. Supports direct TCP and
relay-based connections, peer verification via emoji/fingerprint, and chat
history browsing.

## Usage

`cmd/tui` is a Go module of its own, so run it from its directory:

```
cd cmd/tui
go run . [-no-passphrase] [-change-passphrase]
```

On every launch you'll be prompted for:

1. **Database path**: Enter keeps the default, `~/.config/kamune/db` (change
   the default with `KAMUNE_DB_PATH`)
2. **Passphrase**: unlocks the BoltDB store (skip the prompt with
   `KAMUNE_DB_PASSPHRASE` or `-no-passphrase`)

### Passphrase

The passphrase is typed without echo. For a database that does not exist
yet, the TUI asks for it twice, since a typo would lock you out of the new
identity. Without a passphrase, anyone who can copy the database file can
read your identity key and chat history, so the TUI takes an empty one only
after you answer `y` to a warning that says so. A wrong passphrase, an empty
one you do not confirm and a new one that does not match its repeat each
use up one of three tries; after the third, the TUI exits.

| Flag                 | Effect                                                                                                                                                                                           |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `-no-passphrase`     | Open or create the database without a passphrase, without asking. The TUI exits if the database has a passphrase, or if `KAMUNE_DB_PASSPHRASE` is set as well.                                   |
| `-change-passphrase` | Open the database as usual, ask twice for a new passphrase (an empty one needs the same `y`), set it and exit. Together with `-no-passphrase`, it sets a passphrase on a database that has none. |

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

- `KAMUNE_DB_PATH`: the database path that the prompt offers (default:
  `~/.config/kamune/db`)
- `KAMUNE_DB_PASSPHRASE`: passphrase for database access; skips the prompt,
  and the TUI exits if it does not open the database. The passphrase sits in
  the process environment, so the prompt is the safer choice. An empty value
  counts as unset; use `-no-passphrase` for a database without a passphrase.
