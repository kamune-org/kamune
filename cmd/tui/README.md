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
| Start Relay Server   | Host a relay session for one peer         |
| View Chat History    | Browse past sessions and their messages   |
| Quit                 | Exit the application                      |

## Relay connections

Connect via Relay and Start Relay Server reach a [relay](../relay/README.md).
Start Relay Server registers with the relay and shows a token; your peer
enters it in the Token field of Connect via Relay. A registration takes a
single peer: once that peer is turned away or its chat ends, the relay
session is over, and another peer needs a new one. When the relay limits
how long a session lasts, Start Relay Server says so while it waits, and
the chat shows a countdown.

### Relay address

The address is `scheme://host:port`. A `ws` or `wss` address may leave
out the port, which is then 80 for `ws` and 443 for `wss`. An address
without a scheme uses `wss`. The default, `wss://localhost:8891`, is the
wss listener of a relay that runs with its default config on the same
host.

| Scheme | Transport          | Relay authenticated |
| ------ | ------------------ | ------------------- |
| `wss`  | WebSocket over TLS | Yes                 |
| `tls`  | TCP with TLS       | Yes                 |
| `ws`   | WebSocket          | No                  |
| `tcp`  | Plain TCP          | No                  |

`wss` and `tls` check the relay's certificate against the system's roots
and the relay's host name, or against a pinned fingerprint (see below).
Over `ws` and `tcp`, anyone on the path can pose as the relay and read the
session token; the input screen warns about this. Use them only on a
network you trust.

### Relay password

A relay that has a `password` in the `[server]` table of its config takes
only clients that send it. Enter it in the Relay password field, which
hides what you type, and leave the field empty for a relay without one. The
relay hangs up on a wrong password, a missing one, or one it does not
expect. Over `tcp` and `tls`, the TUI's error then says to check the
password, and for Connect via Relay the token as well. Over `ws` and
`wss`, the error has no such hint and shows `received close frame`
instead.

### Self-signed certificates

A `wss` or `tls` listener without `cert_file` and `key_file`, as in the
relay's default config, uses a self-signed certificate, which the system's
roots do not vouch for. The relay logs the certificate's SHA-256
fingerprint at startup, in a `tls certificate` line as
`sha256=<64 hex digits>`. Enter that value in the Relay certificate SHA-256
fingerprint field, in either case and with or without colons. The TUI then
accepts only the certificate with that fingerprint, in place of the root
and host name checks. The field is refused for `ws` and `tcp`. See
[TLS / Certificates](../relay/README.md#tls--certificates) in the relay
README.

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
