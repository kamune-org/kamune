# TUI Chat

Interactive terminal user interface for Kamune. Supports direct TCP and
relay-based connections, peer verification by numeric fingerprint, and chat
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

Only one program can have the database open at a time. If another, such as
bus, the daemon or another TUI, has it open, the TUI waits for it to close
the database for about five seconds after the passphrase, then says so and
exits. A database written by an older version is upgraded when this
version first opens it, which needs a writable directory and room on the
disk for a copy of the file. If the upgrade fails, the TUI says so and
exits; the older version can still open the database.

### Passphrase

The passphrase is typed without echo. For a database that does not exist
yet, the TUI asks for it twice, since a typo would lock you out of the new
identity. Without a passphrase, anyone who can copy the database file can
read your identity key and chat history, so when you press Enter at the
prompt, the TUI warns you of that, and takes the empty passphrase only if
you answer `y` or `yes`; it does not ask for an empty one a second time. A
wrong passphrase, an empty one you do not confirm and a new one that does
not match its repeat each use up one of three tries; after the third, the
TUI exits.

| Flag                 | Effect                                                                                                                                                                                                                           |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-no-passphrase`     | Open or create the database without a passphrase, without asking. The TUI exits if the database has a passphrase, or if `KAMUNE_DB_PASSPHRASE` is set as well.                                                                   |
| `-change-passphrase` | Open the database as usual, ask twice for a new passphrase (an empty one is asked for once, and needs the same `y` or `yes`), set it and exit. Together with `-no-passphrase`, it sets a passphrase on a database that has none. |

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

## Verifying a peer

Every new connection, in any mode, opens a verify screen before the chat,
also for a peer you have chatted with before, unless it resumes an earlier
session (see [Resumed sessions](#resumed-sessions)). From the top, it
shows:

1. The numeric fingerprint of the peer's key, 40 digits in eight groups of
   five, and that of your own key.
2. The emoji and hex fingerprints of the peer's key.
3. Whether the peer's key is stored from an earlier session, and if so the
   name stored for it.
4. The name and app version that the peer claims, which are not verified.

When the name that the peer claims, or the name stored for its key, reads
the same as the name of a stored peer with a different key, a warning
follows that name. Names read the same when they differ only in case, in
the amount of white space around and between their words, in forms such
as fullwidth letters, or in characters that show as nothing, such as a
zero-width joiner. Names that only look alike, such as one with a
Cyrillic letter in place of a Latin one, do not; only the fingerprint
tells peers apart.

Over a channel you trust, such as a phone call, ask the peer to read out
the numeric fingerprint of its own key, and check it against the peer's
number on the screen; then read yours out in turn. The numeric fingerprint
carries about 132.9 bits. Do not rely on the emoji fingerprint: it carries
about 52.7 bits, few enough that a well-funded attacker can make a key with
the same emojis. If the peer's app shows no numeric fingerprint, compare
the whole hex fingerprint; its first 12 bytes are the same for every key.

Press `y` to accept the peer, or `n` or Esc to reject it. Every other key,
Enter included, is ignored, so an Enter meant for the previous screen
cannot accept a key you have not checked. A prompt left unanswered for two
minutes rejects the peer, and a peer that connects while a prompt is open
is rejected at once. After a rejection, Start Server goes on waiting for
another peer; the other modes end and return to the menu.

The TUI stores a peer you accept once its session is established, under
the name it claims. A peer that claims no name, or a name that reads the
same as that of a stored peer, is stored under a pseudonym derived from
its key instead, such as `gentle frosty deer 78`, and its verify screen
gives that pseudonym. The stored name is how the TUI names the peer from
then on. When the chat opens, it shows a line that names the peer by its
stored name and gives its numeric fingerprint.

### Resumed sessions

A peer whose app resumes dropped sessions, as bus and the daemon do, can
resume a session it had with a TUI Start Server (TCP) within 24 hours of
that session's first, cold handshake; resuming does not extend the 24
hours. Resumption does not run the verifier on either side
([SPEC §6.8.4](../../docs/SPEC.md#684-resumption-asymmetry)), so no verify
screen appears and the chat opens at once. A line in the chat then warns
that no prompt was shown, and gives the peer's stored name and numeric
fingerprint. Check that it is the peer you expect, and press Esc if it is
not. A resumed session that arrives while a prompt is open starts its
chat, and the peer of the prompt is rejected.

A session can be resumed only if the TUI did not close it: leaving its
chat with Esc, or quitting with Ctrl+C, ends it for good, even after the
peer has dropped off. Start Server also stops taking peers once its chat
starts. In practice, then, a peer can resume a session only after the TUI
stopped without closing it, as when its process was killed, and was
started again with Start Server on the same address.

A session with Start Relay Server cannot be resumed: the TUI does not give
the peer the relay tokens it would need to reach the TUI again, and a
relay registration takes a single peer. The TUI never resumes a session
when it dials.

## Controls

| Screen          | Keys                                                                            |
| --------------- | ------------------------------------------------------------------------------- |
| Menu            | ↑/↓, `k`/`j` or Tab to move; Enter or `1` to `6` to select                      |
| Input           | Tab and Shift+Tab to move between fields; Enter to connect; Esc to go back      |
| Connecting      | Esc to cancel                                                                   |
| Verify          | `y` to accept the peer; `n` or Esc to reject it                                 |
| Chat            | Enter to send; PgUp/PgDn to scroll; Esc to end the chat and go back to the menu |
| History         | ↑/↓ or `k`/`j` to move; Enter to open a session; Esc or `q` to go back          |
| History session | ↑/↓ and PgUp/PgDn to scroll; Esc to go back to the list                         |

Ctrl+C quits from any screen. The TUI does not turn on mouse reporting, so
it gets no mouse wheel events; scroll with the keys.

## Environment

- `KAMUNE_DB_PATH`: the database path that the prompt offers (default:
  `~/.config/kamune/db`)
- `KAMUNE_DB_PASSPHRASE`: passphrase for database access; skips the prompt,
  and the TUI exits if it does not open the database. The passphrase sits in
  the process environment, so the prompt is the safer choice. An empty value
  counts as unset; use `-no-passphrase` for a database without a passphrase.
- `KAMUNE_TUI_LOG`: file to append the log to while the UI runs (see
  [Logs](#logs))

## Logs

While the UI runs, the TUI drops the log records of the TUI and the kamune
library, since a record written to the terminal would land in the middle of
the screen. Set `KAMUNE_TUI_LOG` to a file path to keep them: records at
info level and above are appended to that file in slog's text format. A
file the TUI creates gets mode 0600, since the log names peers and
sessions. If the file cannot be opened, the UI does not start. Before the
UI starts and after it exits, records go to stderr.
