# Daemon Protocol

The `cmd/daemon` module provides a JSON-over-stdio protocol for integrating
kamune with external applications (Tauri, Electron, editor plugins, scripts).
The daemon exposes the same surface area as the `cmd/bus` Wails GUI client:
TCP/UDP/relay/P2P transports, peer verification, chat history persistence, relay
and P2P token management, identity, share info, log management, and keychain
integration.

This document is the **authoritative protocol specification**. For build
instructions and a quick-start, see [`cmd/daemon/README.md`](../cmd/daemon/README.md).

## Overview

```
┌──────────┐   stdin (NDJSON commands)   ┌──────────┐
│  Client  │ ──────────────────────────▶ │          │
│  (Tauri, │                             │  Daemon  │  kamune
│  Editor, │   stdout (NDJSON events)    │          │ ────────▶ peers
│  etc.)   │ ◀────────────────────────── │          │
└──────────┘   stderr (JSON logs)        └──────────┘
```

The daemon reads commands from stdin and emits events to stdout as
newline-delimited JSON (NDJSON). Each line is a single valid JSON object
followed by `\n`. Logs go to stderr in JSON format via `log/slog`.

## Wire Format

### Command Envelope (Client → Daemon)

```json
{
  "type": "cmd",
  "cmd": "<command_name>",
  "id": "<correlation_id>",
  "params": { ... }
}
```

| Field    | Type   | Description                                                                                                                                                                            |
| -------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `type`   | string | Always `"cmd"` for commands.                                                                                                                                                           |
| `cmd`    | string | The command name (see [Commands](#commands)).                                                                                                                                          |
| `id`     | string | Optional correlation ID. The daemon echoes it on the response or error event; the answer to a command without one carries no `id`.                                                     |
| `params` | object | Command-specific parameters. A command that takes parameters fails with `invalid_params` when `params` is absent, except `generate_relay_token`. A command that takes none ignores it. |

The daemon reads one command per line. A line that is not a JSON object fails
with `invalid_json`, a `type` other than `"cmd"` with `unknown_message_type`
and an unknown `cmd` with `unknown_command`. A line longer than 1 MiB, newline
included, is dropped and reported with `line_too_long`.

### Event Envelope (Daemon → Client)

```json
{
  "type": "evt",
  "evt": "<event_name>",
  "id": "<correlation_id>",
  "data": { ... }
}
```

| Field  | Type   | Description                                                                                                                                                     |
| ------ | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `type` | string | Always `"evt"` for events.                                                                                                                                      |
| `evt`  | string | The event name (see [Commands](#commands) and [Push Events](#push-events)).                                                                                     |
| `id`   | string | Correlation ID of the command that the event answers. Omitted for push events, for side events such as `status_changed`, and for commands sent without an `id`. |
| `data` | object | Event-specific payload.                                                                                                                                         |

Every command in the [Commands](#commands) section below shows the exact
JSON it expects on stdin and the JSON it emits on stdout. The daemon also
emits a `log_entry` event for each line it logs, and the examples leave
those out.

Some values have a fixed encoding:

- Public keys (`public_key`, `b64`, `peer_pub_b64`) are the 44-byte PKIX
  encoding of an Ed25519 key in unpadded base64url.
- Message data (`data_base64`) is standard base64 with padding.
- Durations (`*_ns`) are integer nanoseconds, and times are RFC 3339 strings.

Machine-readable JSON Schemas for every command and event are in
[`cmd/daemon/schema`](../cmd/daemon/schema/README.md).

## Commands

All 53 commands, grouped by category. Each block shows the **exact JSON**
to send and the JSON to expect back.

### `SessionInfo` Shape

`session_started`, `session_closed`, `list_sessions` and `get_session_info`
(for a live session) carry a `SessionInfo` object. Its shape, for a dialed
relay session:

```json
{
  "session_id": "abc123def456...",
  "peer_name": "CrimsonOtter",
  "claimed_name": "CrimsonOtter",
  "peer_key": "MCowBQYDK2VwAyEA...",
  "peer_fingerprint": "12345 67890 13579 24680 11223 34455 66778 89900",
  "known_peer": true,
  "name_mismatch": false,
  "name_conflict": false,
  "is_server": false,
  "msg_count": 3,
  "last_activity": "2026-06-21T10:30:00Z",
  "transport_type": "relay",
  "remote_version": "0.5.0",
  "cause": "dial",
  "session_ttl_ns": 3600000000000,
  "session_started_at": "2026-06-21T10:25:00Z",
  "remote_addr": "wss://relay.example.com:8443"
}
```

| Field                | Description                                                                                                                                                                                                                                                                                                                                                                                                                         |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `session_id`         | The kamune session ID.                                                                                                                                                                                                                                                                                                                                                                                                              |
| `peer_name`          | The session's label: the name stored for the peer's key, the name `rename_session` set, or, for a key that is not stored, `Unknown peer` and the first ten digits of the key's numeric fingerprint, such as `Unknown peer 12345 67890`. A stored name from before the protocol limited names is shown with each character that the name rules refuse as U+FFFD and cut to 64 bytes. Never the name the peer introduced itself with. |
| `claimed_name`       | The name the peer introduced itself with, made safe to show as `peer_name` is. Any peer can claim any name, so show it only as the peer's claim.                                                                                                                                                                                                                                                                                    |
| `peer_key`           | The peer's public key, base64 as `list_peers` gives it: the key the handshake authenticated.                                                                                                                                                                                                                                                                                                                                        |
| `peer_fingerprint`   | The numeric fingerprint of `peer_key`, 40 digits in eight groups of five.                                                                                                                                                                                                                                                                                                                                                           |
| `known_peer`         | Whether the peer's key was stored when the session started. An unknown peer accepted in `verify_peer` is stored by then, unless incognito mode is on.                                                                                                                                                                                                                                                                               |
| `name_mismatch`      | The peer is stored, and the name it claimed is not the name stored for its key.                                                                                                                                                                                                                                                                                                                                                     |
| `name_conflict`      | The peer claimed, or is stored under, the name of another stored peer. Names that differ only in case, white space or characters that do not show, such as a zero-width joiner, count as the same.                                                                                                                                                                                                                                  |
| `is_server`          | `true` for a session that a peer opened to the server, `false` for one from `dial`.                                                                                                                                                                                                                                                                                                                                                 |
| `msg_count`          | Messages stored for the session before it started, plus those sent or received since. Stored messages are not counted in incognito mode.                                                                                                                                                                                                                                                                                            |
| `last_activity`      | Time of the last message sent or received since the session started, or of its start. Omitted while unset.                                                                                                                                                                                                                                                                                                                          |
| `transport_type`     | `tcp`, `udp`, `relay`, `p2p` or `direct-p2p`. Omitted when empty.                                                                                                                                                                                                                                                                                                                                                                   |
| `remote_version`     | The peer's kamune version. Omitted when empty.                                                                                                                                                                                                                                                                                                                                                                                      |
| `cause`              | `dial` for a dialed session, `incoming` for one that a peer opened to the server.                                                                                                                                                                                                                                                                                                                                                   |
| `session_ttl_ns`     | The relay's session TTL for a relay session. Sessions over other transports carry `0`, incoming sessions of a server started after a relay server stopped too.                                                                                                                                                                                                                                                                      |
| `session_started_at` | When the daemon set the session up.                                                                                                                                                                                                                                                                                                                                                                                                 |
| `remote_addr`        | Where a dialed session was dialed: the server's address, the `relay_addr` for relay, `p2p` for p2p and the peer's address for direct-p2p. Omitted for incoming sessions.                                                                                                                                                                                                                                                            |

### Storage

#### `open_storage`

Opens the single shared storage. Must be called before any command that
requires storage. `storage_path` is required (`storage_path_required`); the
daemon does not read `KAMUNE_DB_PATH`.

Keep the database in a directory of the user's own, not in a shared one such
as `/tmp`, where another local user can create the file first. The example
opens an encrypted database with the passphrase from `KAMUNE_DB_PASSPHRASE`;
`db_no_passphrase: true` opens or creates one without encryption.

- Without `db_no_passphrase`, the passphrase is read from
  `KAMUNE_DB_PASSPHRASE`. When that is unset, the command fails with
  `storage_open_failed` and reason `passphrase_required`. The daemon never
  saves this passphrase to the keychain.
- `db_no_passphrase` on an encrypted storage fails with `storage_open_failed`
  and reason `wrong_passphrase`.
- The path of an `open_storage` that fails, with `db_no_passphrase` or
  without, is kept for [`submit_passphrase`](#submit_passphrase), in place of
  the path of any earlier one that failed, until a storage opens. An
  `open_storage` refused with `storage_busy` keeps no path.
- A storage that has no identity key yet gets a new Ed25519 identity.
- While a storage is open, the new one is opened first, and the old one is
  closed only once that succeeds; when the new open fails, the old storage
  stays open. Opening the path that is already open closes it and opens it
  again, and when that fails the previous storage is opened again as it was.
- Each storage starts from the settings the daemon had before the first
  storage was opened (the defaults, or what the client set before that), and
  only that storage's own saved settings are applied on top: verification
  mode, incognito, fingerprint format and log level. The identity, local name
  and history list of a storage opened earlier are dropped.
- It fails with `storage_busy` while a server runs, a server start or a dial is
  under way, or a session is open, and with `storage_open_failed` when the
  storage does not open. That error carries a `reason` when the cause is one a
  client can act on: `wrong_passphrase`, `passphrase_required`,
  `corrupt_metadata`, `insecure_permissions` (the database file is open to
  other users and its mode cannot be restricted), `unsupported_format` (a
  newer version wrote it), `in_use` (another program, such as another daemon,
  the TUI or Bus, holds the database; the open waits 5 seconds for it first),
  or `upgrade_failed` or `compact_failed` (an older version wrote the
  database, and it could not be upgraded, or compacted after its upgrade, for
  example on a full disk or in a directory the daemon cannot write to, where
  the lock file next to the database cannot be created; free space or make
  the directory writable, and every open tries again).

**Input:**

```json
{
  "type": "cmd",
  "cmd": "open_storage",
  "id": "1",
  "params": { "storage_path": "/home/alice/.config/kamune/daemon.db" }
}
```

**Output:**

The identity, the local name (the fingerprint pseudonym until one is set) and
the history list of the storage come first:

```json
{ "type": "evt", "evt": "fingerprint_changed", "data": { "emoji": "🦊 • 🐱 • 🌵 • 🔑 • 🚀 • 🍀 • 🎲 • 🐙", "b64": "MCowBQYDK2VwAyEA...", "hex": "30:2A:30:05:06:03:2B:65:70:03:21:00:5D:...", "sum": "q3Vx0Zl8...", "numeric": "12345 67890 13579 24680 11223 34455 66778 89900" } }
{ "type": "evt", "evt": "local_name_changed", "data": { "name": "CrimsonOtter" } }
{ "type": "evt", "evt": "history_updated", "data": {} }
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": { "status": "opened", "storage_path": "/home/alice/.config/kamune/daemon.db" }
}
```

#### `submit_passphrase`

Opens a storage with the given passphrase: the path of the last
`open_storage`, when that failed, with `db_no_passphrase` or without, or else
the path of the open storage. The response names the path it opened in
`storage_path`. It fails with `storage_not_opened` when there is neither, and
with `passphrase_required` for an empty passphrase; an unencrypted database is
opened with `open_storage` and `db_no_passphrase`. Opening, the settings and
the other errors work as for [`open_storage`](#open_storage).

`save_to_keychain` (default `false`) saves the passphrase to the system
keychain once the storage has opened; without it the passphrase is not saved.
A failure to save is logged as a warning.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "submit_passphrase",
  "id": "1",
  "params": { "passphrase": "correct horse battery staple", "save_to_keychain": false }
}
```

**Output:** the identity events of `open_storage`, then:

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "opened", "storage_path": "/home/alice/.config/kamune/daemon.db" } }
```

#### `change_passphrase`

Changes the passphrase of the open storage. The storage is re-encrypted under a
new data key that only the new passphrase unlocks, and the file is rewritten.
Copies of the old file made elsewhere, such as backups, still open with the old
passphrase. `old_passphrase` is empty or absent for a storage opened with
`db_no_passphrase`, which the command then encrypts; `new_passphrase` must not
be empty.

A keychain entry for the storage would hold the old passphrase, so it is
replaced with the new one when `save_to_keychain` is set, and removed
otherwise.

Like `open_storage` it needs the storage idle. It fails with `storage_busy`
while a server runs, a server start or a dial is under way, or a session is
open; `storage_not_opened` without an open storage; `passphrase_required` for
an empty `new_passphrase`; `wrong_passphrase` when `old_passphrase` does not
open the storage; and `change_passphrase_failed` otherwise, which leaves the
passphrase unchanged. In the rare case that the new passphrase is in effect but
the storage cannot be opened again, it fails with `storage_reopen_failed` and
no storage is open: open it with `submit_passphrase` and the new passphrase.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "change_passphrase",
  "id": "1",
  "params": {
    "old_passphrase": "correct horse battery staple",
    "new_passphrase": "a new passphrase",
    "save_to_keychain": false
  }
}
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "changed" } }
```

When the storage had to be opened again after the change, the identity events
of `open_storage` come before the response.

### Server Lifecycle

#### `start_server`

Starts a kamune server. The command is checked at once, and the server then
starts in the background; `server_started`, or an error event, carries the
command's `id`.

| Param              | Transports                | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------ | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `transport`        | all                       | `"tcp"` (the default, when empty or absent), `"udp"`, `"relay"`, `"p2p"` or `"direct-p2p"`. Any other value fails with `invalid_transport`.                                                                                                                                                                                                                                                                                                                                      |
| `addr`             | tcp, udp, p2p, direct-p2p | The listen address. Required for tcp and udp (`addr_required`); `"0.0.0.0:0"` listens on every interface on a port the system picks. For p2p and direct-p2p, the UDP address the punch socket binds; when absent, any port on every interface. Ignored for relay.                                                                                                                                                                                                                |
| `relay_addr`       | relay                     | Required. `host:port` with an optional scheme: `wss://` (the default when none is given), `tls://`, `ws://` or `tcp://`. A trailing `?insecure=true` turns off TLS certificate checks. Over `ws://`, `tcp://` or `?insecure=true` an on-path attacker can read the relay password and tokens, and the daemon logs a warning.                                                                                                                                                     |
| `relay_pin`        | relay                     | The SHA-256 fingerprint of the relay's TLS certificate, 64 hex digits, optionally colon-separated; the relay logs it at startup. A `wss` or `tls` relay must then have exactly that certificate, in place of the checks against the system's roots and the relay's name, so a relay with a self-signed certificate can be used without `?insecure=true`. A pin for a `ws` or `tcp` relay, with `?insecure=true`, or that is not a SHA-256 digest fails with `invalid_relay_pin`. |
| `password`         | relay                     | The relay's pre-shared key, if it asks for one.                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `name`             | all                       | The server's display name, saved as the local name. Defaults to the fingerprint pseudonym of the identity key, which incognito mode always uses (and does not save). A name longer than 64 bytes, not UTF-8, or with a control, format, line separator or paragraph separator character (the zero-width joiner and non-joiner are allowed) fails with `invalid_name`.                                                                                                            |
| `broker_addr`      | p2p                       | Required. The broker's UDP `host:port`; see [P2P Tokens](#p2p-tokens).                                                                                                                                                                                                                                                                                                                                                                                                           |
| `peer_pub_b64`     | p2p                       | Registers the [static token](#relay) for this peer instead of a random token that the broker assigns.                                                                                                                                                                                                                                                                                                                                                                            |
| `direct_peer_addr` | direct-p2p                | Required. The peer's UDP `host:port`, which the server sends packets to for 10 seconds to open the NATs on the way.                                                                                                                                                                                                                                                                                                                                                              |

Before the server starts, the command fails with `invalid_params`,
`invalid_name`, `invalid_transport`, `addr_required`, `invalid_relay_pin`,
`storage_not_opened`, `server_already_running` or `server_start_in_progress`.
A start that fails later reports one of `storage_unavailable`,
`identity_unavailable`, `relay_listen_failed`, `listener_failed`,
`broker_client_failed`, `p2p_token_failed`, `p2p_listener_failed`,
`direct_p2p_failed` or `create_server_failed`, most of them after setting the
status to `error`. A relay server registers its first token at start;
connecting to the relay and the relay handshake are limited to 15 seconds.

**Input (TCP):**

```json
{
  "type": "cmd",
  "cmd": "start_server",
  "id": "1",
  "params": { "addr": "127.0.0.1:9000", "transport": "tcp", "name": "MyServer" }
}
```

**Input (Relay):**

```json
{
  "type": "cmd",
  "cmd": "start_server",
  "id": "1",
  "params": {
    "transport": "relay",
    "relay_addr": "wss://relay.example.com:8443",
    "password": "psk-secret",
    "name": "MyServer"
  }
}
```

**Input (P2P via broker):**

```json
{
  "type": "cmd",
  "cmd": "start_server",
  "id": "1",
  "params": {
    "transport": "p2p",
    "addr": "0.0.0.0:0",
    "broker_addr": "broker.example.com:4788",
    "peer_pub_b64": "<optional-base64-public-key>"
  }
}
```

**Input (Direct P2P):**

```json
{
  "type": "cmd",
  "cmd": "start_server",
  "id": "1",
  "params": {
    "transport": "direct-p2p",
    "addr": "0.0.0.0:0",
    "direct_peer_addr": "203.0.113.5:9000"
  }
}
```

**Output:**

```json
{ "type": "evt", "evt": "status_changed", "data": { "status": "connecting", "message": "Starting server..." } }
{ "type": "evt", "evt": "fingerprint_changed", "data": { "emoji": "🦊 • 🐱 • 🌵 • 🔑 • 🚀 • 🍀 • 🎲 • 🐙", "b64": "MCowBQYDK2VwAyEA...", "hex": "30:2A:30:05:06:03:2B:65:70:03:21:00:5D:...", "sum": "q3Vx0Zl8...", "numeric": "12345 67890 13579 24680 11223 34455 66778 89900" } }
{ "type": "evt", "evt": "server_running", "data": { "running": true, "transport": "tcp" } }
{ "type": "evt", "evt": "status_changed", "data": { "status": "connected", "message": "Server running on 127.0.0.1:9000" } }
{ "type": "evt", "evt": "history_updated", "data": {} }
{ "type": "evt", "evt": "server_started", "id": "1", "data": { "addr": "127.0.0.1:9000", "transport": "tcp", "name": "MyServer", "public_key": "MCowBQYDK2VwAyEA...", "emoji": ["🦊", "🐱", "🌵", "🔑", "🚀", "🍀", "🎲", "🐙"], "fingerprint_hex": "30:2A:30:05:06:03:2B:65:70:03:21:00:5D:...", "fingerprint_sum": "q3Vx0Zl8...", "fingerprint_numeric": "12345 67890 13579 24680 11223 34455 66778 89900" } }
```

`server_started.addr` is the address the server is bound to, with the port the
system picked when `addr` asked for port 0, and is empty for a relay server.
`fingerprint_numeric` is the fingerprint for the peer to compare; see
[Verification Flow](#verification-flow).

A p2p server emits `p2p_tokens` with its token before `fingerprint_changed`. A
relay server also emits, before `server_started`:

```json
{ "type": "evt", "evt": "relay_token", "data": { "token": "deadbeef...", "ttl_ns": 600000000000, "session_ttl_ns": 300000000000, "expires_at": "2026-06-21T11:00:00Z" } }
{ "type": "evt", "evt": "relay_tokens", "data": { "tokens": [{ "token": "deadbeef...", "consumed": false, "ttl_ns": 600000000000, "session_ttl_ns": 300000000000, "expires_at": "2026-06-21T11:00:00Z", "mode": "random" }] } }
```

`relay_token` names the token registered at start, and is emitted only while
that token is still listed and unused; `relay_tokens` is always emitted.

#### `stop_server`

Stops the running server, or a server start in progress, without exiting the
daemon. Every live session, incoming or dialed, is closed and reported with
`session_closed`. Pending `verify_peer` prompts of peers that connected to the
server are rejected, since the stopped server drops their handshakes, and the
command waits up to 5 seconds for those handshakes to end. The server's relay
and P2P tokens are dropped.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "stop_server", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "status_changed", "data": { "status": "disconnected", "message": "Stopping server..." } }
{ "type": "evt", "evt": "session_closed", "data": { "session_id": "abc123...", "peer_name": "CrimsonOtter", "claimed_name": "CrimsonOtter", "peer_key": "MCowBQYDK2VwAyEA...", "peer_fingerprint": "12345 67890 13579 24680 11223 34455 66778 89900", "known_peer": true, "name_mismatch": false, "name_conflict": false, "is_server": true, "msg_count": 3, "last_activity": "2026-06-21T10:35:00Z", "transport_type": "tcp", "remote_version": "0.5.0", "cause": "incoming", "session_ttl_ns": 0, "session_started_at": "2026-06-21T10:30:00Z" } }
{ "type": "evt", "evt": "server_running", "data": { "running": false, "transport": "tcp" } }
{ "type": "evt", "evt": "status_changed", "data": { "status": "disconnected", "message": "Server stopped" } }
{ "type": "evt", "evt": "history_updated", "data": {} }
{ "type": "evt", "evt": "server_stopped", "data": { "running": false } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "stopped" } }
```

`session_closed` comes for each session that was live, and `history_updated`
follows when there was one. `server_running` and its `status_changed` come
when a server was running, from the server's own shutdown, so they may come
before or between the `session_closed` events. A p2p server also emits
`p2p_tokens` with an empty list.

#### `restart_server`

Stops the server as `stop_server` does, which closes all sessions, and starts
it again with the params of the last `start_server`, `relay_pin` included and
with the address that command asked for. A relay server registers a new token,
and a p2p server gets a new random token unless it was started with
`peer_pub_b64`. Tokens that `generate_relay_token`, `generate_p2p_token` or
`get_share_info` added are gone, so share cards handed out before stop
working. It fails with `server_not_started` until a `start_server` has passed
its checks.

There is no `response` event: the events of `stop_server` up to
`server_stopped` come first, then those of `start_server`, and
`server_started`, or an error event, carries the `restart_server` command's
`id`.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "restart_server", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "status_changed", "data": { "status": "disconnected", "message": "Stopping server..." } }
{ "type": "evt", "evt": "server_running", "data": { "running": false, "transport": "tcp" } }
{ "type": "evt", "evt": "status_changed", "data": { "status": "disconnected", "message": "Server stopped" } }
{ "type": "evt", "evt": "server_stopped", "data": { "running": false } }
{ "type": "evt", "evt": "status_changed", "data": { "status": "connecting", "message": "Starting server..." } }
{ "type": "evt", "evt": "fingerprint_changed", "data": { "emoji": "🦊 • 🐱 • 🌵 • 🔑 • 🚀 • 🍀 • 🎲 • 🐙", "b64": "MCowBQYDK2VwAyEA...", "hex": "30:2A:30:05:06:03:2B:65:70:03:21:00:5D:...", "sum": "q3Vx0Zl8...", "numeric": "12345 67890 13579 24680 11223 34455 66778 89900" } }
{ "type": "evt", "evt": "server_running", "data": { "running": true, "transport": "tcp" } }
{ "type": "evt", "evt": "status_changed", "data": { "status": "connected", "message": "Server running on 127.0.0.1:9000" } }
{ "type": "evt", "evt": "history_updated", "data": {} }
{ "type": "evt", "evt": "server_started", "id": "1", "data": { "addr": "127.0.0.1:9000", "transport": "tcp", "name": "MyServer", "public_key": "MCowBQYDK2VwAyEA...", "emoji": ["🦊", "🐱", "🌵", "🔑", "🚀", "🍀", "🎲", "🐙"], "fingerprint_hex": "30:2A:30:05:06:03:2B:65:70:03:21:00:5D:...", "fingerprint_sum": "q3Vx0Zl8...", "fingerprint_numeric": "12345 67890 13579 24680 11223 34455 66778 89900" } }
```

#### `cancel_start_server`

Cancels an in-flight server start and waits up to 5 seconds for it to stop. It
fails with `server_start_not_in_progress` when no start is under way,
`server_already_started` when the start finished first (use `stop_server`),
and `cancel_timeout` when the start did not stop in time.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "cancel_start_server", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "status_changed", "data": { "status": "disconnected", "message": "Cancelled" } }
{ "type": "evt", "evt": "server_start_cancelled", "data": {} }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "cancelled" } }
```

#### `get_server_status`

Returns the current server state. `transport`, `relay_addr` and `name` are
those of the last `start_server` (`name` is empty when it gave none). `addr`
is the address the server is bound to while it runs, and otherwise the address
the last `start_server` asked for. `started_at` is when the running server
started, and empty while no server runs.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_server_status", "id": "1", "params": {} }
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "running": true,
    "transport": "tcp",
    "addr": "127.0.0.1:9000",
    "relay_addr": "",
    "name": "MyServer",
    "started_at": "2026-06-21T10:25:00Z"
  }
}
```

#### `get_status`

Returns the current connection status.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_status", "id": "1", "params": {} }
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "status": "connected",
    "message": "Server running on 127.0.0.1:9000"
  }
}
```

### Connections

#### `dial`

Connects to a remote kamune server. The command is checked at once, and the
dial then runs in the background; `session_started`, or an error event, carries
the command's `id`.

| Param                                 | Transports | Description                                                                                                                                                                                                                                                                                                          |
| ------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `transport`                           | all        | `"tcp"` (the default, when empty or absent), `"udp"`, `"relay"`, `"p2p"` or `"direct-p2p"`. Any other value fails with `invalid_transport`.                                                                                                                                                                          |
| `addr`                                | tcp, udp   | Required (`addr_required`). The server's address. Ignored for the other transports.                                                                                                                                                                                                                                  |
| `relay_addr`, `relay_pin`, `password` | relay      | As for [`start_server`](#start_server). `relay_addr` is required.                                                                                                                                                                                                                                                    |
| `token`                               | relay      | Required. The server's relay token in hex: 32 characters for a random token, 64 for a [static token](#relay), which the dialing side computes itself.                                                                                                                                                                |
| `name`                                | all        | The display name sent to the server and saved as the local name. Defaults to the fingerprint pseudonym, which incognito mode always uses (and does not save). Checked as for `start_server` (`invalid_name`).                                                                                                        |
| `broker_addr`                         | p2p        | Required. The broker's UDP `host:port`.                                                                                                                                                                                                                                                                              |
| `p2p_token`                           | p2p        | Required. The server's P2P token in hex: 32 characters for a random token, 64 for a static one. Anything else fails with `invalid_p2p_token`.                                                                                                                                                                        |
| `direct_peer_addr`                    | direct-p2p | Required. The peer's UDP `host:port`.                                                                                                                                                                                                                                                                                |
| `peer_pub_b64`                        | all        | The public key of the peer to reach, as `list_peers` gives it. The session must reach that key: a peer with another key is rejected before it is verified or asked about, whatever name it claims, and the dial fails with `peer_key_mismatch`. A key that is not a valid Ed25519 key fails with `invalid_peer_key`. |

Set `peer_pub_b64` whenever the dial is meant for a known peer, above all on
a [static token](#relay): anyone who knows both public keys can answer such a
token, and the relay or the broker picks who does. Without it, Quick mode
admits any stored peer that answers, under its own stored name. A reconnect of
a dialed session is always held to the key of the session's peer, with or
without `peer_pub_b64`.

For relay, connecting to the relay and the relay handshake are limited to 15
seconds. For p2p, the dial waits at most 30 seconds for the broker to match the
token (`p2p_match_failed`), then sends 5 packets to the server's address over
about 400 ms to open the NATs on the way before it starts KCP
(`hole_punch_failed` when it cannot send any).

Before the dial starts, the command fails with `invalid_params`,
`invalid_name`, `invalid_transport`, `addr_required`, `invalid_relay_pin`,
`invalid_peer_key` or `storage_not_opened`. A dial that fails later sets the
status to `error` and reports one of `storage_unavailable`,
`identity_unavailable`, `relay_dial_failed` (for example a missing
`relay_addr` or `token`), `broker_client_failed`, `invalid_p2p_token`,
`p2p_match_failed`, `hole_punch_failed`, `direct_p2p_failed`,
`create_dialer_failed`, `peer_key_mismatch` (the peer's key is not
`peer_pub_b64`), `dial_failed` (the handshake failed or the peer was
rejected) or `goroutine_panic`.

There is no command to cancel a dial. A server that accepts the connection but
stops answering keeps the dial waiting until the kamune library's handshake
limits run out: up to about 3 minutes, the 30-second handshake timeout plus
the 150 seconds allowed for the server's verifier.

**Input (TCP):**

```json
{
  "type": "cmd",
  "cmd": "dial",
  "id": "1",
  "params": { "addr": "127.0.0.1:9000", "name": "MyClient" }
}
```

**Input (Relay):**

```json
{
  "type": "cmd",
  "cmd": "dial",
  "id": "1",
  "params": {
    "transport": "relay",
    "relay_addr": "wss://relay.example.com:8443",
    "token": "deadbeef...",
    "password": "psk-secret"
  }
}
```

**Input (P2P via broker):**

```json
{
  "type": "cmd",
  "cmd": "dial",
  "id": "1",
  "params": {
    "transport": "p2p",
    "broker_addr": "broker.example.com:4788",
    "p2p_token": "4f1c2a9be07d35a8c6e19b0f72d4a3e5",
    "name": "MyClient"
  }
}
```

**Input (Direct P2P):**

```json
{
  "type": "cmd",
  "cmd": "dial",
  "id": "1",
  "params": {
    "transport": "direct-p2p",
    "direct_peer_addr": "203.0.113.5:9000",
    "name": "MyClient"
  }
}
```

**Output (correlated by command `id`):**

```json
{
  "type": "evt",
  "evt": "status_changed",
  "data": { "status": "connecting", "message": "Connecting to 127.0.0.1:9000..." }
}
{
  "type": "evt",
  "evt": "session_started",
  "id": "1",
  "data": {
    "session_id": "xyz789...",
    "peer_name": "CrimsonOtter",
    "claimed_name": "CrimsonOtter",
    "peer_key": "MCowBQYDK2VwAyEA...",
    "peer_fingerprint": "12345 67890 13579 24680 11223 34455 66778 89900",
    "known_peer": true,
    "name_mismatch": false,
    "name_conflict": false,
    "is_server": false,
    "msg_count": 0,
    "last_activity": "2026-06-21T10:30:00Z",
    "transport_type": "tcp",
    "remote_version": "0.5.0",
    "cause": "dial",
    "session_ttl_ns": 0,
    "session_started_at": "2026-06-21T10:30:00Z",
    "remote_addr": "127.0.0.1:9000"
  }
}
{
  "type": "evt",
  "evt": "status_changed",
  "data": { "status": "connected", "message": "Connected to 127.0.0.1:9000" }
}
```

In Strict mode, and in Quick mode for a server that is not a known peer, a
`verify_peer` event comes before `session_started`, and the dial waits for
`verify_response` (see [Verification Flow](#verification-flow)). If the peer
has a different minor version, a `version_warning` event comes too. The second
`status_changed` names the relay address for relay, `p2p` for p2p and the
peer's address for direct-p2p.

When the connection of a dialed session drops, the daemon tries to resume the
session, except for p2p and incognito sessions, and reports that with
`session_reconnecting` and, once it works, `session_reconnected` (see
[Push Events](#push-events)). When the session ends, `session_closed` fires
and the history is refreshed (`history_updated`). See
[Connection Drops](#connection-drops) for how the daemon tells a dropped
connection from the other ways a session ends.

#### `close_session`

Closes a live session, incoming or dialed, for good. The daemon sends the peer
a close frame and deletes the session's resumption and relay reconnect tokens,
so neither side can resume it, and waits up to 5 seconds for the session's
receive loop to end. The kamune library waits at most 5 seconds for the close
frame to go out; a peer that does not get it sees the connection drop, and
cannot resume the session either. Fails with `session_not_found` for a session
that is not live.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "close_session",
  "id": "1",
  "params": { "session_id": "xyz789..." }
}
```

**Output:**

```json
{ "type": "evt", "evt": "session_closed", "data": { "session_id": "xyz789...", "peer_name": "CrimsonOtter", "claimed_name": "CrimsonOtter", "peer_key": "MCowBQYDK2VwAyEA...", "peer_fingerprint": "12345 67890 13579 24680 11223 34455 66778 89900", "known_peer": true, "name_mismatch": false, "name_conflict": false, "is_server": false, "msg_count": 3, "last_activity": "2026-06-21T10:35:00Z", "transport_type": "tcp", "remote_version": "0.5.0", "cause": "dial", "session_ttl_ns": 0, "session_started_at": "2026-06-21T10:30:00Z", "remote_addr": "127.0.0.1:9000" } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "closed", "session_id": "xyz789..." } }
```

If this was the last active session, `status_changed` with
`{ "status": "disconnected", "message": "Not connected" }` follows the
response. The history is refreshed last (`history_updated`).

#### `rename_session`

Sets the `peer_name` of a live session, in memory only; `rename_history_session`
names a session in the history. Fails with `session_not_found` for a session
that is not live, and with `invalid_name` for a name that `start_server` would
refuse.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "rename_session",
  "id": "1",
  "params": { "session_id": "xyz789...", "name": "Alice" }
}
```

**Output:**

```json
{ "type": "evt", "evt": "session_updated", "data": { "session_id": "xyz789..." } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "ok" } }
```

#### `list_sessions`

Returns all active sessions.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "list_sessions", "id": "1", "params": {} }
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "sessions": [
      {
        "session_id": "xyz789...",
        "peer_name": "CrimsonOtter",
        "claimed_name": "CrimsonOtter",
        "peer_key": "MCowBQYDK2VwAyEA...",
        "peer_fingerprint": "12345 67890 13579 24680 11223 34455 66778 89900",
        "known_peer": true,
        "name_mismatch": false,
        "name_conflict": false,
        "is_server": false,
        "msg_count": 3,
        "last_activity": "2026-06-21T10:30:00Z",
        "transport_type": "tcp",
        "remote_version": "0.5.0",
        "cause": "dial",
        "session_ttl_ns": 0,
        "session_started_at": "2026-06-21T10:30:00Z",
        "remote_addr": "127.0.0.1:9000"
      }
    ]
  }
}
```

### Messaging

#### `send_message`

Sends a message on a live session and saves it to the session's history,
except in incognito mode. The send runs after the command is read, so other
commands are handled meanwhile, and the messages of one session are sent,
saved and reported with `message_sent` in the order of their commands.
`message_sent.timestamp` is the local time the message went out, the clock
that `get_history_messages` orders the history by, and `sent_at` the time the
daemon put on the message, which the peer gets as its `sent_at`.

A send that fails is not tried again, and fails with `send_message_failed`:

- with reason `connection_lost` when the connection is gone, so the message was
  not delivered. A dialed session then tries to resume (see
  `session_reconnecting`), and a server session ends. Every send on a session
  whose connection dropped fails this way until the session resumes, over a
  relay too;
- with reason `message_too_large` when the message is over the protocol's or
  the relay's limit, which leaves the session usable;
- with no reason for other failures.

Before the send, the command fails with `invalid_params`,
`session_id_required`, `data_base64_required`, `session_not_found` or
`invalid_base64`. A message that was sent but could not be saved is reported
with `history_save_failed` before its `message_sent`.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "send_message",
  "id": "1",
  "params": { "session_id": "xyz789...", "data_base64": "SGVsbG8sIFdvcmxkIQ==" }
}
```

**Output:**

```json
{ "type": "evt", "evt": "message_sent", "id": "1", "data": { "session_id": "xyz789...", "timestamp": "2026-06-21T10:30:00.123500000Z", "sent_at": "2026-06-21T10:30:00.123456789Z" } }
{ "type": "evt", "evt": "session_updated", "data": { "session_id": "xyz789..." } }
```

### Relay

A relay or p2p server can register a static token for one peer, by passing the
peer's public key as `peer_pub_b64`. The static token is SHA-256 over the two
raw 32-byte Ed25519 public keys, the smaller one first: 32 bytes, 64 hex
characters. The peer computes the same token from the same two keys and dials
with it, so neither side has to send the other a token.

A static token is not a secret, and it does not limit who can connect. Anyone
who knows both public keys, which peers hand out to be verified, can compute
it, and the relay and the broker do not check who registers or joins with it.
Whoever connects with it still goes through the verification mode. A session
on a static relay token whose peer has another key than the one the token was
made for is then closed before `session_started`, whatever the mode let in: a
stored peer that Quick mode admits cannot take a session meant for another
peer. The verifier runs first, so in Strict mode, or in Quick mode for an
unknown key, such a peer is still asked about, and its session is closed
whatever the answer; the token is used up either way. A p2p server checks the
same for its static tokens, as [P2P Tokens](#p2p-tokens) says. On the dialing
side, `peer_pub_b64` holds a [`dial`](#dial) to the peer it names. The
[security considerations](RELAY.md#security-considerations) of static tokens in
RELAY.md say what a third party can do with one.

#### `generate_relay_token`

Generates a new relay token for the running relay server: a random 16-byte
token (32 hex characters) that the relay picks, or, with `peer_pub_b64`, the
[static token](#relay) for that peer. `params` may be left out.

The token is registered with the relay after the command is read, for at most
15 seconds, and the response follows; other commands are handled meanwhile.
The command fails with `relay_not_configured` when no relay server runs,
`invalid_params` for params that do not parse, `invalid_peer_key` for a
`peer_pub_b64` that is not a valid Ed25519 key, and `relay_token_failed` when
the static token cannot be derived. A registration that fails reports
`relay_listen_failed`, `server_stopped` when the server stopped or restarted
meanwhile, or `listener_failed`.

**Input (random token):**

```json
{ "type": "cmd", "cmd": "generate_relay_token", "id": "1", "params": {} }
```

**Input (static token for specific peer):**

```json
{
  "type": "cmd",
  "cmd": "generate_relay_token",
  "id": "1",
  "params": { "peer_pub_b64": "base64key..." }
}
```

**Output:**

```json
{ "type": "evt", "evt": "relay_tokens", "data": { "tokens": [{ "token": "cafebabe...", "consumed": false, "ttl_ns": 600000000000, "session_ttl_ns": 300000000000, "expires_at": "2026-06-21T11:00:00Z", "mode": "static", "peer_pub_b64": "base64key..." }] } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "token": "cafebabe...", "ttl_ns": 600000000000, "session_ttl_ns": 300000000000, "expires_at": "2026-06-21T11:00:00Z", "mode": "static" } }
```

#### `remove_relay_token`

Removes a relay token from the list and closes its relay listener. Removing a
reconnect token (mode `ecdh`) ends the server's offer to resume that dropped
session through the relay: its reconnect tokens are deleted and none is
registered again. Fails with `token_not_found` for a token that is not listed.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "remove_relay_token",
  "id": "1",
  "params": { "token": "deadbeef..." }
}
```

**Output:**

```json
{ "type": "evt", "evt": "relay_tokens", "data": { "tokens": [] } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "removed" } }
```

#### `list_relay_tokens`

Returns the relay tokens of the running relay server.

| Field            | Description                                                                                                                         |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `token`          | The token in hex.                                                                                                                   |
| `consumed`       | `true` once a peer has connected with the token. A consumed token is removed from the list about 4 seconds later.                   |
| `ttl_ns`         | The token's lifetime, as the relay reported it.                                                                                     |
| `session_ttl_ns` | The relay's session TTL.                                                                                                            |
| `expires_at`     | When the token expires; it is then removed from the list.                                                                           |
| `mode`           | `random`, `static` for a [static token](#relay), or `ecdh` for a reconnect token that lets the peer of a dropped session resume it. |
| `peer_pub_b64`   | The public key that a static token was derived for. Omitted otherwise.                                                              |

A token also leaves the list when its listener loses its link to the relay
before a peer used it. For a token other than a reconnect token, the daemon
then emits an `error` event without an `id` and with code `relay_link_lost`,
since no peer can connect with that token any more. A server whose list runs
empty through expiry or a lost link keeps running and logs a warning; it
accepts connections again once `generate_relay_token` or `get_share_info`
registers a token.

When the connection of a session that came through the relay drops, the server
registers a listener with one of the session's reconnect tokens, which the two
peers derived when the session started, so that the peer can resume the
session through the relay. Such a listener is listed with mode `ecdh`. Each
reconnect token is registered once and then deleted. When a listener ends
unused, the server registers the next token, until the session has resumed,
its reconnect tokens or its resumption tokens run out, the server stops, or 10
minutes have passed since the drop. `remove_relay_token` on the listener's
token, or `delete_history_session` of the session, ends this and deletes the
session's reconnect tokens. A session that ends with `close_session`, a
graceful close by the peer, or any way other than a dropped connection gets no
such listener, and its reconnect tokens are deleted.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "list_relay_tokens", "id": "1", "params": {} }
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "tokens": [
      {
        "token": "deadbeef...",
        "consumed": false,
        "ttl_ns": 600000000000,
        "session_ttl_ns": 300000000000,
        "expires_at": "2026-06-21T11:00:00Z",
        "mode": "random"
      }
    ]
  }
}
```

#### `get_share_info`

Returns a connection card for the running server, or fails with
`server_not_running`. The card carries the server's fingerprint as
`fingerprint_emoji`, `fingerprint_hex` and `fingerprint_numeric`, the last
being the one for the peer to compare.

- **tcp, udp, direct-p2p**: `address` and `port` are those the server is bound
  to. When it is bound to every interface (`0.0.0.0`, `[::]` or an empty
  host), `address` is the first non-loopback IPv4 address of the host
  (`detect_ip_failed` when there is none). `url` is
  `<transport>://<address>:<port>`.
- **relay**: the card carries the token of the previous card while that token
  is listed, unused, and has more than half its lifetime left. Otherwise a new
  random token is registered for it, after the command is read and for at most
  15 seconds, which can fail with `relay_token_failed`, `server_stopped` or
  `listener_failed`. Call `generate_relay_token` for a token of its own for
  each peer. `relay_info` names the relay's address and scheme (`wss` for an
  address without one), the token, whether the relay needs a password, and
  `pin`, the relay's certificate fingerprint, when the server was started
  with `relay_pin`. The `url` carries the same as query parameters, with
  `password=1` and `pin=<hex>` only when they apply; the password itself is
  never on the card.
- **p2p**: `address` is the broker address and `url` is
  `p2p://<broker_addr>?token=<token>`, with the server's first P2P token.

`relay_info` is `null` for every transport but relay.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_share_info", "id": "1", "params": {} }
```

**Output (TCP):**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "url": "tcp://192.168.1.5:9000",
    "transport": "tcp",
    "address": "192.168.1.5",
    "port": "9000",
    "fingerprint_emoji": "🦊 • 🐱 • 🌵 • 🔑 • 🚀 • 🍀 • 🎲 • 🐙",
    "fingerprint_hex": "30:2A:30:05:06:03:2B:65:70:03:21:00:5D:...",
    "fingerprint_numeric": "12345 67890 13579 24680 11223 34455 66778 89900",
    "relay_info": null
  }
}
```

**Output (Relay), when a new token is registered for the card:**

```json
{ "type": "evt", "evt": "relay_tokens", "data": { "tokens": [{ "token": "freshbeef...", "consumed": false, "ttl_ns": 600000000000, "session_ttl_ns": 300000000000, "expires_at": "2026-06-21T11:00:00Z", "mode": "random" }] } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "url": "relay://relay.example.com:8443?token=freshbeef...&scheme=wss", "transport": "relay", "address": "", "port": "", "fingerprint_emoji": "🦊 • 🐱 • 🌵 • 🔑 • 🚀 • 🍀 • 🎲 • 🐙", "fingerprint_hex": "30:2A:30:05:06:03:2B:65:70:03:21:00:5D:...", "fingerprint_numeric": "12345 67890 13579 24680 11223 34455 66778 89900", "relay_info": { "address": "relay.example.com:8443", "scheme": "wss", "token": "freshbeef...", "password": false } } }
```

### P2P Tokens

A p2p server (`start_server` with `transport: "p2p"`) binds a UDP punch socket,
registers its tokens with the broker at `broker_addr` from that socket, and
refreshes each registration every 30 seconds. `broker_addr` is the broker's UDP
`host:port` (the relay's shipped config puts its broker on port 4788), not a
URL. A dialer registers the same token, the broker tells each side the other's
public address, and both send packets toward the other to open their NATs. The
server lets KCP packets in only from hosts that the broker matched with one of
its tokens, for 10 minutes after the match and after each packet.

A token is either random, 16 bytes (32 hex characters), or static, 32 bytes
(64 hex characters): the [static token](#relay) for the `peer_pub_b64` given
to `start_server` or `generate_p2p_token`. A P2P token is not used up by
a match: it stays registered until it is removed or the server stops.

A KCP session does not tell which token its peer matched on, so the server
checks peers against its tokens as a whole. While it registers a random
token, its own or one that `generate_p2p_token` added, it admits any peer.
While all its tokens are static, it closes a session whose peer is not one of
their peers before `session_started`, as a relay server does for a static
relay token.

#### `generate_p2p_token`

Adds a token to the running p2p server, which registers and refreshes it from
its punch socket, and returns it. `broker_addr` is required and must be the
`broker_addr` the server was started with. Without `peer_pub_b64` the server's
random token is returned, or a random token that the daemon picks is added when
the server has none. With `peer_pub_b64` the token is the
[static token](#relay) for that peer, returned as it is when the server has it
already. The broker carries the first 16 bytes of a static token, and
anyone who computes it can register with it and is sent the server's public IP
address and port (see the broker's
[Static Tokens](RELAY.md#static-tokens-1) in RELAY.md).

It fails with `p2p_server_not_running` when no p2p server runs,
`broker_addr_mismatch` when `broker_addr` is not the server's broker, and
`p2p_token_failed` otherwise. A new token is announced with `p2p_tokens` before
the response.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "generate_p2p_token",
  "id": "1",
  "params": {
    "broker_addr": "broker.example.com:4788",
    "peer_pub_b64": "base64key..."
  }
}
```

**Output:**

```json
{ "type": "evt", "evt": "p2p_tokens", "data": { "tokens": [{ "token": "hex-token...", "consumed": false, "ttl_ns": 60000000000, "expires_at": "2026-06-21T11:00:00Z", "mode": "static", "peer_pub_b64": "base64key..." }] } }
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "token": "hex-token...",
    "broker_addr": "broker.example.com:4788",
    "peer_pub_b64": "base64key..."
  }
}
```

#### `remove_p2p_token`

Removes a P2P token, the server's own token included, and stops the p2p server
from registering it again. The broker has no way to drop a registration at
once, so it forgets the token when its last registration expires, within its
`registration_ttl` (60 seconds by default). Fails with
`p2p_token_remove_failed` for a token that is not listed.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "remove_p2p_token",
  "id": "1",
  "params": { "token": "hex-token..." }
}
```

**Output:**

```json
{ "type": "evt", "evt": "p2p_tokens", "data": { "tokens": [] } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "removed" } }
```

#### `list_p2p_tokens`

Returns the tokens of the running p2p server.

| Field          | Description                                                                                                                                                       |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `token`        | The token in hex: 32 characters for a random token, 64 for a static one.                                                                                          |
| `consumed`     | Always `false`: a match does not use a P2P token up.                                                                                                              |
| `ttl_ns`       | How long the broker keeps a registration after a refresh, as the daemon reckons it: always 60 seconds, the default `registration_ttl` of the relay's broker.      |
| `expires_at`   | When the broker drops the registration unless the server refreshes it first. Each refresh moves it on, so it stays 30 to 60 seconds ahead while refreshes go out. |
| `mode`         | `random` or `static`.                                                                                                                                             |
| `peer_pub_b64` | The public key that a static token was derived for. Omitted for a random token.                                                                                   |

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "list_p2p_tokens", "id": "1", "params": {} }
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "tokens": [
      {
        "token": "4f1c2a9be07d35a8c6e19b0f72d4a3e5",
        "consumed": false,
        "ttl_ns": 60000000000,
        "expires_at": "2026-06-21T11:00:00Z",
        "mode": "random"
      }
    ]
  }
}
```

### Connections (continued)

#### `get_session_info`

Returns info for a single session: a live one, or else one from the history
list. A session ID that is neither fails with `session_not_found`.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "get_session_info",
  "id": "1",
  "params": { "session_id": "xyz789..." }
}
```

**Output (live session):**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "type": "live",
    "session_id": "xyz789...",
    "peer_name": "CrimsonOtter",
    "claimed_name": "CrimsonOtter",
    "peer_key": "MCowBQYDK2VwAyEA...",
    "peer_fingerprint": "12345 67890 13579 24680 11223 34455 66778 89900",
    "known_peer": true,
    "name_mismatch": false,
    "name_conflict": false,
    "is_server": false,
    "msg_count": 3,
    "last_activity": "2026-06-21T10:30:00Z",
    "transport_type": "tcp",
    "remote_version": "0.5.0",
    "cause": "dial",
    "session_ttl_ns": 0,
    "session_started_at": "2026-06-21T10:25:00Z",
    "remote_addr": "192.168.1.10:9000"
  }
}
```

**Output (history session):**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "type": "history",
    "session_id": "abc123...",
    "name": "Alice",
    "msg_count": 15,
    "first_message": "2026-06-20T09:00:00Z",
    "last_message": "2026-06-20T10:30:00Z",
    "loaded": false
  }
}
```

### Verification

Modes: `0` = Strict (prompt for every peer, known or not), `1` = Quick
(accept known peers without a prompt, prompt for others), `2` = Auto-Accept
(accept every peer, and store none of them as a known peer). Only the key
decides whether a peer is known, never the name it claims, and sessions and
prompts name a known peer by its stored name. Without a saved
mode the daemon uses Quick, unless the client set a mode before it opened
the first storage. No mode prompts for a peer that resumes a session, Strict
included. See [Verification Flow](#verification-flow).

#### `set_verification_mode`

Sets the verification mode, and saves it while a storage is open. The new mode
applies to the next peer verified, by a running server too: the server is not
restarted, and live sessions and relay tokens are kept. A mode other than 0, 1
or 2 fails with `invalid_verification_mode`.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "set_verification_mode",
  "id": "1",
  "params": { "mode": 1 }
}
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": { "status": "ok", "mode": "1" }
}
```

The response gives the mode as a string.

#### `get_verification_mode`

Returns the current verification mode.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_verification_mode", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "mode": "1" } }
```

#### `verify_response`

Answers a pending `verify_peer` event (see [`verify_peer`](#verify_peer)). A
`request_id` that names no pending prompt, because it was answered, timed out,
was replaced by a newer prompt for the same peer or ended when the server
stopped, fails with `verification_not_found`. An
unknown peer that is accepted is stored as a known peer once its session is
established, unless incognito mode is on; a peer whose handshake fails after
it was accepted is not stored. It is stored under the name it claimed, unless
that name is empty or another stored peer has it (see `name_conflict`); then
it is stored under the pseudonym of its key.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "verify_response",
  "id": "1",
  "params": { "request_id": 42, "accepted": true }
}
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "ok" } }
```

### Incognito Mode

When incognito mode is enabled:

- New servers and dials use the fingerprint pseudonym of the identity key as
  their name, and do not save it as the local name.
- Messages that are sent or received are not saved.
- Sessions leave no record in the storage. The daemon creates no session
  record and stores no relay reconnect tokens, and the kamune library
  (`ServeWithoutPersistence`, `DialWithoutPersistence`) stores neither the
  peer's key, the session's start time nor resumption tokens, and leaves the
  last-seen time of a stored peer alone.
- Accepted peers are not stored.
- Sessions cannot be resumed. A dialed session whose connection drops ends with
  `session_closed`, with no `session_reconnecting`; a server started in
  incognito mode refuses resumption; and a dropped relay session gets no
  reconnect listener.

Incognito mode keeps sessions out of this daemon's storage only: a peer that
is not in incognito mode stores the session and its messages as usual.
Commands that change the storage still do so, such as the settings commands
(the incognito flag is itself saved), `set_my_name`, and the peer and history
commands.

The identity key stays the same, so a peer that knows the key, or its
fingerprint, still recognizes the user, and the pseudonym is derived from it.
Existing session history and peers remain accessible. The incognito flag is
saved in the open storage and applied when that storage is opened.

`set_incognito` applies at once to what the daemon saves itself (messages,
session records and peers) and to the next dial, except for a session that
started in incognito mode, or on a server started in it: such a session stays
out of storage until it ends, and none of its messages are saved after the
mode is turned off. A running server keeps what it started with until
`restart_server`: its name, and whether the kamune library stores its
sessions and lets peers resume them, and so new sessions on a server started
in incognito mode are incognito too. A server started with incognito mode off
still has the library store the peer's key, start time and resumption tokens
of each new session, and update a stored peer's last-seen time. A dialed
session likewise keeps what was chosen when it was dialed. Changing the flag
while a server runs logs a warning.

#### `get_incognito`

Returns the current incognito mode state.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_incognito", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "enabled": true } }
```

#### `set_incognito`

Enables or disables incognito mode, and saves the flag while a storage is
open.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "set_incognito",
  "id": "1",
  "params": { "enabled": true }
}
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "enabled": true } }
```

### History

#### `get_history_sessions`

Returns the history list: the sessions stored in the open storage, the one
with the most recent message first. The daemon keeps the list in memory, and
reads it again when a storage is opened, a server starts or a session ends,
and on `refresh_history`. `message_count`, `first_message` and
`last_message` describe the session's stored messages, and `loaded` tells
whether `load_history` was called for it. A `name` that the name rules
refuse, as another client may have stored it, is made safe to show as for
`list_peers`, here and in `get_session_info`.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_history_sessions", "id": "1", "params": {} }
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "sessions": [
      {
        "id": "abc123...",
        "name": "Alice",
        "message_count": 15,
        "first_message": "2026-06-20T09:00:00Z",
        "last_message": "2026-06-20T10:30:00Z",
        "loaded": false
      }
    ]
  }
}
```

#### `load_history`

Marks a session of the history list as loaded, so that
`get_history_messages` returns its messages. Fails with `history_not_found` for
a session that is not in the list.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "load_history",
  "id": "1",
  "params": { "session_id": "abc123..." }
}
```

**Output:**

```json
{ "type": "evt", "evt": "history_loaded", "data": { "session_id": "abc123..." } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "loaded" } }
```

#### `get_history_messages`

Returns one page of the messages of a session, oldest first. The session must
have been loaded with `load_history`; otherwise the command fails with
`history_not_loaded`. It also fails with `storage_unavailable` or
`history_fetch_failed`.

`limit` is the most messages to return: 500 when it is 0, negative or absent.
`offset` is how many messages to skip from the oldest: a negative offset is
read as 0, and one past the last message as the message count. The response
carries the page, `total` (all messages of the session), and the `offset` and
`limit` that were used.

Each message has `text` (the data as a string), `data_base64` (the data),
`is_local` (`true` for a message this side sent), `timestamp`, when the
message was stored by the local clock, which orders the history, and
`sent_at`, the time its sender put on it. The sender can set `sent_at` to
anything, and it is left out for messages stored without one.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "get_history_messages",
  "id": "1",
  "params": { "session_id": "abc123...", "limit": 50, "offset": 0 }
}
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "messages": [
      {
        "text": "Hello, World!",
        "data_base64": "SGVsbG8sIFdvcmxkIQ==",
        "timestamp": "2026-06-20T09:00:00.120Z",
        "sent_at": "2026-06-20T09:00:00.100Z",
        "is_local": true
      }
    ],
    "total": 15,
    "offset": 0,
    "limit": 50
  }
}
```

#### `rename_history_session`

Saves a new name for a session of the history. Fails with
`storage_unavailable` or `rename_failed`.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "rename_history_session",
  "id": "1",
  "params": { "session_id": "abc123...", "name": "Project Discussion" }
}
```

**Output:**

```json
{ "type": "evt", "evt": "history_updated", "data": {} }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "ok" } }
```

#### `delete_history_session`

Deletes a session of the history and all its messages. The database is then
compacted, so that the deleted data does not stay in its file. When the
compaction fails, the session is deleted all the same, and the response has a
`warning` that the deleted data may still be in the file. Deleting a dropped
relay session also ends the server's offer to resume it through the relay.

Fails with `session_active` while the session is live, since its next message
would start its history again (close it with `close_session` first), and with
`storage_unavailable` or `delete_failed`.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "delete_history_session",
  "id": "1",
  "params": { "session_id": "abc123..." }
}
```

**Output:**

```json
{ "type": "evt", "evt": "history_updated", "data": {} }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "deleted" } }
```

When the compaction failed:

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "deleted", "warning": "deleted, but compacting the database failed, so the deleted data may still be in its file: ..." } }
```

#### `refresh_history`

Reloads the history list from storage.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "refresh_history", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "history_updated", "data": {} }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "refreshed" } }
```

### Peers

#### `list_peers`

Returns all known peers. `app_version` is empty for a peer added with
`add_peer`. A stored name that the name rules refuse, as one stored before
the protocol limited names, is shown with each character that the rules
refuse as U+FFFD and cut to 64 bytes, as `peer_name` in `SessionInfo` is.
Fails with `storage_unavailable` or `peer_list_failed`.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "list_peers", "id": "1", "params": {} }
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "peers": [
      {
        "name": "CrimsonOtter",
        "app_version": "0.5.0",
        "first_seen": "2026-06-15T10:00:00Z",
        "last_seen": "2026-06-21T10:30:00Z",
        "public_key": "base64encodedkey..."
      }
    ]
  }
}
```

#### `add_peer`

Adds a known peer manually. `name` is optional; defaults to the fingerprint
pseudonym. `public_key` must be a valid Ed25519 key, 44 bytes of PKIX in
base64url; anything else, such as a key of small order, fails with
`invalid_peer_key`. A name that `start_server` would refuse fails with
`invalid_name`. It also fails with `storage_unavailable`,
`peer_already_exists` or `peer_store_failed`.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "add_peer",
  "id": "1",
  "params": {
    "public_key": "base64encodedkey...",
    "name": "Alice"
  }
}
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": { "status": "added", "name": "Alice" }
}
```

#### `rename_peer`

Updates the display name of a known peer. An empty or absent name resets it to
the fingerprint pseudonym, and a name that `start_server` would refuse fails
with `invalid_name`. It also fails with `invalid_peer_key`,
`storage_unavailable`, `peer_not_found` or `peer_store_failed`.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "rename_peer",
  "id": "1",
  "params": {
    "public_key": "base64encodedkey...",
    "name": "NewName"
  }
}
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": { "status": "renamed", "name": "NewName" }
}
```

#### `get_peer`

Returns a single known peer by base64 public key, its name made safe to show
as for `list_peers`. Fails with `invalid_peer_key`, `storage_unavailable` or
`peer_not_found`.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "get_peer",
  "id": "1",
  "params": { "public_key": "base64encodedkey..." }
}
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "name": "CrimsonOtter",
    "public_key": "base64key...",
    "first_seen": "2026-06-15T10:00:00Z",
    "last_seen": "2026-06-21T10:30:00Z",
    "app_version": "0.5.0"
  }
}
```

#### `delete_peer`

Removes a known peer. Its sessions are kept. The database is then compacted,
and when that fails the peer is deleted all the same, with a `warning` in the
response as for [`delete_history_session`](#delete_history_session). Fails
with `storage_unavailable`, `invalid_peer_key` or `peer_delete_failed`.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "delete_peer",
  "id": "1",
  "params": { "public_key": "base64encodedkey..." }
}
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "deleted" } }
```

### Log Management

Log entries are buffered in memory (200-entry ring buffer). Each entry emits a
`log_entry` push event (see [Push Events](#log_entry)). An entry below the log
level that `set_log_level` chose goes nowhere: not to stderr, the buffer,
`log_entry` or `export_logs`. Relay and P2P tokens appear in log messages only
as their first 8 characters followed by `...`.

#### `get_logs`

Returns all buffered log entries.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_logs", "id": "1", "params": {} }
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "entries": [
      {
        "timestamp": "2026-06-21T10:30:00Z",
        "level": "INFO",
        "message": "[cmd/daemon] Server started"
      }
    ]
  }
}
```

#### `clear_logs`

Clears all buffered log entries.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "clear_logs", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "cleared" } }
```

#### `export_logs`

Writes buffered logs to a file. `file_path` is optional, and defaults to
`kamune-logs-<YYYY-MM-DD_HHMMSS>.txt` in the daemon's working directory. Each
entry is one line, `<RFC 3339 time> [<LEVEL>] <message>`, with characters that
are not printable, such as a line break in a peer's name, escaped Go-style
(`\n`, `\x1b`, `\u2028`). The file is written as a new file that only the
user can read (mode 0600) and then renamed to `file_path`, so it replaces a
file or a symbolic link there without writing through it. Fails with
`export_file_failed` or `export_write_failed`.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "export_logs",
  "id": "1",
  "params": { "file_path": "/home/alice/kamune-logs.txt" }
}
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": { "status": "exported", "file_path": "/home/alice/kamune-logs.txt" }
}
```

#### `get_log_level`

Returns the current log level.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_log_level", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "level": "INFO" } }
```

#### `set_log_level`

Sets the log level, and saves it while a storage is open. Accepted values are
`"DEBUG"`, `"INFO"` (the default), `"WARN"` (or `"WARNING"`) and `"ERROR"`, in
any case; any other value fails with `invalid_log_level`. The level applies to
stderr, the log buffer, `log_entry` events and `export_logs` alike. At `INFO`,
`DEBUG` lines such as the one for each message sent or received are dropped.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "set_log_level",
  "id": "1",
  "params": { "level": "DEBUG" }
}
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": { "status": "set", "level": "DEBUG" }
}
```

### Keychain

The daemon saves a storage passphrase to the system keychain (macOS Keychain,
Linux Secret Service, Windows Credential Manager) only when `submit_passphrase`
or `change_passphrase` asks for it with `save_to_keychain`, and
`change_passphrase` removes an entry that the new passphrase makes stale. It
never reads the saved passphrase to open a storage: `has_keychain_passphrase`
only reports whether one is saved, for a client that reads the keychain
itself. Entries use the service `kamune` and the account
`db-passphrase:<storage_path>`, with the path as `open_storage` was given it.

#### `has_keychain_passphrase`

Returns whether a passphrase is stored in the system keychain for the storage
that [`submit_passphrase`](#submit_passphrase) would open: that of the last
`open_storage` when it failed, or else the storage that is open, or that was
open last. Before any `open_storage`, it looks at the account
`db-passphrase:default`.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "has_keychain_passphrase", "id": "1", "params": {} }
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": { "has_passphrase": true }
}
```

#### `clear_keychain_passphrase`

Removes the stored passphrase of the storage that `has_keychain_passphrase`
looks at from the system keychain. Fails with `keychain_clear_failed` when it
cannot, which includes when no passphrase is saved.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "clear_keychain_passphrase", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "cleared" } }
```

### Fingerprint Format

The daemon can display fingerprints in different formats: `"hex"` (the
default), `"emoji"`, `"b64"`, `"sum"` or `"numeric"`. The format chooses what
`get_fingerprint` puts in `display`. It is saved in the open storage and
applied when that storage is opened. It does not change what to compare to
verify a key, which is `numeric` in every format; the eight emoji are too few
to rely on (see [`verify_peer`](#verify_peer)).

#### `get_fingerprint_format`

Returns the current fingerprint format.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_fingerprint_format", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "format": "hex" } }
```

#### `set_fingerprint_format`

Sets the fingerprint display format, and saves it while a storage is open.
Any format other than those above fails with `invalid_fingerprint_format`.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "set_fingerprint_format",
  "id": "1",
  "params": { "format": "emoji" }
}
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": { "status": "set", "format": "emoji" }
}
```

### Identity

#### `get_fingerprint`

Returns the fingerprint of the identity key in every format, plus `format`,
the display format, and `display`, the fingerprint in that format. All are
empty strings while no identity is loaded.

| Field     | Description                                                                                                        |
| --------- | ------------------------------------------------------------------------------------------------------------------ |
| `emoji`   | Eight emoji, joined with `" • "`. About 52.7 bits: too few to verify a key with.                                   |
| `b64`     | The public key: its 44-byte PKIX encoding in unpadded base64url.                                                   |
| `hex`     | The PKIX encoding as uppercase hex bytes separated by colons. The first 12 bytes are the same for every key.       |
| `sum`     | The SHA-256 of the PKIX encoding in unpadded base64url.                                                            |
| `numeric` | 40 digits in eight groups of five, about 132.9 bits: the fingerprint for people to compare when they verify a key. |

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_fingerprint", "id": "1", "params": {} }
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "emoji": "🦊 • 🐱 • 🌵 • 🔑 • 🚀 • 🍀 • 🎲 • 🐙",
    "b64": "MCowBQYDK2VwAyEA...",
    "hex": "30:2A:30:05:06:03:2B:65:70:03:21:00:5D:...",
    "sum": "q3Vx0Zl8...",
    "numeric": "12345 67890 13579 24680 11223 34455 66778 89900",
    "format": "hex",
    "display": "30:2A:30:05:06:03:2B:65:70:03:21:00:5D:..."
  }
}
```

#### `get_my_name`

Returns the local display name.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_my_name", "id": "1", "params": {} }
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": { "name": "CrimsonOtter" }
}
```

#### `set_my_name`

Sets the local display name, and saves it while a storage is open
(`name_persist_failed` when that fails). A name longer than 32 bytes fails with
`name_too_long`, and one that `start_server` would refuse with
`invalid_name`.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "set_my_name",
  "id": "1",
  "params": { "name": "CrimsonOtter" }
}
```

**Output:**

```json
{ "type": "evt", "evt": "local_name_changed", "data": { "name": "CrimsonOtter" } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "ok" } }
```

### Version

#### `get_version`

Returns the daemon version: the one the build script sets, or `"dev"`.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_version", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "version": "1.0.0" } }
```

#### `get_library_version`

Returns the kamune library version.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "get_library_version", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "version": "0.5.0" } }
```

### General

#### `shutdown`

Gracefully shuts down the daemon. Stops the server and any server start,
closes every session, each reported with `session_closed` before the response,
and closes the storage; the process then exits. A dial that completes during
the shutdown is closed and never reported, and a line that arrives after the
shutdown is dropped.

The daemon shuts down the same way when stdin ends, and when the process gets
SIGTERM or SIGINT, which it handles between commands without waiting for stdin
to deliver a line or end; the response then carries no `id`. A second signal
ends the process at once.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "shutdown", "id": "1", "params": {} }
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": { "status": "shutdown" }
}
```

## Push Events

These events are emitted by the daemon **without** the client sending a
command. They are triggered by peer activity, internal state changes, or
verification flows.

The other events answer commands and are documented with them: `response`,
`server_started`, `server_stopped` and `server_start_cancelled` (server
lifecycle), `relay_token` ([`start_server`](#start_server)), `message_sent`
(`send_message`) and `history_loaded` (`load_history`).

### `ready`

Emitted once on daemon startup.

```json
{
  "type": "evt",
  "evt": "ready",
  "data": { "version": "1.0.0", "pid": "12345", "protocol_version": "1" }
}
```

### `status_changed`

Emitted when the connection status changes (`disconnected`, `connecting`,
`connected`, `verifying`, `error`). The status is `verifying` while
`verify_peer` prompts are open; a verification that times out does not set
`error`.

```json
{
  "type": "evt",
  "evt": "status_changed",
  "data": {
    "status": "connecting",
    "message": "Connecting to 127.0.0.1:9000..."
  }
}
```

### `server_running`

Emitted when the server starts or stops.

```json
{
  "type": "evt",
  "evt": "server_running",
  "data": { "running": true, "transport": "tcp" }
}
```

### `fingerprint_changed`

Emitted when the identity fingerprint is loaded: when a storage is opened and
when a server starts. The fields are those of
[`get_fingerprint`](#get_fingerprint) without `format` and `display`; compare
`numeric` to verify a key.

```json
{
  "type": "evt",
  "evt": "fingerprint_changed",
  "data": {
    "emoji": "🦊 • 🐱 • 🌵 • 🔑 • 🚀 • 🍀 • 🎲 • 🐙",
    "b64": "MCowBQYDK2VwAyEA...",
    "hex": "30:2A:30:05:06:03:2B:65:70:03:21:00:5D:...",
    "sum": "q3Vx0Zl8...",
    "numeric": "12345 67890 13579 24680 11223 34455 66778 89900"
  }
}
```

### `local_name_changed`

Emitted when the local display name is loaded by `open_storage` or
`submit_passphrase`, or set by `set_my_name`.

```json
{
  "type": "evt",
  "evt": "local_name_changed",
  "data": { "name": "CrimsonOtter" }
}
```

### `session_started` (incoming)

Emitted when a peer connects to the server (not from `dial`). The
`session_started` from `dial` is correlated with the command `id` and documented
in [Commands](#connections).

```json
{
  "type": "evt",
  "evt": "session_started",
  "data": {
    "session_id": "abc123...",
    "peer_name": "IncomingPeer",
    "claimed_name": "IncomingPeer",
    "peer_key": "MCowBQYDK2VwAyEA...",
    "peer_fingerprint": "12345 67890 13579 24680 11223 34455 66778 89900",
    "known_peer": true,
    "name_mismatch": false,
    "name_conflict": false,
    "is_server": true,
    "msg_count": 0,
    "last_activity": "2026-06-21T10:30:00Z",
    "transport_type": "tcp",
    "remote_version": "0.5.0",
    "cause": "incoming",
    "session_ttl_ns": 0,
    "session_started_at": "2026-06-21T10:30:00Z"
  }
}
```

### `session_closed`

Emitted whenever a session ends: the peer closed it, its connection dropped
and was not resumed, or `close_session`, `stop_server`, `restart_server` or
`shutdown` closed it. The data is the session's `SessionInfo`, as for
[`close_session`](#close_session).

```json
{
  "type": "evt",
  "evt": "session_closed",
  "data": {
    "session_id": "abc123...",
    "peer_name": "CrimsonOtter",
    "claimed_name": "CrimsonOtter",
    "peer_key": "MCowBQYDK2VwAyEA...",
    "peer_fingerprint": "12345 67890 13579 24680 11223 34455 66778 89900",
    "known_peer": true,
    "name_mismatch": false,
    "name_conflict": false,
    "is_server": false,
    "msg_count": 3,
    "last_activity": "2026-06-21T10:35:00Z",
    "transport_type": "tcp",
    "remote_version": "0.5.0",
    "cause": "dial",
    "session_ttl_ns": 0,
    "session_started_at": "2026-06-21T10:30:00Z",
    "remote_addr": "127.0.0.1:9000"
  }
}
```

### `session_updated`

Emitted when a message is sent, received, or a live session is renamed.

```json
{
  "type": "evt",
  "evt": "session_updated",
  "data": { "session_id": "abc123..." }
}
```

### `message_received`

Emitted when a message is received from a peer. Also emits `session_updated`.
`timestamp` is the local time the message arrived, the clock that
`get_history_messages` orders the history by, so live messages and loaded
history can be merged by it. `sent_at` is the time the sender put on the
message, which the sender can set to anything: show it only as the sender's
claim. A message that could not be saved to history is reported with
`history_save_failed` first.

```json
{
  "type": "evt",
  "evt": "message_received",
  "data": {
    "session_id": "abc123...",
    "data_base64": "SGVsbG8sIFdvcmxkIQ==",
    "timestamp": "2026-06-21T10:30:00.223456789Z",
    "sent_at": "2026-06-21T10:30:00.123456789Z"
  }
}
{
  "type": "evt",
  "evt": "session_updated",
  "data": { "session_id": "abc123..." }
}
```

### `session_reconnecting`

Emitted before each attempt to resume a dialed session whose connection
dropped. The daemon makes up to 10 attempts, waiting 1 second before the
second and twice as long before each next one, at most 30 seconds. p2p and
incognito sessions are never resumed, and get no such event. A resume needs
the session's peer to be a stored peer and its resumption state to be in the
storage, so a session with a peer accepted in Auto-Accept mode gets one
attempt that fails. A resume that the server rejects, missing storage or
resumption state, or a panic ends the attempts at once; other errors are
retried. A server that refuses resumption, as one started in incognito mode
does, closes the connection instead of rejecting the resume, so the attempts
go on until they run out. Through a relay, each attempt tries the session's
stored reconnect tokens in turn, all within 15 seconds. When the attempts end
without success, `session_closed` follows.

```json
{
  "type": "evt",
  "evt": "session_reconnecting",
  "data": { "session_id": "abc123...", "attempt": 1, "max_attempts": 10 }
}
```

### `session_reconnected`

Emitted when a dialed session has been resumed. The session keeps its ID and
carries on.

```json
{
  "type": "evt",
  "evt": "session_reconnected",
  "data": { "session_id": "abc123..." }
}
```

### `history_updated`

Emitted when the history list has been read again or changed: when a storage
is opened, a server starts or a session ends, and on `refresh_history`,
`rename_history_session` and `delete_history_session`. Call
`get_history_sessions` for the list.

```json
{ "type": "evt", "evt": "history_updated", "data": {} }
```

### `history_save_failed`

Emitted when a message that was sent or received could not be saved to
history. `message_sent` or `message_received` still follows for it.

```json
{
  "type": "evt",
  "evt": "history_save_failed",
  "data": { "session_id": "abc123...", "error": "..." }
}
```

### `version_warning`

Emitted when a peer has a different minor version.

```json
{
  "type": "evt",
  "evt": "version_warning",
  "data": {
    "session_id": "abc123...",
    "message": "Minor version mismatch (v0.4.0 vs v0.5.0): things may not work as expected"
  }
}
```

### `verify_peer`

Emitted when a peer needs the user's verdict: every peer in Strict mode, and a
peer that is not known in Quick mode. The client must answer with
`verify_response` within 2 minutes; the peer is rejected otherwise.

Ask the user to compare `numeric`, 40 digits in eight groups of five, with the
peer over a trusted channel before accepting. It carries about 132.9 bits. The
eight `emoji` carry about 52.7 bits, few enough that an attacker can search for
a key that shows the same emoji, so they must not be relied on alone. `hex` is
the whole PKIX key, whose first 12 bytes are the same for every Ed25519 key.
`peer_name` is the name stored for the peer's key, or, for a key that is not
stored, `Unknown peer` and the first ten digits of `numeric`. `claimed_name`
is the name the peer chose for itself, and proves nothing: show it only as
the peer's claim. `peer_key` is the peer's public key, base64 as `list_peers`
gives it. The default names that the daemon derives from a key, its
pseudonym (two adjectives, a noun and a number, such as `brave misty otter
42`), are nicknames of about 29.6 bits, not fingerprints: anyone can make a
key with a given pseudonym. `known` tells whether the key is a stored peer,
and `mode` is `strict` or `quick`. `name_mismatch` flags a stored peer whose
claimed name is not its stored name, and `name_conflict` a peer that claims,
or is stored under, the name of another stored peer; names that differ only in
case, white space or characters that do not show count as the same. Warn the
user about either.

A peer that connects to the server again while a prompt for its key from an
earlier connection is open, as after it gave up or its connection dropped,
gets a new `verify_peer`, which replaces the earlier one: the earlier
`request_id` is no longer pending, so `verify_response` fails for it with
`verification_not_found`, and the earlier handshake ends. A client should
show one prompt per `peer_key`, the latest. The kamune library does not tell
the daemon when the connection of a prompt goes away, so a prompt can
outlive its connection; accepting it then admits nobody. An unknown peer
that connects is rejected at once, without this event, while 8 other unknown
peers that connected have prompts open. Known peers do not count toward the
8, and a peer the user dials (`dial` or a reconnect) is never rejected this
way and replaces no prompt. While prompts are open the status is `verifying`;
when the last one ends, the status before them comes back.

```json
{
  "type": "evt",
  "evt": "verify_peer",
  "data": {
    "request_id": 42,
    "peer_name": "Unknown peer 12345 67890",
    "claimed_name": "CrimsonOtter",
    "peer_key": "MCowBQYDK2VwAyEAXd...",
    "numeric": "12345 67890 13579 24680 11223 34455 66778 89900",
    "emoji": ["🦊", "🐱", "🌵", "🔑", "🚀", "🍀", "🎲", "🐙"],
    "hex": "30:2A:30:05:06:03:2B:65:70:03:21:00:5D:...",
    "known": false,
    "name_mismatch": false,
    "name_conflict": false,
    "mode": "quick"
  }
}
```

### `relay_tokens`

Emitted with the whole list whenever the relay token list of a relay server
changes: a token is registered (at start, by `generate_relay_token` or
`get_share_info`, or as a reconnect listener), consumed, removed, expired or
cut off from the relay. The token fields are those of
[`list_relay_tokens`](#list_relay_tokens).

```json
{
  "type": "evt",
  "evt": "relay_tokens",
  "data": {
    "tokens": [
      {
        "token": "deadbeef...",
        "consumed": false,
        "ttl_ns": 600000000000,
        "session_ttl_ns": 300000000000,
        "expires_at": "2026-06-21T11:00:00Z",
        "mode": "random"
      }
    ]
  }
}
```

### `p2p_tokens`

Emitted when a p2p server starts, when a token is added or removed, each time
the server refreshes its tokens' broker registrations (every 30 seconds), and
with an empty list when the server stops. The token fields are those of
[`list_p2p_tokens`](#list_p2p_tokens).

```json
{
  "type": "evt",
  "evt": "p2p_tokens",
  "data": {
    "tokens": [
      {
        "token": "4f1c2a9be07d35a8c6e19b0f72d4a3e5",
        "consumed": false,
        "ttl_ns": 60000000000,
        "expires_at": "2026-06-21T11:00:00Z",
        "mode": "random"
      }
    ]
  }
}
```

### `log_entry`

Emitted for each log entry added to the in-memory buffer. The same entries are
returned by `get_logs`.

```json
{
  "type": "evt",
  "evt": "log_entry",
  "data": {
    "timestamp": "2026-06-21T10:30:00Z",
    "level": "INFO",
    "message": "[cmd/daemon] Server started"
  }
}
```

### `error`

Emitted when a command fails or an internal error occurs. Correlated by command
`id` when applicable. `error` is a message for people, `code` a stable code for
programs, and `reason`, on some errors, tells apart failures that share a code:
`storage_open_failed` carries `wrong_passphrase`, `passphrase_required`,
`corrupt_metadata`, `insecure_permissions`, `unsupported_format`, `in_use`,
`upgrade_failed` or `compact_failed` (see [`open_storage`](#open_storage)), and `send_message_failed` carries
`connection_lost` or `message_too_large` (see
[`send_message`](#send_message)).

```json
{
  "type": "evt",
  "evt": "error",
  "id": "1",
  "data": { "error": "storage not opened — call open_storage first", "code": "storage_not_opened" }
}
```

| Code                           | Commands                                                                                                              | Meaning                                                                                                                                  |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `addr_required`                | `start_server`, `dial`                                                                                                | A tcp or udp transport without `addr`.                                                                                                   |
| `broker_addr_mismatch`         | `generate_p2p_token`                                                                                                  | `broker_addr` is not the p2p server's broker.                                                                                            |
| `broker_client_failed`         | `start_server`, `dial`                                                                                                | The broker client could not be created (p2p).                                                                                            |
| `cancel_timeout`               | `cancel_start_server`                                                                                                 | The server start did not stop within 5 seconds.                                                                                          |
| `change_passphrase_failed`     | `change_passphrase`                                                                                                   | The change failed; the passphrase is unchanged.                                                                                          |
| `create_dialer_failed`         | `dial`                                                                                                                | The kamune dialer could not be created.                                                                                                  |
| `create_server_failed`         | `start_server`                                                                                                        | The listen address could not be bound, or the kamune server could not be created.                                                        |
| `data_base64_required`         | `send_message`                                                                                                        | `data_base64` is empty.                                                                                                                  |
| `delete_failed`                | `delete_history_session`                                                                                              | The session could not be deleted.                                                                                                        |
| `detect_ip_failed`             | `get_share_info`                                                                                                      | The server listens on every interface and the host has no non-loopback IPv4 address.                                                     |
| `dial_failed`                  | `dial`                                                                                                                | The connection or the kamune handshake failed, or the peer was rejected.                                                                 |
| `direct_p2p_failed`            | `start_server`, `dial`                                                                                                | The direct-p2p socket could not be set up.                                                                                               |
| `export_file_failed`           | `export_logs`                                                                                                         | The file could not be created or put in place.                                                                                           |
| `export_write_failed`          | `export_logs`                                                                                                         | The entries could not be written.                                                                                                        |
| `goroutine_panic`              | `dial`, `send_message`                                                                                                | The dial or the send panicked.                                                                                                           |
| `hole_punch_failed`            | `dial`                                                                                                                | No packet could be sent to the matched p2p server.                                                                                       |
| `history_fetch_failed`         | `get_history_messages`                                                                                                | The messages could not be read.                                                                                                          |
| `history_not_found`            | `load_history`                                                                                                        | The session is not in the history list.                                                                                                  |
| `history_not_loaded`           | `get_history_messages`                                                                                                | `load_history` was not called for the session.                                                                                           |
| `identity_unavailable`         | `start_server`, `dial`                                                                                                | The identity key could not be read.                                                                                                      |
| `invalid_base64`               | `send_message`                                                                                                        | `data_base64` is not standard base64.                                                                                                    |
| `invalid_fingerprint_format`   | `set_fingerprint_format`                                                                                              | Not one of the formats.                                                                                                                  |
| `invalid_json`                 | any line                                                                                                              | The line is not a JSON object. Has no `id`.                                                                                              |
| `invalid_log_level`            | `set_log_level`                                                                                                       | Not one of the levels.                                                                                                                   |
| `invalid_name`                 | `start_server`, `dial`, `set_my_name`, `add_peer`, `rename_peer`, `rename_session`                                    | The name breaks the name rules (see `start_server`).                                                                                     |
| `invalid_p2p_token`            | `dial`                                                                                                                | `p2p_token` is not 32 or 64 hex characters.                                                                                              |
| `invalid_params`               | every command with params                                                                                             | `params` is absent or does not decode into the command's params.                                                                         |
| `invalid_peer_key`             | `add_peer`, `rename_peer`, `get_peer`, `delete_peer`, `generate_relay_token`, `dial`                                  | The public key does not decode, has the wrong length, or (for `add_peer`, `generate_relay_token` and `dial`) is not a valid Ed25519 key. |
| `invalid_relay_pin`            | `start_server`, `dial`                                                                                                | `relay_pin` is not a SHA-256 fingerprint, is for a `ws` or `tcp` relay, or comes with `?insecure=true`.                                  |
| `invalid_transport`            | `start_server`, `dial`                                                                                                | An unknown transport.                                                                                                                    |
| `invalid_verification_mode`    | `set_verification_mode`                                                                                               | A mode other than 0, 1 or 2.                                                                                                             |
| `keychain_clear_failed`        | `clear_keychain_passphrase`                                                                                           | The keychain entry could not be removed, or there is none.                                                                               |
| `line_too_long`                | any line                                                                                                              | The line is over 1 MiB and was dropped. Has no `id`.                                                                                     |
| `listener_failed`              | `start_server`, `generate_relay_token`, `get_share_info`                                                              | A relay listener could not be added to the server.                                                                                       |
| `marshal_failed`               | `get_session_info`                                                                                                    | The session info could not be encoded.                                                                                                   |
| `name_persist_failed`          | `set_my_name`                                                                                                         | The name could not be saved.                                                                                                             |
| `name_too_long`                | `set_my_name`                                                                                                         | The name is over 32 bytes.                                                                                                               |
| `p2p_listener_failed`          | `start_server`                                                                                                        | The p2p punch socket could not be set up or registered with the broker.                                                                  |
| `p2p_match_failed`             | `dial`                                                                                                                | The broker did not match the token within 30 seconds, or the wait failed.                                                                |
| `p2p_server_not_running`       | `generate_p2p_token`                                                                                                  | No p2p server runs.                                                                                                                      |
| `p2p_token_failed`             | `start_server`, `generate_p2p_token`                                                                                  | `broker_addr` is empty, or the P2P token could not be derived or registered.                                                             |
| `p2p_token_remove_failed`      | `remove_p2p_token`                                                                                                    | The token is not listed.                                                                                                                 |
| `passphrase_required`          | `submit_passphrase`, `change_passphrase`                                                                              | The passphrase, or `new_passphrase`, is empty.                                                                                           |
| `peer_already_exists`          | `add_peer`                                                                                                            | The key is already a known peer.                                                                                                         |
| `peer_delete_failed`           | `delete_peer`                                                                                                         | The peer could not be deleted.                                                                                                           |
| `peer_key_mismatch`            | `dial`                                                                                                                | The peer's key is not `peer_pub_b64`.                                                                                                    |
| `peer_list_failed`             | `list_peers`                                                                                                          | The peers could not be read.                                                                                                             |
| `peer_not_found`               | `rename_peer`, `get_peer`                                                                                             | The key is not a known peer.                                                                                                             |
| `peer_store_failed`            | `add_peer`, `rename_peer`                                                                                             | The peer could not be saved.                                                                                                             |
| `relay_dial_failed`            | `dial`                                                                                                                | The relay dial could not be prepared, for example without `relay_addr` or `token`.                                                       |
| `relay_link_lost`              | none                                                                                                                  | A relay token lost its link to the relay and was removed. Has no `id`.                                                                   |
| `relay_listen_failed`          | `start_server`, `generate_relay_token`                                                                                | Registering with the relay failed or took over 15 seconds.                                                                               |
| `relay_not_configured`         | `generate_relay_token`                                                                                                | No relay server runs.                                                                                                                    |
| `relay_token_failed`           | `generate_relay_token`, `get_share_info`                                                                              | The static token could not be derived, or the card's token could not be registered.                                                      |
| `rename_failed`                | `rename_history_session`                                                                                              | The name could not be saved.                                                                                                             |
| `send_message_failed`          | `send_message`                                                                                                        | The send failed; see its `reason`.                                                                                                       |
| `server_already_running`       | `start_server`                                                                                                        | A server runs.                                                                                                                           |
| `server_already_started`       | `cancel_start_server`                                                                                                 | The start finished before the cancel.                                                                                                    |
| `server_not_running`           | `get_share_info`                                                                                                      | No server runs.                                                                                                                          |
| `server_not_started`           | `restart_server`                                                                                                      | No `start_server` has passed its checks.                                                                                                 |
| `server_start_in_progress`     | `start_server`                                                                                                        | Another start is under way.                                                                                                              |
| `server_start_not_in_progress` | `cancel_start_server`                                                                                                 | No start is under way.                                                                                                                   |
| `server_stopped`               | `generate_relay_token`, `get_share_info`                                                                              | The relay server stopped or restarted meanwhile.                                                                                         |
| `session_active`               | `delete_history_session`                                                                                              | The session is live.                                                                                                                     |
| `session_id_required`          | `send_message`                                                                                                        | `session_id` is empty.                                                                                                                   |
| `session_not_found`            | `close_session`, `rename_session`, `send_message`, `get_session_info`                                                 | No such session.                                                                                                                         |
| `storage_busy`                 | `open_storage`, `submit_passphrase`, `change_passphrase`                                                              | A server runs, a server start or a dial is under way, or a session is open.                                                              |
| `storage_not_opened`           | `start_server`, `dial`, `submit_passphrase`, `change_passphrase`                                                      | No storage is open, nor a path for `submit_passphrase`.                                                                                  |
| `storage_open_failed`          | `open_storage`, `submit_passphrase`                                                                                   | The storage did not open; see its `reason`.                                                                                              |
| `storage_path_required`        | `open_storage`                                                                                                        | `storage_path` is empty.                                                                                                                 |
| `storage_reopen_failed`        | `change_passphrase`                                                                                                   | The new passphrase is in effect, but the storage could not be opened again.                                                              |
| `storage_unavailable`          | `start_server`, `dial`, the peer commands, `get_history_messages`, `rename_history_session`, `delete_history_session` | No storage is open.                                                                                                                      |
| `token_not_found`              | `remove_relay_token`                                                                                                  | The token is not listed.                                                                                                                 |
| `unknown_command`              | any line                                                                                                              | An unknown `cmd`.                                                                                                                        |
| `unknown_message_type`         | any line                                                                                                              | A `type` other than `"cmd"`.                                                                                                             |
| `unknown_transport`            | `get_share_info`                                                                                                      | The server's transport has no share card.                                                                                                |
| `verification_not_found`       | `verify_response`                                                                                                     | No prompt with that `request_id` is pending.                                                                                             |
| `wrong_passphrase`             | `change_passphrase`                                                                                                   | `old_passphrase` does not open the storage.                                                                                              |

## Storage Model

The daemon holds a single shared storage instance opened by `open_storage` (or
by `submit_passphrase`). The same storage is used for:

- **Local identity**: the Ed25519 key pair, loaded on `open_storage` and
  created there when the storage has none.
- **Chat history**: `AddChatEntry` on every send and receive, except in
  incognito mode.
- **Known peers**: `FindPeer` on verify. `StorePeer` stores an unknown peer
  that the user accepted in Strict or Quick mode once its session is
  established, except in incognito mode, and `add_peer` stores one by hand.
- **Settings**: `SetSettings`/`GetSettings` under the `"daemon"` namespace,
  saved by the commands that change them while a storage is open, and applied
  when the storage is opened:
  - `verification_mode` (`"0"`, `"1"` or `"2"`)
  - `local_name` (string)
  - `incognito` (`"true"` or `"false"`)
  - `log_level` (`"DEBUG"`, `"INFO"`, `"WARN"`, `"WARNING"` or `"ERROR"`)
  - `fingerprint_format` (`"hex"`, `"emoji"`, `"b64"`, `"sum"` or `"numeric"`)

Calling `open_storage` or `submit_passphrase` while a storage is open opens the
new one first and closes the old one once that succeeds. For the path that is
already open, the open storage is closed first and opened again if the new
open fails.

### Passphrase Sources

| Scenario                                                       | Behavior                                                                                                                                                                                                           |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `db_no_passphrase: true`                                       | Opens with `WithNoPassphrase()`.                                                                                                                                                                                   |
| `db_no_passphrase: false` + `KAMUNE_DB_PASSPHRASE` env var set | Opens with the env var value, which is never saved to the keychain.                                                                                                                                                |
| `db_no_passphrase: false` + env var empty                      | Fails with `storage_open_failed`, reason `passphrase_required`. The path is kept for `submit_passphrase`.                                                                                                          |
| `submit_passphrase`                                            | Opens the path of the last `open_storage` when that failed, with `db_no_passphrase` or without, or else the open storage's path, with the given passphrase; saves it to the keychain only with `save_to_keychain`. |
| `change_passphrase`                                            | Re-encrypts the open storage under a new passphrase.                                                                                                                                                               |
| System keychain                                                | Never read to open a storage.                                                                                                                                                                                      |

## Verification Flow

The daemon supports three peer verification modes. The mode is saved in the
storage settings under `daemon/verification_mode`, applied when the storage is
opened, and can be changed at runtime with `set_verification_mode`; each peer
is verified in the mode in effect at the time. Without a saved mode the
daemon uses Quick, or the mode that the client set before it opened the
first storage. A saved value that names no mode means Strict, and a warning
is logged.

```
                  ┌─────────────────────────────────────────────────────────┐
                  │ A peer connects to the server, or the user dials one    │
                  │ (cold handshake; a resumed session skips all this)      │
                  └────────────────────────────┬────────────────────────────┘
                                               │
                  ┌────────────────────────────▼────────────────────────────┐
                  │ Mode = Auto-Accept?                                     │
                  │ → accept; the peer is not stored                        │
                  └────────────────────────────┬────────────────────────────┘
                                               │ no
                  ┌────────────────────────────▼────────────────────────────┐
                  │ Mode = Quick and the peer is known?                     │
                  │ → accept                                                │
                  └────────────────────────────┬────────────────────────────┘
                                               │ no
                  ┌────────────────────────────▼────────────────────────────┐
                  │ Unknown inbound peer while 8 other unknown inbound      │
                  │ peers have prompts open?                                │
                  │ → reject without a prompt                               │
                  │ Inbound peer whose key has a prompt open?               │
                  │ → end that prompt; this connection is asked instead     │
                  └────────────────────────────┬────────────────────────────┘
                                               │ no
                  ┌────────────────────────────▼────────────────────────────┐
                  │ Emit verify_peer (request_id)                           │
                  │ Wait for verify_response or the 2-minute timeout        │
                  └────────────────────────────┬────────────────────────────┘
                                               │
                  ┌────────────────────────────▼────────────────────────────┐
                  │ accept  → continue; an unknown peer is stored once      │
                  │           its session is established (not in incognito) │
                  │ reject  → kamune.ErrVerificationFailed                  │
                  │ timeout → error, but the status is not set to error     │
                  └─────────────────────────────────────────────────────────┘
```

The verifier runs only on a cold handshake. The kamune library does not run it
when a peer resumes a session
([SPEC §6.8.4](SPEC.md#684-resumption-asymmetry)), which it allows within 24
hours of the session's cold handshake (a resume does not extend that). So in
every mode, Strict included, a peer that resumes a session is not prompted,
and the daemon resumes dropped dialed sessions on its own.

The daemon does not turn resumption off in Strict mode, although SPEC §6.8.4
recommends that for a verifier that must run on every connection: Strict mode
prompts on every cold handshake, not on every connection. A session can be
resumed only while its peer is a stored peer and the session has resumption
tokens left, so a session with an unknown peer that Auto-Accept mode let in,
without storing it, is never resumed. To keep a peer from resuming without a
prompt:

- `close_session` ends a live session for good;
- `delete_history_session` deletes a session that is not live, and its
  resumption tokens with it;
- `delete_peer` keeps every session with the peer from being resumed, until
  the peer is stored again;
- a server started in incognito mode refuses resumption.

A prompt that waits for the user holds the handshake open. The kamune library
allows the verifier 150 seconds, so the daemon's 2-minute timeout ends the
prompt first. `stop_server` and `restart_server` reject the open prompts of
peers that connected to the server.

`request_id` is distinct from the command `id` correlation field because
verification is triggered by the protocol, not by a client command. Match
`verify_response.request_id` to the `request_id` in the `verify_peer` event.

## Connection Drops

The daemon reads the messages of each live session until the kamune library
returns an error, and the error decides what becomes of the session:

- `ErrPeerDisconnected`: the peer closed the session with a close frame. The
  session ends with `session_closed` and is not resumed.
- `ErrConnClosed`: the connection dropped. The peer or the network closed or
  reset it, it broke off in the middle of a frame, or the daemon closed it
  after missed keepalives. A dialed session tries to resume, except for p2p
  and incognito sessions (see [`session_reconnecting`](#session_reconnecting)),
  and ends with `session_closed` when it cannot. A session on the server ends
  with `session_closed`, and its peer may resume it (see
  [Verification Flow](#verification-flow)): the resumed session is reported
  with a new `session_started` for the same `session_id`, without
  `verify_peer`. For a session that came through the relay, the server
  registers a reconnect listener for the peer to resume through (see
  [`list_relay_tokens`](#list_relay_tokens)).
- Any other error, such as a message that fails decryption or its signature
  check, comes out of sequence or carries a route that is not allowed at that
  point: the kamune library closes the connection and deletes the session's
  resumption tokens, and the session ends with `session_closed`. The peer sees
  the connection drop, and an attempt to resume the session fails. After an
  error that leaves the connection open, such as a message with an unknown
  route, the daemon closes a dialed session with a close frame, which deletes
  its tokens too, while a session on the server has its connection closed
  without one, so that its peer sees a dropped connection.

The daemon pings the peer of each live session every 30 seconds. When 3 pings
in a row cannot be sent or get no answer within 10 seconds, it closes the
connection without a close frame, which keeps the session resumable, and the
session goes on as after any dropped connection.

The kamune library waits at most 5 seconds for a close frame to go out. When
the peer's close frame does not get through in that time, the daemon sees a
dropped connection, and the session cannot be resumed, since the peer deleted
its resumption tokens when it closed the session.

## Transports

| Transport       | Server-side                                                                     | Client-side                                               |
| --------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `tcp` (default) | `net.Listen("tcp")` + `ServeWithListener`                                       | `kamune.DialWithTCP`                                      |
| `udp`           | `kcp.Listen` + `ServeWithListener`                                              | `kamune.DialWithUDP`                                      |
| `relay`         | `relayconn.ListenRelay*` + `ServeWithListener(multiListener)`                   | `relayconn.DialRelay*` via `DialWithFunc`                 |
| `p2p`           | `newP2PListener` (punch socket, broker registration, KCP) + `ServeWithListener` | `BrokerClient.WaitMatch` + `HolePunch` via `DialWithFunc` |
| `direct-p2p`    | `newDirectP2PListener` + `ServeWithListener`                                    | `directP2PDial` via `DialWithFunc`                        |

For relay mode, the relay address supports `tcp://`, `ws://`, `wss://`, and
`tls://` schemes, and is `wss://` when it names none, so a relay without TLS
must be named with `ws://` or `tcp://`. The certificate of a `wss` or `tls`
relay is verified against the system's roots and the relay's host name, so a
relay that uses its own self-signed certificate is refused unless `relay_pin`
pins that certificate. The pin is the `sha256` value of the
`tls certificate` line that the relay logs for each TLS listener at startup.
It takes the place of those checks, so it must be updated whenever the relay's
certificate changes, for example when a certificate from an authority is
renewed. An optional `?insecure=true` query parameter turns off TLS
certificate verification instead. Over `ws://`, `tcp://` or `?insecure=true`
an on-path attacker can pose as the relay and read the relay password and
tokens, and the daemon logs a warning. A PSK `password` can be supplied for
relays that require one.
