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

| Field    | Type   | Description                                                          |
| -------- | ------ | -------------------------------------------------------------------- |
| `type`   | string | Always `"cmd"` for commands.                                         |
| `cmd`    | string | The command name (see [Commands](#commands)).                        |
| `id`     | string | Unique correlation ID. The daemon echoes this on the response event. |
| `params` | object | Command-specific parameters (`{}` for commands with none).           |

### Event Envelope (Daemon → Client)

```json
{
  "type": "evt",
  "evt": "<event_name>",
  "id": "<correlation_id>",
  "data": { ... }
}
```

| Field  | Type   | Description                                                                                                             |
| ------ | ------ | ----------------------------------------------------------------------------------------------------------------------- |
| `type` | string | Always `"evt"` for events.                                                                                              |
| `evt`  | string | The event name (see [Commands](#commands) and [Push Events](#push-events)).                                             |
| `id`   | string | Optional correlation ID. Present for command responses (`<command>-id`) and for events triggered by a specific command. |
| `data` | object | Event-specific payload.                                                                                                 |

Every command in the [Commands](#commands) section below shows the exact
JSON it expects on stdin and the exact JSON it emits on stdout. You don't
need to read any other section to use a command.

## Commands

All 49 commands, grouped by category. Each block shows the **exact JSON**
to send and the **exact JSON** to expect back.

### `SessionInfo` Shape

Several events return a full `SessionInfo` object. Its shape:

```json
{
  "session_id": "abc123def456...",
  "peer_name": "CrimsonOtter",
  "is_server": true,
  "msg_count": 3,
  "last_activity": "2026-06-21T10:30:00Z",
  "transport_type": "tcp",
  "remote_version": "0.5.0",
  "session_ttl_ns": 3600000000000,
  "session_started_at": "2026-06-21T10:25:00Z",
  "remote_addr": "192.168.1.10:9000"
}
```

### Storage

#### `open_storage`

Opens the single shared storage. Must be called before any command that
requires storage.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "open_storage",
  "id": "1",
  "params": { "storage_path": "/tmp/kamune.db", "db_no_passphrase": true }
}
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": { "status": "opened", "storage_path": "/tmp/kamune.db" }
}
```

If an identity already exists in the storage, also emits:

```json
{ "type": "evt", "evt": "fingerprint_changed", "data": { "emoji": "🦊 • 🐱", "b64": "base64key...", "hex": "ab12cd34...", "sum": "ab12cd34" } }
{ "type": "evt", "evt": "local_name_changed", "data": { "name": "CrimsonOtter" } }
{ "type": "evt", "evt": "history_updated", "data": {} }
```

#### `submit_passphrase`

Re-opens the previously-opened storage path with a new passphrase. Requires
a prior `open_storage` call.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "submit_passphrase",
  "id": "1",
  "params": { "passphrase": "correct horse battery staple" }
}
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "opened" } }
```

### Server Lifecycle

#### `start_server`

Starts a kamune server. `transport` is `"tcp"` (default), `"udp"`,
`"relay"`, `"p2p"`, or `"direct-p2p"`. When `"relay"`, `relay_addr` is
required (supports `tcp://`, `ws://`, `wss://`, `tls://` schemes;
`?insecure=true` overrides TLS verification). `name` defaults to
`fingerprint.Pseudonym(pubKey)`. When incognito mode is enabled, a pseudonym is
always used regardless of `name`.

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
    "broker_addr": "wss://broker.example.com",
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
{ "type": "evt", "evt": "fingerprint_changed", "data": { "emoji": "🦊 • 🐱", "b64": "base64key...", "hex": "ab12cd34...", "sum": "ab12cd34" } }
{ "type": "evt", "evt": "server_running", "data": { "running": true, "transport": "tcp" } }
{ "type": "evt", "evt": "server_started", "id": "1", "data": { "addr": "127.0.0.1:9000", "transport": "tcp", "name": "MyServer", "public_key": "base64key...", "emoji": ["🦊", "🐱"], "fingerprint_hex": "ab12cd34...", "fingerprint_sum": "ab12cd34" } }
{ "type": "evt", "evt": "status_changed", "data": { "status": "connected", "message": "Server running on 127.0.0.1:9000" } }
```

For relay transport, also emits:

```json
{ "type": "evt", "evt": "relay_token", "data": { "token": "deadbeef...", "ttl_ns": 600000000000, "session_ttl_ns": 300000000000, "expires_at": "2026-06-21T11:00:00Z" } }
{ "type": "evt", "evt": "relay_tokens", "data": { "tokens": [{ "token": "deadbeef...", "consumed": false, "ttl_ns": 600000000000, "session_ttl_ns": 300000000000, "expires_at": "2026-06-21T11:00:00Z" }] } }
```

#### `stop_server`

Stops the running server and all active sessions, without exiting the daemon.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "stop_server", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "status_changed", "data": { "status": "disconnected", "message": "Stopping server..." } }
{ "type": "evt", "evt": "server_stopped", "data": { "running": false } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "stopped" } }
```

#### `restart_server`

Stops the server and starts it again with the last used params. Useful after
`set_verification_mode` to apply the new mode to incoming connections.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "restart_server", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "server_stopped", "data": { "running": false } }
{ "type": "evt", "evt": "server_running", "data": { "running": false, "transport": "tcp" } }
{ "type": "evt", "evt": "server_running", "data": { "running": true, "transport": "tcp" } }
{ "type": "evt", "evt": "server_started", "id": "1", "data": { "addr": "127.0.0.1:9000", "transport": "tcp", "name": "MyServer", "public_key": "base64key...", "emoji": ["🦊", "🐱"], "fingerprint_hex": "ab12cd34...", "fingerprint_sum": "ab12cd34" } }
```

#### `cancel_start_server`

Cancels an in-flight server start.

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

Returns the current server state.

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

Connects to a remote kamune server. `transport` is `"tcp"` (default), `"udp"`,
`"relay"`, `"p2p"`, or `"direct-p2p"`. For relay, `token` is the hex-encoded
token from the server.

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
    "broker_addr": "wss://broker.example.com",
    "p2p_token": "hex-token-from-server",
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
    "is_server": false,
    "msg_count": 0,
    "transport_type": "tcp",
    "remote_version": "0.5.0",
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

If a new peer connects and the verification mode is Strict or Quick, you'll
also receive a `verify_peer` event (see [Push Events](#push-events)). If
the peer has a different minor version, also a `version_warning` event.
When the dial session ends, a `session_closed` event fires and the history
is refreshed (`history_updated`).

#### `close_session`

Closes a specific session.

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
{ "type": "evt", "evt": "session_closed", "data": { "session_id": "xyz789...", "peer_name": "CrimsonOtter", "is_server": false, "msg_count": 3, "transport_type": "tcp", "session_started_at": "2026-06-21T10:30:00Z", "remote_addr": "127.0.0.1:9000" } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "closed", "session_id": "xyz789..." } }
```

If this was the last active session, also emits
`status_changed` → `{ "status": "disconnected", "message": "Not connected" }`.

#### `rename_session`

Renames a live session in memory (does not persist to history).

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
        "is_server": false,
        "msg_count": 3,
        "last_activity": "2026-06-21T10:30:00Z",
        "transport_type": "tcp",
        "remote_version": "0.5.0",
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

Sends a message on an established session. When incognito mode is enabled, the
message is not persisted to chat history.

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
{ "type": "evt", "evt": "message_sent", "id": "1", "data": { "session_id": "xyz789...", "timestamp": "2026-06-21T10:30:00.123456789Z" } }
{ "type": "evt", "evt": "session_updated", "data": { "session_id": "xyz789..." } }
```

### Relay

#### `generate_relay_token`

Generates a new relay token for the running relay server. When `peer_pub_b64` is
set, derives a deterministic (static) token via ECDH — only that peer can
connect using it.

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
{ "type": "evt", "evt": "relay_tokens", "data": { "tokens": [{ "token": "cafebabe...", "consumed": false, "ttl_ns": 600000000000, "session_ttl_ns": 300000000000, "expires_at": "2026-06-21T11:00:00Z" }] } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "token": "cafebabe...", "ttl_ns": 600000000000, "session_ttl_ns": 300000000000, "expires_at": "2026-06-21T11:00:00Z" } }
```

#### `remove_relay_token`

Removes an active relay token.

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

Returns all active relay tokens.

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
        "expires_at": "2026-06-21T11:00:00Z"
      }
    ]
  }
}
```

#### `get_share_info`

Generates a connection card. For `tcp`/`udp`, returns the local address
(auto-detected via `net.InterfaceAddrs` if bound to `""` or `"0.0.0.0"`).
For `relay`, generates a fresh token and includes `relay_info`.

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
    "fingerprint_emoji": "🦊 • 🐱",
    "fingerprint_hex": "ab12cd34...",
    "relay_info": null
  }
}
```

**Output (Relay):**

```json
{ "type": "evt", "evt": "relay_tokens", "data": { "tokens": [{ "token": "freshbeef...", "consumed": false, "ttl_ns": 600000000000, "session_ttl_ns": 300000000000, "expires_at": "2026-06-21T11:00:00Z" }] } }
{ "type": "evt", "evt": "response", "id": "1", "data": { "url": "relay://relay.example.com:8443?token=freshbeef...&scheme=wss", "transport": "relay", "address": "", "port": "", "fingerprint_emoji": "🦊 • 🐱", "fingerprint_hex": "ab12cd34...", "relay_info": { "address": "relay.example.com:8443", "scheme": "wss", "token": "freshbeef...", "password": false } } }
```

### P2P Tokens

#### `generate_p2p_token`

Generates a new P2P token for broker-based hole-punching. When `peer_pub_b64` is
set, the token is derived via ECDH so only that peer can match.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "generate_p2p_token",
  "id": "1",
  "params": {
    "broker_addr": "wss://broker.example.com",
    "peer_pub_b64": "base64key..."
  }
}
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": {
    "token": "hex-token...",
    "broker_addr": "wss://broker.example.com",
    "peer_pub_b64": "base64key..."
  }
}
```

#### `remove_p2p_token`

Removes an active P2P token.

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
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "removed" } }
```

#### `list_p2p_tokens`

Returns all active P2P tokens.

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
        "token": "hex-token...",
        "nonce": "base64...",
        "pub": "base64...",
        "peer": "base64...",
        "broker_addr": "wss://broker.example.com",
        "expires_at": "2026-06-21T11:00:00Z"
      }
    ]
  }
}
```

### Connections (continued)

#### `get_session_info`

Returns info for a single session, either live or from history. Returns `null`
if the session ID is not found.

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
    "is_server": false,
    "msg_count": 3,
    "last_activity": "2026-06-21T10:30:00Z",
    "transport_type": "tcp",
    "remote_version": "0.5.0",
    "session_ttl_ns": 3600000000000,
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
    "message_count": 15,
    "first_message": "2026-06-20T09:00:00Z",
    "last_message": "2026-06-20T10:30:00Z"
  }
}
```

### Verification

Modes: `0` = Strict (always prompt), `1` = Quick (auto-accept known peers,
prompt for new), `2` = Auto-Accept (accept all). See
[Verification Flow](#verification-flow).

#### `set_verification_mode`

Sets the verification mode and persists it. If a server is running, it
is auto-restarted to apply the new mode to incoming connections.

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

If a server was running, also emits `server_stopped` + `server_started` (the
`restart_server` flow).

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

Answers a pending `verify_peer` event (see [Push Events](#push-events)).

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

- A pseudonym is used instead of the display name for new connections
- New messages are not saved to disk
- Session history is not recorded
- Accepted peers are not stored

Existing session history and peers remain accessible. The incognito flag is
persisted in storage and restored on startup.

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

Enables or disables incognito mode. Persisted to storage.

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

Returns the list of past chat sessions.

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

Marks a history session as loaded so its messages can be retrieved.

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

Returns messages for a loaded history session.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "get_history_messages",
  "id": "1",
  "params": { "session_id": "abc123..." }
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
        "timestamp": "2026-06-20T09:00:00Z",
        "is_local": true
      }
    ]
  }
}
```

#### `rename_history_session`

Persists a new name for a history session.

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

Deletes a history session and all its messages.

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

Returns all known peers.

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
pseudonym.

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

Updates the display name of a known peer.

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

Returns a single known peer by base64 public key.

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

Removes a known peer.

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
`log_entry` push event (see [Push Events](#log_entry)).

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

Writes buffered logs to a file. `file_path` is optional — defaults to
`kamune-logs-<timestamp>.txt` in the current directory.

**Input:**

```json
{
  "type": "cmd",
  "cmd": "export_logs",
  "id": "1",
  "params": { "file_path": "/tmp/kamune-logs.txt" }
}
```

**Output:**

```json
{
  "type": "evt",
  "evt": "response",
  "id": "1",
  "data": { "status": "exported", "file_path": "/tmp/kamune-logs.txt" }
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

Sets the log level. Persisted to storage. Accepted values: `"DEBUG"`, `"INFO"`,
`"WARN"`, `"ERROR"`.

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
  "data": { "status": "ok", "level": "DEBUG" }
}
```

### Keychain

The daemon can save and retrieve the storage passphrase from the system keychain
(macOS Keychain, Linux Secret Service, Windows Credential Manager).

#### `has_keychain_passphrase`

Returns whether a passphrase is stored in the system keychain for the current
database path.

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

Removes the stored passphrase from the system keychain.

**Input:** (no params)

```json
{ "type": "cmd", "cmd": "clear_keychain_passphrase", "id": "1", "params": {} }
```

**Output:**

```json
{ "type": "evt", "evt": "response", "id": "1", "data": { "status": "cleared" } }
```

### Fingerprint Format

The daemon can display fingerprints in different formats. Default is `"hex"`.
Format is stored in memory only (not persisted).

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

Sets the fingerprint display format.

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
  "data": { "status": "ok", "format": "emoji" }
}
```

### Identity

#### `get_fingerprint`

Returns the current identity fingerprint. Empty strings if no key exists.

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
    "emoji": "🦊 • 🐱",
    "b64": "base64key...",
    "hex": "ab12cd34...",
    "sum": "ab12cd34"
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

Sets the local display name (max 32 characters). Persisted to storage.

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

Returns the daemon version.

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

Gracefully shuts down the daemon. Closes storage, server, and all sessions
before exiting.

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

### `ready`

Emitted once on daemon startup.

```json
{
  "type": "evt",
  "evt": "ready",
  "data": { "version": "1.0.0", "pid": "12345" }
}
```

### `status_changed`

Emitted when the connection status changes (`disconnected`, `connecting`,
`connected`, `verifying`, `error`).

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

Emitted when the identity fingerprint is loaded or changes.

```json
{
  "type": "evt",
  "evt": "fingerprint_changed",
  "data": {
    "emoji": "🦊 • 🐱",
    "b64": "base64key...",
    "hex": "ab12cd34...",
    "sum": "ab12cd34"
  }
}
```

### `local_name_changed`

Emitted when the local display name changes.

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
    "is_server": true,
    "msg_count": 0,
    "transport_type": "tcp",
    "remote_version": "0.5.0",
    "session_ttl_ns": 0,
    "session_started_at": "2026-06-21T10:30:00Z"
  }
}
```

### `session_closed` (peer disconnect)

Emitted when a session ends (not from `close_session`). The `session_closed`
from `close_session` is documented in [Commands](#connections).

```json
{
  "type": "evt",
  "evt": "session_closed",
  "data": {
    "session_id": "abc123...",
    "peer_name": "CrimsonOtter",
    "is_server": false,
    "msg_count": 3,
    "transport_type": "tcp",
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

```json
{
  "type": "evt",
  "evt": "message_received",
  "data": {
    "session_id": "abc123...",
    "data_base64": "SGVsbG8sIFdvcmxkIQ==",
    "timestamp": "2026-06-21T10:30:00.123456789Z"
  }
}
{
  "type": "evt",
  "evt": "session_updated",
  "data": { "session_id": "abc123..." }
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

Emitted when a new peer needs verification (Strict or Quick mode). The client
must respond with a `verify_response` command within 2 minutes.

```json
{
  "type": "evt",
  "evt": "verify_peer",
  "data": {
    "request_id": 42,
    "peer_name": "CrimsonOtter",
    "emoji": ["🦊", "🐱"],
    "hex": "ab12cd34...",
    "known": false,
    "mode": "quick"
  }
}
```

### `relay_tokens`

Emitted when the relay token list changes (token generated, consumed, or
removed).

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
        "expires_at": "2026-06-21T11:00:00Z"
      }
    ]
  }
}
```

### `p2p_tokens`

Emitted when the P2P token list changes (token generated or removed).

```json
{
  "type": "evt",
  "evt": "p2p_tokens",
  "data": {
    "tokens": [
      {
        "token": "hex-token...",
        "nonce": "base64...",
        "pub": "base64...",
        "peer": "base64...",
        "broker_addr": "wss://broker.example.com",
        "expires_at": "2026-06-21T11:00:00Z"
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
`id` when applicable.

```json
{
  "type": "evt",
  "evt": "error",
  "id": "1",
  "data": { "error": "storage not opened — call open_storage first" }
}
```

## Storage Model

The daemon holds a single shared storage instance opened by `open_storage` (or
re-opened by `submit_passphrase`). The same storage is used for:

- **Local identity** — Ed25519 keypair, loaded on `open_storage` as `pubKey`.
- **Chat history** — `AddChatEntry` on every send and receive.
- **Known peers** — `StorePeer` on accept, `FindPeer` on verify.
- **Settings** — `SetSettings`/`GetSettings` under the `"daemon"` namespace:
  - `verification_mode` (int: 0/1/2)
  - `local_name` (string)
  - `incognito` (bool: "true"/"false")
  - `log_level` (string: "DEBUG"/"INFO"/"WARN"/"ERROR")

Calling `open_storage` or `submit_passphrase` while a storage is already open
**closes the previous instance first**.

### Passphrase Sources

| Scenario                                                       | Behavior                                                                                                         |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `db_no_passphrase: true`                                       | Opens with `WithNoPassphrase()`.                                                                                 |
| `db_no_passphrase: false` + `KAMUNE_DB_PASSPHRASE` env var set | Opens with the env var value.                                                                                    |
| `db_no_passphrase: false` + env var empty                      | Fails with `"KAMUNE_DB_PASSPHRASE not set and db_no_passphrase is false; use submit_passphrase to provide one"`. |
| `submit_passphrase`                                            | Re-opens the previously-opened path with a new passphrase. Requires a prior `open_storage` call.                 |

## Verification Flow

The daemon supports three peer verification modes. The mode is persisted in
storage settings under `daemon/verification_mode` and can be changed at runtime
via `set_verification_mode`.

```
                  ┌──────────────────────────────────────────┐
                  │  Peer connects (server or dial)          │
                  └──────────────────┬───────────────────────┘
                                     │
                  ┌──────────────────▼───────────────────────┐
                  │  Mode = Auto-Accept?                     │
                  │  → accept, store peer (if new), continue │
                  └──────────────────┬───────────────────────┘
                                     │ no
                  ┌──────────────────▼───────────────────────┐
                  │  Mode = Quick? + peer known?             │
                  │  → accept, continue                      │
                  └──────────────────┬───────────────────────┘
                                     │ no
                  ┌──────────────────▼──────────────────────-─┐
                  │  Emit verify_peer event (request_id)      │
                  │  Wait for verify_response or 2-min timeout│
                  └──────────────────┬───────────────────────-┘
                                     │
                  ┌──────────────────▼─────────────────────-----──┐
                  │  accept → store peer (if new), continue       │
                  │  reject → return kamune.ErrVerificationFailed │
                  │  timeout → return generic timeout error       │
                  └──────────────────────────────────────────-----┘
```

`request_id` is distinct from the command `id` correlation field because
verification is triggered by the protocol, not by a client command. Match
`verify_response.request_id` to the `request_id` in the `verify_peer` event.

## Transports

| Transport       | Server-side                                                   | Client-side                                  |
| --------------- | ------------------------------------------------------------- | -------------------------------------------- |
| `tcp` (default) | `kamune.ServeWithTCP`                                         | `kamune.DialWithTCP`                         |
| `udp`           | `kamune.ServeWithUDP`                                         | `kamune.DialWithUDP`                         |
| `relay`         | `relayconn.ListenRelay*` + `ServeWithListener(multiListener)` | `relayconn.DialRelay*` via `DialWithFunc`    |
| `p2p`           | `broker.BrokerClient` + `newP2PListener` + `ServeWithUDP`     | `WaitMatch` + `HolePunch` via `DialWithFunc` |
| `direct-p2p`    | `newDirectP2PListener` + `ServeWithListener`                  | `directP2PDial` via `DialWithFunc`           |

For relay mode, the relay address supports `tcp://`, `ws://`, `wss://`, and
`tls://` schemes. An optional `?insecure=true` query parameter overrides TLS
certificate verification. A PSK `password` can be supplied for relays that
require one.
