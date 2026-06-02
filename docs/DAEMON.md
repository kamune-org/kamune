# Daemon Protocol

The `cmd/daemon` module provides a JSON-over-stdio protocol for integrating
kamune with external applications (GUI, editor plugins, etc.).

## Wire Format

The daemon reads commands from stdin and writes events to stdout as
newline-delimited JSON. Logging goes to stderr.

## Commands

Each command is a JSON object with `type: "cmd"`:

| Command         | Description                                |
| --------------- | ------------------------------------------ |
| `start_server`  | Start a kamune server on the given address |
| `dial`          | Dial a remote kamune server                |
| `send_message`  | Send a message on an established session   |
| `list_sessions` | List all active sessions                   |
| `close_session` | Close a specific session                   |
| `shutdown`      | Gracefully shut down the daemon            |

**Command Structure:**

```json
{"type": "cmd", "cmd": "start_server", "id": "req-1", "params": {"addr": "127.0.0.1:9000"}}
{"type": "cmd", "cmd": "dial", "id": "req-2", "params": {"addr": "192.168.1.10:9000"}}
{"type": "cmd", "cmd": "send_message", "id": "req-3", "params": {"session_id": "abc", "data_base64": "SGVsbG8="}}
{"type": "cmd", "cmd": "shutdown", "id": "req-4", "params": {}}
```

**`start_server` and `dial` parameters:**

```json
{
  "addr": "127.0.0.1:9000",
  "storage_path": "/path/to/db",
  "db_no_passphrase": true
}
```

When `db_no_passphrase` is true, the database is opened with an empty
passphrase (equivalent to `WithNoPassphrase()`).

## Events

| Event              | Trigger                                         |
| ------------------ | ----------------------------------------------- |
| `ready`            | Daemon initialized and listening                |
| `server_started`   | Server started successfully                     |
| `session_started`  | New session established                         |
| `session_closed`   | Session closed                                  |
| `message_received` | Message received on a session                   |
| `message_sent`     | Message sent successfully                       |
| `error`            | An error occurred                               |
| `response`         | Response to a command (list_sessions, shutdown) |

**Event Structure:**

```json
{"type": "evt", "evt": "ready", "data": {"version": "1.0.0", "pid": "12345"}}
{"type": "evt", "evt": "server_started", "id": "req-1", "data": {"addr": "127.0.0.1:9000", "public_key": "base64...", "emoji": ["..."]}}
{"type": "evt", "evt": "session_started", "data": {"session_id": "abc123", "is_server": true}}
{"type": "evt", "evt": "message_received", "data": {"session_id": "abc123", "data_base64": "SGVsbG8=", "timestamp": "2024-01-15T10:30:00Z"}}
{"type": "evt", "evt": "error", "id": "req-2", "data": {"error": "connection refused"}}
```

## Storage Caching

The daemon caches storage instances by path and `no_passphrase` flag,
reopening existing ones when the same storage path is reused across commands.

## Session Lifecycle

- Sessions are tracked in memory by session ID.
- `server_handler` runs in a goroutine and auto-closes when the transport ends.
- Dialed sessions also run in goroutines.
- `close_session` cancels the session context and closes the transport.
- `shutdown` closes the server listener, all sessions, then waits for all
  goroutines to finish before emitting a response and closing stdin.
