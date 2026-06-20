# Kamune Daemon

A JSON-over-stdio protocol wrapper for the kamune secure messaging library.
Enables external applications (Tauri, Electron, editor plugins, scripts)
to use kamune's end-to-end encrypted communication through a simple
line-delimited JSON protocol.

The daemon exposes the same surface area as the `bus` GUI client:
TCP/UDP/relay transports, peer verification, chat history persistence,
relay token management, identity, and share info.

**For the complete protocol specification (commands, events, params,
storage model, verification flow, transports), see
[`docs/DAEMON.md`](../../docs/DAEMON.md).**

## Quick Example

**Terminal 1 — Server:**

```bash
./daemon <<EOF
{"type":"cmd","cmd":"open_storage","id":"1","params":{"storage_path":"./server.db","db_no_passphrase":true}}
{"type":"cmd","cmd":"start_server","id":"2","params":{"addr":"127.0.0.1:9000"}}
EOF
```

**Terminal 2 — Client:**

```bash
./daemon <<EOF
{"type":"cmd","cmd":"open_storage","id":"1","params":{"storage_path":"./client.db","db_no_passphrase":true}}
{"type":"cmd","cmd":"dial","id":"2","params":{"addr":"127.0.0.1:9000"}}
EOF
```

The client receives a `session_started` event (correlated by `"id": "2"`)
after the dial handshake. The `session_id` is in `evt.data.session_id`.

Then send a message:

```json
{
  "type": "cmd",
  "cmd": "send_message",
  "id": "3",
  "params": {
    "session_id": "<from-session_started>",
    "data_base64": "SGVsbG8="
  }
}
```

## Environment Variables

| Variable               | Description                                                                                                                                         |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `KAMUNE_DB_PATH`       | Override the default database path (`~/.config/kamune/db`). Used when the storage is opened with `storage.WithDBPath`.                              |
| `KAMUNE_DB_PASSPHRASE` | Passphrase for `open_storage` when `db_no_passphrase` is `false`. If empty, `open_storage` fails and directs the client to use `submit_passphrase`. |

## Testing

```bash
go test -short ./...          # unit tests only
go test -timeout 60s ./...    # full suite including end-to-end integration test
```

The integration test spawns the daemon as a subprocess and exercises the
full protocol: `open_storage` → `set_verification_mode` → `start_server` →
`dial` → `send_message` → `close_session` → `refresh_history` →
`get_history_sessions` → `shutdown`.

## Related

- [`docs/DAEMON.md`](../../docs/DAEMON.md) — full protocol specification
- [`cmd/bus/`](../bus/) — Wails GUI client (reference implementation)
- [`cmd/tui/`](../tui/) — Bubble Tea terminal client
