# Kamune Daemon

A JSON-over-stdio daemon wrapper for the kamune secure messaging library. This daemon enables external applications (like Tauri, Electron, or any other runtime) to leverage kamune's end-to-end encrypted communication through a simple line-delimited JSON protocol.

## Building

```bash
# Build for current platform
go build -o daemon ./cmd/daemon

# Cross-compile for different platforms
GOOS=darwin GOARCH=arm64 go build -o dist/daemon-darwin-arm64 ./cmd/daemon
GOOS=darwin GOARCH=amd64 go build -o dist/daemon-darwin-amd64 ./cmd/daemon
GOOS=linux GOARCH=amd64 go build -o dist/daemon-linux-amd64 ./cmd/daemon
GOOS=windows GOARCH=amd64 go build -o dist/daemon-windows-amd64.exe ./cmd/daemon
```

## Running

The daemon reads commands from stdin and emits events to stdout. Logs are written to stderr in JSON format.

```bash
./daemon
```

## Protocol Specification

The protocol uses line-delimited JSON (newline-delimited JSON, NDJSON). Each message is a single line of valid JSON followed by a newline character (`\n`).

### Message Types

#### Commands (Client → Daemon)

Commands are sent from the client application to the daemon via stdin.

```json
{
  "type": "cmd",
  "cmd": "<command_name>",
  "id": "<uuid>",
  "params": { ... }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Always `"cmd"` for commands |
| `cmd` | string | The command name |
| `id` | string | Unique correlation ID (UUID recommended) for matching responses |
| `params` | object | Command-specific parameters |

#### Events (Daemon → Client)

Events are emitted by the daemon to stdout.

```json
{
  "type": "evt",
  "evt": "<event_name>",
  "id": "<correlation_id>",
  "data": { ... }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Always `"evt"` for events |
| `evt` | string | The event name |
| `id` | string | Optional correlation ID (present for command responses) |
| `data` | object | Event-specific payload |

---

## Commands

### `start_server`

Start a kamune server listening for incoming connections.

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `addr` | string | Yes | Address to bind (e.g., `"127.0.0.1:9000"`) |
| `storage_path` | string | No | Path to storage database |
| `db_no_passphrase` | bool | No | If true, use empty passphrase |

**Example:**

```json
{"type":"cmd","cmd":"start_server","id":"abc-123","params":{"addr":"127.0.0.1:9000","storage_path":"./server.db","db_no_passphrase":true}}
```

**Response Event:** `server_started`

```json
{"type":"evt","evt":"server_started","id":"abc-123","data":{"addr":"127.0.0.1:9000","public_key":"base64-encoded-key"}}
```

---

### `dial`

Connect to a remote kamune server.

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `addr` | string | Yes | Server address (e.g., `"192.168.1.10:9000"`) |
| `storage_path` | string | No | Path to storage database |
| `db_no_passphrase` | bool | No | If true, use empty passphrase |

**Example:**

```json
{"type":"cmd","cmd":"dial","id":"def-456","params":{"addr":"127.0.0.1:9000","storage_path":"./client.db","db_no_passphrase":true}}
```

**Response Event:** `session_started`

```json
{"type":"evt","evt":"session_started","id":"def-456","data":{"session_id":"xyz789","is_server":false,"remote_addr":"127.0.0.1:9000","public_key":"base64-encoded-key"}}
```

---

### `send_message`

Send a message on an established session.

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `session_id` | string | Yes | Target session ID |
| `data_base64` | string | Yes | Message content (base64 encoded) |

**Example:**

```json
{"type":"cmd","cmd":"send_message","id":"ghi-789","params":{"session_id":"xyz789","data_base64":"SGVsbG8gV29ybGQh"}}
```

**Response Event:** `message_sent`

```json
{"type":"evt","evt":"message_sent","id":"ghi-789","data":{"session_id":"xyz789","timestamp":"2024-01-15T10:30:00.000Z"}}
```

---

### `list_sessions`

List all active sessions.

**Parameters:** None

**Example:**

```json
{"type":"cmd","cmd":"list_sessions","id":"jkl-012","params":{}}
```

**Response Event:** `response`

```json
{"type":"evt","evt":"response","id":"jkl-012","data":{"sessions":[{"session_id":"xyz789","remote_addr":"127.0.0.1:9000","is_server":false,"created_at":"2024-01-15T10:25:00Z"}]}}
```

---

### `close_session`

Close a specific session.

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `session_id` | string | Yes | Session to close |

**Example:**

```json
{"type":"cmd","cmd":"close_session","id":"mno-345","params":{"session_id":"xyz789"}}
```

**Response Event:** `response`

```json
{"type":"evt","evt":"response","id":"mno-345","data":{"status":"closed","session_id":"xyz789"}}
```

---

### `shutdown`

Gracefully shut down the daemon.

**Parameters:** None

**Example:**

```json
{"type":"cmd","cmd":"shutdown","id":"pqr-678","params":{}}
```

---

## Events

### `ready`

Emitted when the daemon starts and is ready to accept commands.

```json
{"type":"evt","evt":"ready","data":{"version":"1.0.0","pid":"12345"}}
```

### `server_started`

Emitted when a server successfully starts listening.

```json
{"type":"evt","evt":"server_started","id":"<correlation_id>","data":{"addr":"127.0.0.1:9000","public_key":"base64-encoded-key"}}
```

### `session_started`

Emitted when a new session is established (either incoming server connection or successful dial).

```json
{"type":"evt","evt":"session_started","id":"<correlation_id>","data":{"session_id":"...", "is_server":true|false, "remote_addr":"...", "public_key":"..."}}
```

### `session_closed`

Emitted when a session is closed (either locally or by remote peer).

```json
{"type":"evt","evt":"session_closed","data":{"session_id":"..."}}
```

### `message_received`

Emitted when a message is received from a remote peer.

```json
{"type":"evt","evt":"message_received","data":{"session_id":"...","data_base64":"...","timestamp":"2024-01-15T10:30:00.000Z"}}
```

### `message_sent`

Emitted when a message is successfully sent.

```json
{"type":"evt","evt":"message_sent","id":"<correlation_id>","data":{"session_id":"...","timestamp":"..."}}
```

### `error`

Emitted when an error occurs.

```json
{"type":"evt","evt":"error","id":"<correlation_id>","data":{"error":"error message"}}
```

### `response`

Generic response event for commands that don't have a specific event type.

```json
{"type":"evt","evt":"response","id":"<correlation_id>","data":{...}}
```

---

## Security Considerations

1. **Bind Address**: Always bind the server to `127.0.0.1` for local-only access unless remote connections are explicitly required.

2. **Storage Path**: Use secure, user-specific directories for storage:
   - macOS: `~/Library/Application Support/YourApp/kamune.db`
   - Linux: `~/.local/share/YourApp/kamune.db`
   - Windows: `%APPDATA%\YourApp\kamune.db`

3. **Passphrase**: In production, avoid `db_no_passphrase: true`. Instead, prompt users for a passphrase or use secure keychain storage.

4. **Process Isolation**: The daemon should be spawned as a child process with restricted permissions.

---

## Example Usage

### Starting a Server and Client

**Terminal 1 (Server):**

```bash
./daemon <<EOF
{"type":"cmd","cmd":"start_server","id":"1","params":{"addr":"127.0.0.1:9000","storage_path":"./server.db","db_no_passphrase":true}}
EOF
```

**Terminal 2 (Client):**

```bash
./daemon <<EOF
{"type":"cmd","cmd":"dial","id":"1","params":{"addr":"127.0.0.1:9000","storage_path":"./client.db","db_no_passphrase":true}}
{"type":"cmd","cmd":"send_message","id":"2","params":{"session_id":"SESSION_ID","data_base64":"SGVsbG8gV29ybGQh"}}
EOF
```

### Programmatic Integration

```python
import subprocess
import json

proc = subprocess.Popen(
    ['./daemon'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

def send_cmd(cmd, params, cmd_id):
    msg = json.dumps({"type": "cmd", "cmd": cmd, "id": cmd_id, "params": params})
    proc.stdin.write(msg + "\n")
    proc.stdin.flush()

def read_event():
    line = proc.stdout.readline()
    return json.loads(line)

# Wait for ready
evt = read_event()
print(f"Daemon ready: {evt}")

# Start server
send_cmd("start_server", {"addr": "127.0.0.1:9000", "db_no_passphrase": True}, "1")
evt = read_event()
print(f"Server started: {evt}")
```

---

## Troubleshooting

### Daemon doesn't start

Check stderr for error logs:

```bash
./daemon 2>daemon.log
```

### Connection refused

Ensure the server is running and the address is correct. Check firewall settings.

### Base64 encoding errors

Use standard base64 encoding (not URL-safe). In most languages:

```python
import base64
encoded = base64.b64encode(b"Hello World!").decode()
```

```javascript
const encoded = btoa("Hello World!");
```
