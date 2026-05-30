# Relay-as-Transport Integration

Enable the Kamune core protocol (`Transport`, `Server`, `Dialer`, `Router`) to
communicate through the relay server instead of raw TCP/UDP.

## Goals

- Indirect messaging when peers aren't directly reachable (NAT, firewalls)
- Store-and-forward for offline peers (relay queue)
- Single public endpoint for both peers to connect to the relay

## The Seam: `Conn` Interface

The entire integration pivots on one interface (`conn.go:21-26`):

```go
type Conn interface {
    ReadBytes() ([]byte, error)
    WriteBytes(data []byte) error
    SetDeadline(t time.Time) error
    Close() error
}
```

`Transport`, the handshake functions (`exchange.go`, `handshake.go`, `intro.go`),
`Server.serve()`, and `Dialer.handshake()` all operate on `Conn`. Replace the
TCP-based `conn` with a relay-based `relayConn`, and everything upstream (HPKE
exchange, ML-KEM handshake, Ed25519 signing, XChaCha20-Poly1305 encryption,
route dispatch) works unchanged.

## Architecture

```
┌─ Dialer / Initiator ─────────────────────────────────────┐
│                                                          │
│  DialWithExistingConn(relayConn)                         │
│       ↓                                                  │
│  exchange.go (HPKE)                                      │
│  intro.go (Ed25519)                                      │
│  handshake.go (MLKEM)                                    │
│  challenge.go                                            │
│       ↓                                                  │
│  Transport.Send/Receive  →  same relayConn               │
│                                                          │
└──────────────────────┬───────────────────────────────────┘
                       │  WS JSON     {"type":"message",
                       │              "sender":"<pk>",
                       │              "receiver":"<pk>",
                       │              "session_id":"<id>",
                       │              "data":"<base64>"}
                       ▼
┌─ Relay Server ────────────────────────────────────────────┐
│                                                           │
│  Hub ─→ WS push to receiver (instant if online)           │
│  Convey ─→ HTTP direct push (if peer registered address)  │
│  Queue ─→ store-and-forward (fallback)                    │
│                                                           │
└──────────────────────┬────────────────────────────────────┘
                       │
                       ▼
┌─ Server / Responder ──────────────────────────────────────┐
│                                                           │
│  relayListener.Accept()  →  relayConn                     │
│  server.ServeConn(relayConn)                              │
│       ↓                                                   │
│  exchange.go → intro.go → handshake.go → challenge        │
│       ↓                                                   │
│  handlerFunc(transport)                                   │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

## Protocol Flow (Round-Trips)

The existing handshake requires **6 sequential round-trips** before application
messages flow:

| Step | Direction | Messages | SessionID known? |
|------|-----------|----------|-----------------|
| Exchange (2+2 writes/reads) | ↔ | HPKE pubkey, enc, remote pubkey, enc | No |
| Introduction (1+1) | ↔ | Signed identity (RouteIdentity) | No |
| RequestHandshake (1+1) | ↔ | MLKEM pubkey, encapsulated key | Yes (generated) |
| Challenge ×2 (1+1 each) | ↔ | Challenge, echo | Yes |

Over WebSocket, each round-trip is a JSON frame. The relay treats all payloads
as opaque blobs — it never decrypts or inspects them.

## The Session ID Problem

The relay's WS protocol requires a non-empty `session_id` field on every
message (`ws_handler.go:53`). But during handshake steps 1-2, no session ID
exists yet — it's generated inside `requestHandshake()` / `acceptHandshake()`.

**Solution**: Use a synthetic session ID during the handshake phase, then switch
to the real one post-handshake.

```
Handshake phase:   session_id = "relay-hs:<sender_key[:8]>:<receiver_key[:8]>"
Post-handshake:    session_id = <real 20-char session ID from Transport.SessionID()>
```

The relay's queue key derivation (HKDF-based) produces different keys for the
two phases. This is fine — handshake messages are ephemeral and timeout-bound,
so they don't need queue persistence. For WS hub delivery, only the `receiver`
key matters for routing; the session ID is metadata passed to the recipient.

## Components

### Server.ServeConn — core change

`Server.serve()` is currently a private method. Exposing it allows any caller
to run the full handshake flow on an arbitrary `Conn`:

```go
// ServeConn runs the server's handshake flow on an existing Conn.
// This allows external code (e.g., a relay listener) to accept connections
// without going through Server.ListenAndServe.
func (s *Server) ServeConn(cn Conn) error {
    return s.serve(cn)
}
```

This is the **only core change needed**. The initiator side already has
`DialWithExistingConn`.

### relayConn — client-local, one per client module

Each client (TUI, Bus, Daemon) implements the 4-method `Conn` interface using
the relay's WebSocket protocol. This lives in each client's own `internal/` tree:

**`internal/relayconn/relayconn.go`**:

```go
type relayConn struct {
    ws         *websocket.Conn
    peerKey    string            // target peer's public key
    selfKey    string            // our public key
    recv       chan []byte       // incoming messages for this session
    sessionID  atomic.Value      // synthetic → real after handshake
    ctx        context.Context
    cancel     context.CancelFunc
    writeMu    sync.Mutex
}
```

Methods (~170 lines total including WS setup):

- **`Dial(ctx, relayURL, selfKey, peerKey)`** — connects to relay WS with
  `?key=<selfKey>`, returns `*relayConn`. Used by the initiator.
- **`Listen(ctx, relayURL, selfKey)`** — connects to relay WS, returns a
  `Listener`. Used by the server/responder.
- **`WriteBytes([]byte)`** — sends `WSMessage{Type:"message", Sender, Receiver,
  SessionID, Data: base64(data)}`. Uses the session ID from `atomic.Value`.
- **`ReadBytes()`** — blocks on `recv` channel. Returns `ErrConnClosed` on
  context cancellation.
- **`SetDeadline(time.Time)`** — creates a new context with timeout, resets the
  recv channel.
- **`Close()`** — cancels context, closes WS, closes recv channel.
- **`SetSessionID(string)`** — called after handshake to switch from synthetic
  to real session ID.

**`internal/relayconn/pump.go`** — WS read pump with optional demultiplexing:

```go
// ReadPump reads WS messages and dispatches them to relayConn instances
// based on session_id. For a single-session client (like TUI), no demux is
// needed — it feeds directly to the one relayConn.
func ReadPump(ctx context.Context, conn *websocket.Conn, rc *relayConn) {
    for {
        _, raw, err := conn.Read(ctx)
        // unmarshal, extract data, send to rc.recv
    }
}
```

**`internal/relayconn/listener.go`** — virtual listener for the server side:

```go
type Listener struct {
    ws          *websocket.Conn
    selfKey     string
    acceptCh    chan *relayConn
    handshakeID string
}

func (l *Listener) Accept() (*relayConn, error)
```

- Blocks on `acceptCh`.
- On receiving a message with the handshake session ID:
  creates a `relayConn`, pushes it to `acceptCh`.
- Supports multiple concurrent sessions (for Bus).

### Queue Drain on WS Connect — relay change

After registering a peer in the hub, drain any queued messages so the offline
peer catches up:

```go
// In ws_handler.go, after hub.Register(pk, conn):
for _, session := range pendingSessions(pk) {
    msgs, _ := service.BatchPopQueue(pk, session.sender, session.id, 100)
    for _, msg := range msgs {
        wsjson.Write(ctx, conn, WSMessage{
            Type: "message", Sender: session.sender,
            SessionID: session.id, Data: base64(msg),
        })
    }
}
```

This adds ~30 lines to `ws_handler.go`.

## Integration in TUI (Prototype Target)

New commands:

```
# Dial through relay
./chat -db ./client.db relay-dial relay.example.com <base64_peer_pubkey>

# Serve through relay
./chat -db ./server.db relay-serve relay.example.com
```

### Client side (`cmd/tui/relay_client.go`)

```go
func relayClient(ctx context.Context, relayURL, peerPubKey string, opts ...any) error {
    store := openStorage(...)
    dialer, _ := kamune.NewDialer("relay://"+peerPubKey, store)
    // relayConn replaces the raw TCP dial
    rc, _ := relayconn.Dial(ctx, relayURL, selfKey, peerPubKey)
    dialer, _ = kamune.NewDialer("relay://"+peerPubKey, store,
        kamune.DialWithExistingConn(rc),
    )
    t, err := dialer.Dial()
    // same RouteDispatcher loop as today
    return handleSession(t, store)
}
```

### Server side (`cmd/tui/relay_server.go`)

```go
func relayServer(ctx context.Context, relayURL string, opts ...any) error {
    store := openStorage(...)
    srv, _ := kamune.NewServer("relay://"+relayURL, handler, store,
        kamune.ServeWithRemoteVerifier(...),
    )
    listener, _ := relayconn.Listen(ctx, relayURL, selfKey)
    for {
        rc, _ := listener.Accept()
        go func() {
            t, err := srv.ServeConn(rc) // uses the exported method
            if err != nil { return }
            handler(t)
        }()
    }
}
```

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Where to put relayConn | Each client's `internal/relayconn/` | Clean dependency isolation; `Conn` is trivially small |
| Core change | Only `Server.ServeConn()` | Without it, every client duplicates the full handshake sequence |
| WS demultiplexing | Per-session relayConn with shared WS | A client may handle multiple sessions; one WS connection per peer maps to the relay's Hub model |
| Handshake session ID | Synthetic `"relay-hs:<keyhash>"` | Relay requires non-empty sessionID; distinguishable for debugging |
| Authentication | Relay trusts `?key=` (prototype) | Proper WS auth comes later |
| Peer discovery | User provides peer pubkey out-of-band | `/peers` API can automate later |
| Heartbeat | Client-side ping every 30s | Matches relay's existing `"ping"` → `"pong"` protocol |

## Required Changes

| What | Where | Lines | Scope |
|------|-------|-------|-------|
| `Server.ServeConn()` | `server.go` | +3 | Core |
| `relayconn` package | `cmd/tui/internal/relayconn/` | ~170 | TUI |
| Relay commands | `cmd/tui/main.go`, `relay_client.go`, `relay_server.go` | ~60 | TUI |
| Queue drain on WS connect | `cmd/relay/internal/handlers/ws_handler.go` | ~30 | Relay |

## Non-Goals for Prototype

1. **Message authentication** — relay doesn't verify sender owns their pubkey
2. **Relay cluster / multi-relay** — single relay instance
3. **NAT traversal via relay** — all traffic goes through relay (not just
   signaling)
4. **Graceful reconnect** — WS drop kills the session
5. **Webhook integration** — clients use WS directly
6. **Bus / Daemon integration** — TUI-only for now

## Future Work

- Ed25519 signature verification on WS messages (prevent impersonation)
- Relay as signaling channel only: relay for handshake, then switch to direct
  P2P (best of both worlds)
- Session resumption after WS drop
- Multi-session support in TUI (currently one session at a time)
- Automated test: spin up relay, two TUI instances, verify message delivery
