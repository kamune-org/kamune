# Relay Protocol

Kamune supports a relay server for NAT traversal and offline message delivery.
Peers communicate through a WebSocket relay using HPKE-encrypted channels.

## Relay Protobuf Schema

```protobuf
package relayconn;

message Frame {
    oneof kind {
        Identity identity = 1;
        Message  msg      = 2;
        Ack      ack      = 3;
        Ping     ping     = 4;
        Pong     pong     = 5;
    }
}

message Identity {
    bytes key = 1;  // Peer's public key (PKIX/DER)
}

message Message {
    bytes  receiver   = 1;  // Target peer's public key
    bytes  sender     = 2;  // Set by relay when forwarding
    string session_id = 3;
    bytes  data       = 4;
}

message Ack {
    string session_id = 1;
}

message Ping {}
message Pong {}
```

## Connection to Relay

Both dialing (`DialRelay`) and listening (`ListenRelay`) initiate a WebSocket
connection to the relay at `ws://<addr>/ws`:

1. Establish HPKE Channel via `exchange.Initiate` over the WebSocket.
2. Send `Frame{Identity{key: selfPubKey}}` through the HPKE channel.
3. Receive the relay's `Frame{Identity{key: relayPubKey}}`.
4. The relay now knows the peer's public key and can route messages.

## Relay Sessions

Each relay session is identified by a synthetic session ID:

```
syntheticSessionID(selfKey, peerKey) = "relay-hs:" + hex(SHA-256(selfKey || peerKey)[:8])
```

## Relay Frame Flow

- **Outgoing messages**: Wrapped in `Frame{Msg{receiver, sessionID, data}}`,
  encrypted via the HPKE Channel, and sent over the relay WebSocket.
- **Incoming messages**: `Frame{Msg{data}}` is unwrapped from the relay,
  buffered, and returned via `ReadBytes()`.
- **Ping/Pong**: `Frame{Ping}` triggers an automatic `Frame{Pong}` response at
  the relay connection level.

## RelayListener

`ListenRelay` returns a `RelayListener` implementing the `Listener` interface.
When a message arrives for a new session ID, a new `RelayConn` is created and
pushed to the accept channel. The `RelayConn` implements the `Conn` interface
and can be used with the standard `Server` via `ServeWithListener`.
