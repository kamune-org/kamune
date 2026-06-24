// Package relayconn is the transport layer for the Kamune relay.
//
// The relay forwards opaque, end-to-end-encrypted frames between two
// peers using a token-based rendezvous. The transport layer is the
// set of primitives that both sides must agree on for any of that to
// work: the on-wire framing, the protobuf frame types, and the
// transport adapters that carry them.
//
// # Wire format
//
// Every frame exchanged by the relay is a length-prefixed payload:
// two big-endian bytes of length followed by exactly that many bytes
// of payload. The length is an unsigned 16-bit integer, so the maximum
// frame size is 64 KB. Framing implements this format for any
// io.ReadWriteCloser. The default and recommended maximum is
// DefaultMaxFrameSize (64 KB); both sides of a connection should use
// the same value to avoid one side accepting frames the other rejects.
//
// The protobuf sub-package (relayconn/pb) defines the frame types
// themselves: Register, Registered, Message, Ping, Pong, and Auth.
// Consumers of relayconn rarely need to import pb directly — the
// transport layer handles marshalling.
//
// # Transports
//
// Three transport adapters are provided, all of which implement the
// exchange.ReadWriter interface:
//
//   - wsAdapter  — WebSocket (ws://, wss://)
//   - tcpAdapter — raw TCP with length-prefixed framing
//   - tlsAdapter — TLS over TCP with the same length-prefixed framing
//
// The length-prefixed framing is what makes the TCP and TLS adapters
// interchangeable: once framed, the byte stream is opaque to the
// transport.
//
// # Rendezvous helpers
//
// For end-user applications that want to talk to a relay, the package
// exposes high-level helpers built on top of the transport layer:
//
//   - ListenRelay*  — establishes a listener session, returns a token
//     to share out-of-band with a peer.
//   - DialRelay*    — presents a token, connects the two peers through
//     the relay.
//
// These return RelayListener (implements kamune.Listener) and
// RelayConn (implements kamune.Conn) respectively. They support the
// four transports: ListenRelay/DialRelay (WebSocket),
// ListenRelayWSS/DialRelayWSS (WebSocket over TLS),
// ListenRelayTCP/DialRelayTCP (raw TCP), and
// ListenRelayTLS/DialRelayTLS (TLS over TCP).
//
// PSK authentication is optional via WithPassword().
//
// # Protocol design
//
// The relay is intentionally "blind": it sees only the framing and
// the protobuf types, not the contents of Message frames. End-to-end
// encryption happens inside the relay's wire format (via HPKE in
// pkg/exchange) and is opaque to the transport layer. The transport
// layer's job is to move bytes; the cryptographic layer's job is to
// protect them.
package relayconn
