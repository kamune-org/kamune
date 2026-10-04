// Package relayconn is the transport layer for the Kamune relay.
//
// The relay forwards opaque frames between two peers using a
// token-based rendezvous. The transport layer is the
// set of primitives that both sides must agree on for any of that to
// work: the on-wire framing, the protobuf frame types, and the
// transport adapters that carry them.
//
// # Wire format
//
// On the TCP and TLS transports every frame is a length-prefixed
// payload: two big-endian bytes of length followed by exactly that many
// bytes of payload. The length is an unsigned 16-bit integer, so a frame
// carries at most 65535 bytes. Framing implements this format for any
// io.ReadWriteCloser and rejects frames longer than its maximum;
// DefaultMaxFrameSize matches the relay's default max_message_size. The
// WebSocket transports carry one frame per binary message instead.
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
// Each client runs its own HPKE exchange (pkg/exchange) with the relay,
// and that channel ends at the relay. The relay decrypts every frame on
// it, so it sees the Auth PSK, the Register token and the size and
// timing of Message frames. The exchange does not prove the relay's
// identity: over ws:// or tcp://, or over TLS without certificate
// verification, an active on-path attacker can pose as the relay. Use
// wss:// or tls:// with a certificate the client verifies, or pin a
// self-signed relay certificate with PinnedTLSConfig. The relay is
// "blind" only to the payload of Message frames, which it forwards
// unchanged between the two peers.
//
// That payload is the kamune protocol the peers run with each other,
// and its protection comes from kamune, not from this package. Its
// opening HPKE exchange is not authenticated either, so the relay, or
// an attacker posing as it, can read what the peers send before the
// kamune handshake completes, such as their introductions. The messages
// of an established session stay confidential as long as each peer
// checks the other's identity key.
package relayconn
