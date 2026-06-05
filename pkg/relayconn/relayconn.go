// Package relayconn is a client library for the Kamune relay protocol.
//
// It provides two symmetric connection roles:
//
//   - ListenRelay*  — establishes a listener session with a relay server,
//     receives an opaque token (and TTL) to share out-of-band with a peer.
//   - DialRelay*    — establishes a dialer session by presenting a token
//     obtained from a listener, connecting the two peers through the relay.
//
// Both roles support four transports:
//
//   - ListenRelay / DialRelay       — WebSocket (ws://)
//   - ListenRelayWSS / DialRelayWSS — WebSocket Secure (wss://)
//   - ListenRelayTCP / DialRelayTCP — raw TCP with length-prefixed framing
//   - ListenRelayTLS / DialRelayTLS — TLS over TCP
//
// PSK authentication is optional via WithPassword().
//
// Types
//
// RelayListener implements the kamune.Listener interface. After a successful
// ListenRelay* call, the caller obtains the token and TTL, shares the token
// out-of-band, then calls Accept() to wait for a peer to connect. Stop()
// halts acceptance without closing an active connection; Close() tears down
// everything.
//
// RelayConn implements the kamune.Conn interface with ReadBytes, WriteBytes,
// SetDeadline, and Close methods. Both sides can send and receive framed
// messages through the relay.
//
// Wire protocol
//
// The pb sub-package (relayconn/pb) defines the protobuf wire format shared
// with the relay server. Consumers of relayconn never need to import it
// directly — the client library handles marshalling internally.
//
// Location
//
// relayconn lives at pkg/relayconn inside the root module rather than as a
// standalone module or inside the relay server for the following reasons:
//
//   - The protobuf types in pb/ are imported by both the relay server
//     (for parsing the wire format on the server side) and this client
//     library. Keeping them in a single package avoids creating a separate
//     protobuf module or duplicating the definitions.
//
//   - If relayconn were its own module, every consumer (relay server, bus,
//     tui) would need an additional require+replace pairing in go.mod.
//
//   - If relayconn were inside the relay server module, bus and tui would
//     import the entire relay server (and its internal packages) just to
//     use the client library — an inverted dependency that couples
//     unrelated consumers to server internals.
//
//   - As part of the root module, relayconn is available to all sub-modules
//     through the existing replace directives without adding new ones. The
//     tradeoff is that relayconn is client-side only, while the root module
//     primarily exposes the core protocol interfaces (Server, Dialer,
//     Transport, Conn) and cryptographic primitives.
package relayconn
