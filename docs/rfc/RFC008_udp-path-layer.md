# RFC: UDP Path Layer: Return Routability and Packet Authentication for KCP

**Status:** Draft

**Target:** Kamune Protocol Specification before v1.0 (not scheduled)

**Relates to:** §9.2 (UDP via KCP), §9.4 (Connection Contract), §10.1
(Responder Role), §12.7 (Traffic Analysis Resistance), §13 (Constants and
Limits), §14 (Error Conditions); RELAY.md "Broker: STUN-Echo and Signal
Introduction"; RFC006 (overview), RFC007 (handshake), RFC010 (tokens),
RFC011 (broker)

---

## 1. Summary

Put a thin layer, `internal/udppath`, between kamune's UDP sockets and
kcp-go. The layer owns the socket, runs a two-round-trip path handshake per
peer that proves the dialer receives packets at its source address, and then
gives each path its own `net.PacketConn`. kcp-go runs one client-style
session (`kcp.NewConn4`) on each path. kcp-go's `Listener` (`kcp.Listen`,
`kcp.ServeConn`) is no longer used anywhere, so its address-keyed session
map, its accept backlog and its in-band `conv`/`sn == 0` reset are out of the
picture. Every KCP packet is sealed with ChaCha20-Poly1305 under a per-path
key and checked against a replay window, and either side can end a path with
an authenticated CLOSE.

The server also gains a three-level handshake rate limit (source, network,
global) in front of the kamune handshake for every transport, and counts a
connection's source address against its per-source cap only when the
connection proves return routability.

This RFC is one part of the pre-v1.0 protocol rework described in RFC006.
The rework is not implemented now. The change is a wire-incompatible hard
cut, as RFC004 is, and no backward compatibility is kept: the UDP wire
format, the `ServeWithUDP` and `DialWithUDP` signatures, the server's
source accounting and the hole-punch helpers in `cmd/bus` and `cmd/daemon`
all change. A peer running today's KCP code cannot talk to a peer running
this layer.

It closes KAM-11 and the rest of KAM-05 (section 3). The work lives in the
root module, with follow-up changes in `cmd/bus` and `cmd/daemon`.

## 2. Current Behavior

Root module (`kamune`):

- `ServeWithUDP` (`server.go`) calls `kcp.Listen(s.addr)` (nil block cipher,
  0 data and 0 parity shards) and wraps the result in `udpListener`. kcp-go's
  `Listener.packetInput` creates a `UDPSession` for the first datagram from
  any new address that it can read a `conv` from: 12 bytes or more for a
  packet typed as FEC OOB (`0xf3` in bytes 4-5), 24 bytes for a plain KCP
  segment. It closes an existing session when a packet from that address
  carries another `conv` with `sn == 0`; an OOB-typed packet carries no `sn`
  and is read as `sn == 0`.
- `DialWithUDP` (`dial.go`) calls `kcp.Dial(addr)`. A dial never fails at the
  UDP level, so an unreachable server shows up only as the 30 s handshake
  timeout (`defaultHandshakeTimeout`).
- `Server.admit` sets `pendingConn.forgeable` from `forgeableAddr`: any
  address whose network starts with `udp` counts against the per-source cap
  only once the dialer has introduced itself (`Server.introduced`); any other
  address counts at accept, whatever the `Listener`. SPEC §10.1 describes this
  rule and its gap: a sender that forges source addresses from many networks
  can still push out an initiator that has not introduced itself.
- kcp-go's listener read loop (`Listener.monitor`) and each client
  session's `readLoop`, batched or not, read into 1,500-byte buffers
  (`mtuLimit`). Any read error ends the loop and reaches every session of
  that listener, or the session itself, through `notifyReadError`. On
  Windows a datagram larger than 1,500 bytes is such an error
  (`WSAEMSGSIZE`, the trigger of REL-01 on the relay's broker port).
- `Server.Close` closes the `udpListener`, and kcp-go's `Listener.Close`
  closes the socket that `kcp.Listen` opened. Sessions already handed to the
  handler read from that socket, so they end too, contrary to the documented
  `Server.Close` contract (SPEC §10.1: "Sessions already handed to the
  handler are not affected").
- KCP packets are not authenticated. SPEC §9.2 says so, and already states
  that FEC and kcp-go packet encryption are off (2a6df97).
- kcp-go v5.6.72 is a direct dependency of the root module, `cmd/bus` and
  `cmd/daemon`, and an indirect one of `cmd/relay` and `cmd/tui`.

Clients (`cmd/bus`, `cmd/daemon`):

| Use | bus | daemon |
| --- | --- | ------ |
| Plain UDP server | `StartServer`: `kamune.ServeWithUDP()` | `startServer`: `listenDirect` calls `kcp.Listen` and wraps sessions with `kamune.NewConn` in `boundListener`, then `ServeWithListener` |
| Plain UDP dial | `ConnectToServer`: `dialUDP` (`dialattempt.go`) calls `kcp.Dial` and `kamune.NewConn`, through `DialWithFunc`; the reconnect function uses `kamune.DialWithUDP()` | `dial`: `kamune.DialWithUDP()` |
| Broker P2P listener | `newP2PListener`: `kcp.ServeConn(nil, 0, 0, punchFilter)`. `punchFilter` hands broker packets to `handleBroker` and passes only packets from IPs that a PEER_MATCHED named within `matchWindow` (1 min) or from the address of a live session | `newP2PListener`: `kcp.ServeConn(nil, 0, 0, &punchConn{...})`. `punchConn` hands broker packets to `handleBroker` and passes only packets from IPs that a PEER_MATCHED named (`admitted`, `matchedPeerIdle`) |
| Direct P2P listener | `newDirectP2PListener`: `kcp.ServeConn` behind a `punchFilter` that passes the peer's IP, any port | `newDirectP2PListener`: `kcp.ServeConn(nil, 0, 0, conn)`, any source |
| Direct P2P listener NAT kicks | `kickFor`, started by `newDirectP2PListener`: a burst every 2 s for 10 s | `natKickLoop`: a burst every 2 s for 10 s |
| Broker P2P listener NAT kicks | `p2pListener.kick` on each PEER_MATCHED: `kickFor`, a burst every 2 s for 10 s (at most `maxMatchedPeers` addresses at once) | one `sendNATKick` burst on each PEER_MATCHED (`p2plistener.go`) |
| Broker P2P dial | `BrokerClient.HolePunch(ctx, punchConn, ip, port)` has no timeout; it starts `sendNATKick` in the background and returns `kcp.NewConn4(...)` at once | `BrokerClient.HolePunch(ctx, punchConn, ip, port, timeout)` sends the kick burst within `timeout` (`DefaultHolePunchTimeout`, 5 s), fails with `ErrHolePunchFailed` only when no kick could be sent, then returns `kcp.NewConn4(...)` at once |
| Direct P2P dial | `directP2PDial(ctx, addr)`: `sendNATKick` under a 5 s context, then `kcp.NewConn4(...)` | `directP2PDial(addr)`: the same, not cancellable |

A burst (`sendNATKick`) is five 1-byte `0x00` datagrams 100 ms apart. Both
clients wrap the KCP session from `HolePunch` and `directP2PDial` with
`kamune.NewConn`. Neither dial waits for the peer, so a failed punch shows up
only as the kamune handshake timeout. The source filters in the clients test
addresses that an off-path sender can forge: they keep scanners out, not
spoofers, and kcp-go behind them still keys sessions by address.

The TUI does not use UDP.

## 3. Motivation and Findings Closed

Findings from `docs/RED_TEAM_REVIEW.md` that this RFC closes:

| Finding | Status | What closes it |
| ------- | ------ | -------------- |
| KAM-11 | Closed | No kcp-go `Listener` (no address-keyed sessions, no in-band reset); a path handshake before any kcp-go state exists; AEAD and a replay window on every KCP packet; socket read errors never reach kcp-go (section 8.1); `UDPWithSourceFilter` and `UDPWithKnockKey` for P2P listeners; every call site moves off `kcp.Listen`, `kcp.Dial`, `kcp.ServeConn` and raw `kcp.NewConn4`. The FEC claim was already removed from SPEC §9.2 (2a6df97); FEC stays off (section 15). |
| KAM-05 | Closed | Already on main: accept backoff (d26e196), the waiting cap and per-source cap (a860952), `io.ErrClosedPipe` read as shutdown. This RFC closes the rest: (1) UDP sources are verified before a `Conn` exists, so forged sources no longer reach the waiting cap; (2) per-source accounting trusts an address only from a conn that proves return routability (`ReturnRoutable`), so a third-party `Listener` cannot reopen the spoofing gap; (3) `ServeWithHandshakeRate`: per-source, per-network and global token buckets in `admit`, before the first KEM operation, with constant memory and no fail-open branch; (4) the path layer has per-source, per-network and eviction-based total caps, so it adds no global lockout that TCP lacks. |

Neither is only partly closed. KAM-05 keeps one residual, which SPEC §10.1
documents: an attacker with real addresses in many networks can still use up
the global handshake rate. That turns CPU exhaustion into refused
handshakes, which costs the server less and gives dialers the same outcome.
It is the same residual as for TCP.

Related findings, not claimed by this RFC:

| Finding | Relation |
| ------- | -------- |
| REL-01 | Fixed on main in the relay's broker loop (`TestRun_SurvivesPacketReadErrors`). RFC011's broker server keeps that fix (its loop survives read errors, with the v1 backoff); whether the loop's 2,048-byte buffer grows to 65,536 bytes is RFC011's open question 2. RFC011's Endpoint follows the read rule of section 8.1 (RFC011 §10.4). This RFC applies that rule (65,536-byte buffer, every non-close read error transient) to every socket the path layer reads, where kcp-go today has the same weakness (section 2), and requires it of RFC011's Endpoint (section 13). |
| RC-05, REL-12 | Closed by RFC011 (authenticated matches). This RFC bounds what a dialer sends to an address that never answers (section 11). |
| BUS-17 | Fixed on main in the bus (`punchFilter` passes only the direct peer's IP). This RFC replaces that filter with `UDPWithSourceFilter(isPeerIP)` and the knock key, and gives the daemon's direct-P2P listener, which has no filter today, the same (section 12). |
| DMN-20 | Fixed on main on the current KCP code. This RFC replaces that code: `HolePunch` blocks on `DialUDP` within its timeout, and HELLO retransmissions replace the dialer's kick burst (sections 8.3, 12). |
| BUS-06, DMN-21 | Fixed on main on the current KCP code; RFC011 closes the broker part in v2 (its endpoint consumes broker packets, the listener reads MATCHED and kicks). This RFC's share: the dialer's kick and timeout handling (as DMN-20) and the first-byte rule that keeps any broker datagram out of KCP. Accepting KCP only from hosts a match named is open question 1 (section 20). |
| DOC-05 | Fixed on main (2a6df97). SPEC §9.2 is rewritten again here and keeps the statement that FEC is off. |

For BUS-17, DMN-20, BUS-06 and DMN-21 the implementer checks, once this RFC
is implemented, that each fix still holds, and records the result.

## 4. Terminology

| Term | Meaning |
| ---- | ------- |
| Path | One dialer-to-listener association on a UDP socket, created by a completed path handshake and bound to one peer address and port. |
| `cid` | Client id: random, non-zero, 32 bits, picked by the dialer per handshake attempt. Also the KCP `conv` of the path's session. |
| `sid` | Server id: random, non-zero, 32 bits, unique among the server's live paths. |
| `rid` | Receiver's id in DATA and CLOSE: `sid` from client to server, `cid` from server to client. |
| Path address | The source address and port of the INIT that created the path, with any IPv4-in-IPv6 mapping removed. |
| Cookie | `t \|\| mac` (20 bytes) from COOKIE, proof that the dialer receives packets at its source address. |
| Knock key | Optional 32-byte key `k_knock` that both peers hold; with it, a listener ignores HELLO and INIT from anyone else. |
| Return routable | A conn whose remote address has shown that it receives packets: TCP, Unix sockets and path conns. |
| Source key, network key | `SourceKey`: an IPv4 address or IPv6 /64. `NetworkKey`: an IPv4 /24 or IPv6 /48. |
| HALF_OPEN, QUEUED, ACCEPTED | Server path states (section 8.2). |

## 5. Design Overview

```
dialer (client)                                    listener (server)
HELLO   {cid, mac1, pad to 1200}         ------->  stateless: HMAC only
                                         <-------  COOKIE {cid, t, mac}   28 B
INIT    {cid, cookie, c_eph, mac1, pad}  ------->  verify cookie, admit,
         1200 B                                    X25519, create path
                                         <-------  ACCEPT {cid, sid, s_eph, tag}
DATA    {sid, ctr, AEAD(KCP packet)}     <------>  DATA {cid, ctr, AEAD(...)}
CLOSE   {sid, ctr, tag}                  <------>  CLOSE {cid, ctr, tag}
```

- HELLO and COOKIE form a stateless return-routability check, as in DTLS 1.2
  HelloVerifyRequest (RFC 6347 4.2.1), QUIC Retry tokens (RFC 9000 8.1) and
  the WireGuard cookie reply. The cookie is an HMAC under a per-listener
  secret over the source address and port, a client id and a timestamp.
- INIT and ACCEPT form an unauthenticated ephemeral X25519 exchange (Noise
  `NN` shape), run only after the cookie proves the address. Keys come from a
  TLS 1.3 style `HKDF-Expand-Label` over a transcript hash, one key per
  direction.
- Every KCP packet travels in a DATA packet sealed with ChaCha20-Poly1305
  under the path key, with an explicit 64-bit counter and a 2048-packet
  sliding replay window (WireGuard, RFC 6479).
- CLOSE is an authenticated, replay-protected end-of-path message, so a peer
  learns at once that the other side dropped, evicted or expired the path.
- An optional knock key (the WireGuard `mac1` pattern) lets a P2P listener
  ignore HELLO and INIT from anyone who does not hold the pair's punch key.
- Every reply to an unverified source is smaller than the request that
  caused it (HELLO 1200 B, COOKIE 28 B). Every other reply goes to an address
  that has proven it receives packets.

Result: a spoofed datagram can no longer create kcp-go state, start KEM
work, reset or inject into a KCP session, or take a place in the server's
caps. A datagram of any size or content cannot end a session through a
socket read error. The three-level handshake rate limit bounds KEM work
driven from many addresses, for every transport.

## 6. Wire Format

All integers are big-endian. Every packet starts with a 4-byte header:

| Offset | Size | Field | Value |
| ------ | ---- | ----- | ----- |
| 0 | 1 | `type` | `0x01` HELLO, `0x02` COOKIE, `0x03` INIT, `0x04` ACCEPT, `0x05` DATA, `0x06` CLOSE |
| 1 | 1 | `version` | `0x01` |
| 2 | 2 | `reserved` | `0x0000` |

First-byte ranges on a socket the layer reads. This is a wire invariant,
written into SPEC §9.2 and RELAY.md:

| First byte | Owner | Path layer action |
| ---------- | ----- | ----------------- |
| `0x00` | NAT kicks (1-byte datagrams) | drop, count `Kick` |
| `0x01`-`0x0F` | this layer | validate as below |
| `0x10`-`0xFF` | others (broker v2 `"KBRK"` = `0x4B`) | drop, count `Foreign` |

Broker datagrams never reach the path layer: RFC011's endpoint sits closest
to the socket and consumes them (section 13). Anything else outside the
layer's range is dropped.

Receivers drop, with no reply, a packet whose `version` is not `0x01`, whose
`reserved` is not zero, whose `type` is unknown, whose length is not exactly
the one given below (DATA: within its range), or which carries a zero `cid`
or `sid`. An unauthenticated refusal would be a forgeable DoS signal and a
scanning oracle. The layer never replies to a packet it did not expect: the
only replies are COOKIE to HELLO and ACCEPT to INIT.

### 6.1 HELLO (client to server), exactly 1200 bytes

| Offset | Size | Field |
| ------ | ---- | ----- |
| 0 | 4 | header, `type = 0x01` |
| 4 | 4 | `cid`: client id, random, non-zero |
| 8 | 16 | `mac1` (section 7.4); all zero without a knock key |
| 24 | 1176 | zero padding (the receiver checks it is all zero) |

The padding makes the reply to an unverified source smaller than the
request (43:1) and checks that the path carries 1200-byte datagrams (the
data MTU, section 6.5).

### 6.2 COOKIE (server to client), 28 bytes

| Offset | Size | Field |
| ------ | ---- | ----- |
| 0 | 4 | header, `type = 0x02` |
| 4 | 4 | `cid`, echoed |
| 8 | 4 | `t`: server Unix time in seconds at issue |
| 12 | 16 | `mac` |

`cookie` below means bytes 8-27 (`t || mac`, 20 bytes).

### 6.3 INIT (client to server), exactly 1200 bytes

| Offset | Size | Field |
| ------ | ---- | ----- |
| 0 | 4 | header, `type = 0x03` |
| 4 | 4 | `cid` (the same as in the HELLO) |
| 8 | 20 | `cookie` (`t \|\| mac`, copied from COOKIE) |
| 28 | 32 | `c_eph`: client ephemeral X25519 public key |
| 60 | 16 | `mac1` (section 7.4); all zero without a knock key |
| 76 | 1124 | zero padding |

### 6.4 ACCEPT (server to client), 60 bytes

| Offset | Size | Field |
| ------ | ---- | ----- |
| 0 | 4 | header, `type = 0x04` |
| 4 | 4 | `cid` |
| 8 | 4 | `sid`: server id, random, non-zero, unique among the server's live paths |
| 12 | 32 | `s_eph`: server ephemeral X25519 public key |
| 44 | 16 | `tag` = `ChaCha20-Poly1305.Seal(k_s2c, nonce(0), "", AD = bytes 0-43)` |

The tag is key confirmation: only a party that knows the `c_eph` private key
can check it, and only a party that ran X25519 with `c_eph` can produce it.

### 6.5 DATA (both directions), 32 + n bytes, 1 <= n <= 1200

| Offset | Size | Field |
| ------ | ---- | ----- |
| 0 | 4 | header, `type = 0x05` |
| 4 | 4 | `rid`: receiver's id (`sid` client to server, `cid` server to client) |
| 8 | 8 | `ctr`: sender's packet counter, 1 <= ctr < 2^63 |
| 16 | n + 16 | `ChaCha20-Poly1305.Seal(k_dir, nonce(ctr), kcp_packet, AD = bytes 0-15)` |

`nonce(c) = 0x00000000 || uint64be(c)` (12 bytes). Counter 0 is never used
for DATA or CLOSE: under `k_s2c` it is the ACCEPT tag's nonce, and under
`k_c2s` it is simply skipped. Receivers drop `ctr == 0` and `ctr >= 2^63`.

Sizes: the KCP MTU is 1200 on every session, set before any packet is read
or written (section 8.5), so DATA is at most 1232 bytes, which fits the IPv6
minimum MTU (1280 - 40 - 8). `MaxKCPPacket` equals `KCPMTU`; there is no
larger allowance, because no session ever runs at kcp-go's default MTU.

### 6.6 CLOSE (both directions), 32 bytes

| Offset | Size | Field |
| ------ | ---- | ----- |
| 0 | 4 | header, `type = 0x06` |
| 4 | 4 | `rid` |
| 8 | 8 | `ctr` (the same counter space as DATA) |
| 16 | 16 | `ChaCha20-Poly1305.Seal(k_dir, nonce(ctr), "", AD = bytes 0-15)` |

CLOSE goes only to the peer of an existing path, so it is never sent to an
unverified address. The `type` byte is in the AD, so a DATA packet cannot be
turned into a CLOSE.

## 7. Cryptography

Primitives already in the dependency set: `crypto/ecdh` X25519,
`crypto/hmac` with `crypto/sha256`, `crypto/sha512`, `crypto/hkdf` (Go
1.24 and later), `golang.org/x/crypto/chacha20poly1305`, and `hash/maphash`
(limiter slots, section 9.2).

### 7.1 Cookie

```
secret  = 32 random bytes, drawn once in NewServer, never persisted
addr    = As16(src_ip.Unmap()) (16 bytes) || uint16be(src_port)
mac     = HMAC-SHA256(secret,
            "kamune udp cookie v1" || uint32be(t) || cid || addr)[:16]
```

- The input has a fixed length after a fixed label; the label carries the
  version.
- A cookie is valid if and only if the MAC matches (`hmac.Equal`) and
  `now - 10 <= t <= now + 1` (seconds, server clock).
- No rotation: the MAC covers `t` and the window is 11 s, which already
  gives the return-routability property. A leaked secret lets an attacker
  create HALF_OPEN paths for forged sources but not finish them (ACCEPT goes
  to the forged address), and a memory disclosure that leaks the secret also
  leaks the Ed25519 identity. A restart draws a new secret; clients repeat
  HELLO.
- Binding `cid` ties INIT to the HELLO attempt; binding address and port is
  the return-routability proof. The listener's own address is not bound,
  because the secret is per listener.

### 7.2 Path keys

```
th      = SHA-512("kamune udp path v1" || cid || cookie || c_eph
                  || sid || s_eph)
shared  = X25519(own_eph_priv, peer_eph_pub)
          // crypto/ecdh rejects the all-zero result
prk     = HKDF-Extract(SHA-512, salt = th, ikm = shared)
k_c2s   = ExpandLabel(prk, "c2s", 32)
k_s2c   = ExpandLabel(prk, "s2c", 32)

ExpandLabel(s, label, L) = HKDF-Expand(SHA-512, s,
    uint16be(L) || uint8(len(l)) || l || 0x00, L)
    where l = "kamune udp " || label
```

This is the TLS 1.3 `HkdfLabel` layout (RFC 8446 7.1) with an empty
context; the transcript is in the salt. The label `"binding"` is reserved
for a later channel binding (section 15) and is not derived now. Ephemeral
private keys are fresh per path on both sides and dropped once the keys are
derived; the client keeps its `c_eph` private key only until ACCEPT is
verified or the attempt is abandoned.

**Scope of these keys.** The path keys protect the integrity, replay
resistance and availability of KCP packets, and hide KCP headers from
passive observers. They are classical X25519 only. They are not a
confidentiality layer for kamune: every kamune frame is protected end to end
by RFC007's hybrid post-quantum handshake, and no other layer may rely on
the path keys for confidentiality or identity hiding. SPEC §9.2 states this.

Why no ML-KEM here: it adds no confidentiality (above), and the costs are
real. An ML-KEM-768 encapsulation key is 1184 bytes, so INIT would grow past
the 1232-byte IPv6 budget and need fragmentation or a third round trip, and
every path would pay a second KEM on top of RFC007's. Amplification is not
the reason: ACCEPT goes only to a cookie-verified address.

### 7.3 DATA and CLOSE protection, replay

- Sender: `ctr = p.sendCtr.Add(1)` (`atomic.Uint64`, one per path and
  direction). When `ctr >= 2^63` the path closes and `WriteTo` returns
  `ErrPathClosed`.
- Receiver (the reader goroutine of the path's socket, section 8.1): look up
  `rid`; check that the source equals the path address; check `ctr` against
  the window; open; only then update the window. The window is 2048 packets
  (a bitmap of 32 `uint64`, RFC 6479): drop if `ctr + 2048 <= highest` or
  the bit is set.
- The AEAD also encrypts the KCP header (`conv`, `cmd`, `sn`, `una`, `wnd`),
  which hides it from passive observers and stops on-path tampering. No
  claim is made about content confidentiality (section 7.2).

### 7.4 Knock MAC (optional)

```
mac1    = HMAC-SHA256(k_knock, "kamune udp knock v1" || covered)[:16]
covered = bytes 0-7 of HELLO, or bytes 0-59 of INIT
```

`k_knock` is a 32-byte key that both peers hold, set with
`UDPWithKnockKey`. For P2P it comes from RFC010's per-pair punch key
(section 13). A sender with a key fills `mac1`; a sender without one sends
zeros. A receiver with a key checks `mac1` first (`hmac.Equal`) and drops on
mismatch before any other work; a receiver without a key ignores the field.
This is WireGuard's `mac1`: the responder ignores packets from parties that
do not know a pre-shared value. It stops scanners and hosts that share the
peer's IP (CGNAT) from getting a COOKIE. It does not stop an on-path
observer, who can replay a HELLO from its own address; that observer gains
nothing beyond what section 11 grants it.

## 8. State Machines

### 8.1 Socket reader (server and client)

One goroutine per socket owns all reads. It never returns an error to
kcp-go; kcp-go only ever sees a path's `ReadFrom`.

```
buf = make([]byte, 65536)          // one per socket
loop:
    n, from, err = pc.ReadFrom(buf)
    if err != nil:
        if layer closing: return
        if errors.Is(err, net.ErrClosed):   // socket closed under us
            close every path (reason ErrPathClosed); return
        stats.ReadErrors++; consecutive++
        if consecutive >= 64: sleep(backoff)  // 5 ms doubling to 1 s
        continue
    consecutive = 0; backoff = 0
    src = from.(*net.UDPAddr).AddrPort() with Addr().Unmap()  // else drop
    pkt = buf[:n]
    if n == 0 or pkt[0] == 0x00: Kick++; continue
    if pkt[0] > 0x0F: Foreign++; continue
    validate header, exact length, non-zero ids; else Malformed++; continue
    dispatch by type (8.2 server, 8.3 client)
```

All read errors other than a closed socket are transient: `WSAEMSGSIZE`,
`WSAECONNRESET`, `ECONNREFUSED`, `ENOBUFS`, `io.ErrShortBuffer`, and
deadline errors set by a careless caller. The 65,536-byte buffer holds any
UDP datagram, so an oversize datagram is read whole and dropped by the
length check instead of turning into an error on Windows. The client reader
clears any read deadline once the handshake ends (section 8.3).

### 8.2 Server

Goroutines: the reader (section 8.1), one handshake worker, and one 1 s
sweep ticker. Accepted paths add kcp-go's per-session goroutines.

**Locking.** One `sync.Mutex` guards the path table (`byID`, `byInit`, the
per-source and per-network counts, the pending list, the accept queue) and
each path's `state`. It is held for lookups, inserts and removals, never for
AEAD or X25519 work. The handshake worker is the only goroutine that inserts
paths; others only remove them. `Stats` fields are `atomic.Uint64`, and
`Stats()` returns a snapshot. A path's replay window belongs to the reader.

**Reader dispatch.**

```
HELLO, INIT:
    if closing: drop
    copy into a pooled 1200-byte buffer; push to hsQueue (cap 256);
    if full: HandshakeDropped++ (the client retransmits)
DATA, CLOSE:
    p = byID[rid] (under lock); if p == nil or p.addr != src: NoPath++; drop
    if !p.win.check(ctr): Replay++; drop
    open (fail: BadTag++; drop); p.win.update(ctr); p.lastRecv = now
    if CLOSE: p.close(peerClosed); continue
    if p.state == HALF_OPEN (under lock, re-checked):
        p.state = QUEUED; p.queuedAt = now; push p to acceptQ
    push plaintext (pooled buffer) to p.in (cap 128); if full: InboundDropped++
COOKIE, ACCEPT: Unexpected++; drop
```

`acceptQ` has capacity `MaxPending`, and pending paths never exceed
`MaxPending`, so the push never blocks.

**Handshake worker.**

```
HELLO:
    if knock key and mac1 bad: KnockFail++; drop
    if Allow != nil and !Allow(src): Filtered++; drop
    send COOKIE(cid, now, mac(src, cid, now)) to src   // stateless
INIT:
    if knock key and mac1 bad: KnockFail++; drop
    if Allow != nil and !Allow(src): Filtered++; drop
    if !validCookie(cookie, src, cid): BadCookie++; drop
    sweep(now)                                         // expire first
    lock
    if p = byInit[(src, cid)]:
        if p.cEph == c_eph and not p.closed: resend p.acceptBytes to src
        unlock; drop
    if !initRate.Allow(SourceKey(src)): RateLimited++; unlock; drop
    if pendingFrom(SourceKey(src)) >= MaxPendingPerSource
       or pathsFrom(SourceKey(src)) >= MaxPathsPerSource
       or pathsFrom(NetworkKey(src)) >= MaxPathsPerNetwork:
        PathsFull++; unlock; drop
    unlock
    generate s_eph, sid; X25519 (error -> drop); derive keys; build ACCEPT
    lock
    if closing: unlock; drop
    if pending >= MaxPending: v = victim(pending scope, src); close v (Evicted)
    if paths >= MaxPaths:     v = victim(all scope, src);     close v (Evicted)
        (if a victim rule picks the new INIT itself: PathsFull++; drop)
    ensure sid unique in byID (draw again on collision)
    insert p{state HALF_OPEN, addr src, cid, sid, cEph, keys, acceptBytes,
             createdAt now} into byID, byInit, counts, pending list
    unlock; send ACCEPT
```

Admission checks run before anything is removed, and an INIT that a cap
refuses removes nothing. A retransmitted INIT is answered from `byInit`
before the rate limiter, so retransmits never use up tokens. Several paths
may share one address (the same socket dialing twice, or a client that
restarted): each is its own kcp-go session and they never mix, because DATA
is routed by `rid` and each kcp-go session writes only to its own `*Path`.
There is no takeover rule between paths of one address.

**Victim selection.** A layer-local rule of about 30 lines;
`Server.dropCandidateLocked` in `server.go` is not touched. Count paths per
`NetworkKey` within the scope, the new INIT counted; take the networks with
the highest count; pick one of them at random. Pending scope: drop that
network's oldest HALF_OPEN path, else its oldest QUEUED path. All scope:
drop its oldest path in any state. If the pick is the new INIT's network and
that network holds no existing path in scope, the new INIT is dropped
instead.

**Sweep.** Runs on the 1 s ticker, at the start of INIT handling, and in
`Accept`: close HALF_OPEN paths older than 5 s and QUEUED paths older than
10 s since `queuedAt` (reason `Expired`).

**Accept.**

```
loop:
    select p = <-acceptQ:
        lock
        if p.closed or now - p.queuedAt > 10 s:
            unlock; p.close(Expired); continue
        p.state = ACCEPTED; unlock; return p
    case <-done: return nil, ErrListenerClosed (wraps net.ErrClosed)
```

**Path removal** (`p.close(reason)`, idempotent): remove the path from the
table and the counts; close `p.done`, so that `ReadFrom` returns
`ErrPathClosed` once `p.in` is drained; unless the reason is `peerClosed`,
send CLOSE twice back to back (two counters). Reasons: `Expired`, `Evicted`,
`peerClosed`, `localClose` (the kcp-go session closed), `Shutdown`.

**Close** (`Server.Close`, idempotent): set closing; close `done` (Accept
returns); close every HALF_OPEN and QUEUED path at once (reason `Shutdown`,
which sends CLOSE); stop the handshake worker and the ticker. If no ACCEPTED
path is left, close the socket now; otherwise close it when the last
ACCEPTED path closes. Until then the reader keeps serving ACCEPTED paths,
and HELLO and INIT are dropped. The UDP port therefore stays bound until the
last handed-off session ends; `ServeWithUDP` documents this. Live sessions
keep working, which matches the documented `Server.Close` contract.

Path states:

| State | Entered on | Leaves on | Counts against |
| ----- | ---------- | --------- | -------------- |
| HALF_OPEN | valid INIT | first valid DATA (to QUEUED); 5 s; evicted; CLOSE; Close | pending, per-source pending, all caps |
| QUEUED | first valid DATA | `Accept` (to ACCEPTED); 10 s; evicted; CLOSE; Close | pending, per-source pending, all caps |
| ACCEPTED | `Accept` returned it | kcp-go session closed (`Path.Close`); CLOSE from the peer; evicted at `MaxPaths` | `MaxPaths`, per-source, per-network |

An ACCEPTED path has no idle timeout; an idle kamune session must survive.
Its end is driven by kamune (`Conn.Close`), by the peer's CLOSE, or by
eviction at the memory backstop.

### 8.3 Client (dialer)

`Dial` runs the handshake on the caller's goroutine, reading `pc` with read
deadlines, and clears the deadline before it returns, on success and on
every error.

```
start: check raddr (8.6); pick random non-zero cid; send HELLO; HELLO_SENT
HELLO_SENT:
    COOKIE from raddr with matching cid -> store cookie, cookieAt = now,
        helloBudget = 5, new c_eph, send INIT, INIT_SENT (tries = 1)
    timer -> if helloBudget > 0: resend HELLO; helloBudget--
             else: send nothing, wait for ctx
INIT_SENT:
    ACCEPT from raddr, matching cid, tag verifies -> derive keys, ESTABLISHED
    ACCEPT with bad tag -> drop (stay)
    COOKIE -> drop
    timer -> if tries == 3 or now - cookieAt > 8 s:
                 new cid, send HELLO, HELLO_SENT (helloBudget counts this send)
             else resend the same INIT bytes, tries++
any state: ctx done ->
    DeadlineExceeded: return fmt.Errorf("%w: %w", ErrUDPHandshakeTimeout, err)
    otherwise:        return fmt.Errorf("udp path handshake: %w", err)
ESTABLISHED: start the reader (8.1) for pc; return the *Path
```

Timers: HELLO at 0, 0.5, 1.5, 3.5 and 7.5 s (500 ms doubling, no ceiling),
so at most 5 HELLOs (6,000 bytes) go to an address that has not answered
with a COOKIE; the budget refills on each COOKIE. INIT retransmit: 250 ms
doubling to a 2 s ceiling. The HELLO schedule spans the 10 s hole-punch
window, which covers the direct-P2P listener's NAT kicks every 2 s for 10 s
(bus `kickFor`, daemon `natKickLoop`, both in `directp2p.go`). On broker
P2P the listener kicks after each match: today the bus kicks for 10 s
(`kickFor`) and the daemon sends one burst, and under RFC011 the listener
kicks `Match.Peer` when the match arrives (RFC011 §11.3). HELLO
retransmissions double as the dialer's NAT kicks, so the dialer no longer
calls `sendNATKick`.

Client reader dispatch after ESTABLISHED: DATA and CLOSE from `raddr` with
`rid == cid` go through the same input step as on the server (section 8.2);
everything else is dropped and counted.

### 8.4 Path as `net.PacketConn`

```
ReadFrom(b): wait for Start; then select p.in (copy, return the pooled buffer,
             return n and p.raddrUDP) or p.done (drain p.in first, then
             return ErrPathClosed)
WriteTo(b, _): 1 <= len(b) <= KCPMTU else error; ErrPathClosed if closed;
             seal into a pooled 1500-byte buffer; pc.WriteTo(raddr)
Close():     server: p.close(localClose)
             client: p.close(localClose), then close pc (stops the reader)
```

`ReadFrom` always returns the same `*net.UDPAddr` (the unmapped path
address), which is the `raddr` given to `kcp.NewConn4`, so kcp-go's
same-source check (`sameUDPAddr` in `readloop.go`) passes. A write error
from `pc.WriteTo` is returned as is; kcp-go then fails the session through
`notifyWriteError`.

### 8.5 kcp-go session setup and close (root package)

```
p := ...  // srv.Accept() or udppath.Dial(...)
sess, _ := kcp.NewConn4(p.Conv(), p.RemoteUDPAddr(), nil, 0, 0, true, p)
sess.SetMtu(udppath.KCPMTU)
p.Start()
conn := newPathConn(sess, p, connOpts...)
```

- The KCP `conv` is `cid` on both ends. kcp-go drops segments with another
  `conv` (`ikcp_input`), and there is no listener to reset.
- `ownConn = true`: `UDPSession.Close` calls `Path.Close`, which removes the
  path and sends CLOSE.
- `Start` after `SetMtu` guarantees that no packet is read or written at
  kcp-go's default MTU of 1400 (`IKCP_MTU_DEF`).

**Close linger.** `Transport.Close` sends `RouteCloseTransport` and then
closes the `Conn`; over KCP the send returns once the frame is in kcp-go's
send queue. `UDPSession.Close` flushes once and stops retransmitting.
`pathConn.Close` therefore waits `clamp(3 * sess.GetSRTT(), 50 ms, 1 s)`
before `sess.Close()`, unless a read or write on the session already failed.
kcp-go v5.6.72 does not export the send queue length on `UDPSession`, so
SRTT is the only signal. The close frame over UDP stays best effort: if it
is lost, the peer still gets CLOSE (sent twice) and reports `ErrConnClosed`;
if both are lost, the peer's read deadline (5 min by default, set in
`newConn` in `conn.go`) ends the session.

### 8.6 Dial target check

`udppath.Dial` refuses, with `ErrBadAddr`, an unspecified address, a
multicast address, `255.255.255.255`, and port 0. Loopback and link-local
targets are allowed, because tests and LAN P2P use them. Refusing peer
addresses that should not come from a broker match is the job of RFC011's
match address filter, since only a broker match can come from an untrusted
party.

## 9. Go API

### 9.1 `internal/udppath` (new)

```go
package udppath

const (
    Version            = 0x01
    HelloSize          = 1200
    InitSize           = 1200
    CookieSize         = 28
    AcceptSize         = 60
    CloseSize          = 32
    DataOverhead       = 32
    KCPMTU             = 1200
    MaxDatagram        = KCPMTU + DataOverhead // 1232
    CookieLifetime     = 10 * time.Second
    HalfOpenTimeout    = 5 * time.Second
    QueuedTimeout      = 10 * time.Second
    ReplayWindow       = 2048
    MaxHellos          = 5
    HandshakeQueue     = 256
    PathInbound        = 128
)

type Limits struct { // zero field = default; negative = no limit (per-* only)
    MaxPaths            int // default 4096, eviction (section 8.2)
    MaxPathsPerSource   int // default 32
    MaxPathsPerNetwork  int // default 128
    MaxPending          int // default 256, eviction (section 8.2)
    MaxPendingPerSource int // default 4
    InitRate            admit.Rate // per source; default {4, 8}
}

type Config struct {
    Clock    clock.Clock                    // internal/clock; Real() if nil
    Allow    func(from netip.AddrPort) bool // server only; nil = all
    KnockKey []byte                         // nil or 32 bytes
    Limits   Limits                         // server only
}

type Server struct{ /* ... */ }

// NewServer starts the reader, the handshake worker and the sweep ticker.
func NewServer(pc net.PacketConn, cfg Config) (*Server, error)
func (s *Server) Accept() (*Path, error)    // ErrListenerClosed after Close
func (s *Server) Close() error              // section 8.2
func (s *Server) Addr() net.Addr
func (s *Server) Stats() Stats

// Dial runs the client side of the path handshake. On error pc stays the
// caller's, with its read deadline cleared.
func Dial(ctx context.Context, pc net.PacketConn, raddr netip.AddrPort,
    cfg Config) (*Path, error)

// Path is a net.PacketConn bound to one peer.
type Path struct{ /* ... */ }
func (p *Path) ReadFrom(b []byte) (int, net.Addr, error)
func (p *Path) WriteTo(b []byte, _ net.Addr) (int, error)
func (p *Path) Close() error
func (p *Path) LocalAddr() net.Addr
func (p *Path) SetDeadline(time.Time) error      // no-op, nil
func (p *Path) SetReadDeadline(time.Time) error  // no-op, nil
func (p *Path) SetWriteDeadline(time.Time) error // no-op, nil
func (p *Path) Start()
func (p *Path) Conv() uint32                     // cid
func (p *Path) RemoteAddr() netip.AddrPort
func (p *Path) RemoteUDPAddr() *net.UDPAddr      // the value ReadFrom returns
func (p *Path) Stats() Stats                     // client paths: socket stats

type Stats struct { // snapshot of atomic counters, for tests
    Hello, CookieSent, BadCookie, KnockFail, Filtered, RateLimited,
    PathsFull, Evicted, Expired, HandshakeDropped, BadTag, Replay, NoPath,
    InboundDropped, Malformed, Unexpected, Kick, Foreign, ReadErrors,
    CloseSent, CloseReceived uint64
}

var (
    // ErrPathClosed wraps net.ErrClosed so kamune's isConnDrop matches it.
    ErrPathClosed     = fmt.Errorf("udp path closed: %w", net.ErrClosed)
    ErrListenerClosed = fmt.Errorf("udp path listener closed: %w",
        net.ErrClosed)
    ErrBadAddr        = errors.New("udp path: address cannot be dialed")
)
```

There is no periodic `Stats` log; `Stats` exists for tests and debugging.
`isConnDrop` in `transport.go` already lists `net.ErrClosed` among
`connDropErrors`, so a closed path surfaces as `ErrConnClosed`.

### 9.2 `internal/admit` (new)

```go
package admit

// SourceKey: IPv4 address, or IPv6 /64. NetworkKey: IPv4 /24, IPv6 /48.
// Moved unchanged from server.go (sourceKey, networkKey, prefixKey, hostIP).
func SourceKey(addr net.Addr) string
func NetworkKey(addr net.Addr) string
func SourceKeyAddrPort(ap netip.AddrPort) string
func NetworkKeyAddrPort(ap netip.AddrPort) string

type Rate struct {
    PerSecond float64 // 0 disables
    Burst     int
}

// Limiter is a fixed array of token buckets indexed by
// maphash.String(seed, key) % slots, with a random per-process seed.
// Memory is constant (16 bytes per slot); there is no map, no sweep and no
// overflow branch. A collision only makes two keys share one bucket, which
// is stricter, never looser. Safe for concurrent use (one mutex).
type Limiter struct{ /* ... */ }
func NewLimiter(r Rate, slots int, clk clock.Clock) *Limiter
func (l *Limiter) Allow(key string) bool
```

`hash/maphash` with a random seed is unpredictable to an attacker, who
therefore cannot aim collisions at a victim's slot; it is in the standard
library and costs tens of nanoseconds. A bucket is
`{tokens float32; last int64}`, refilled from `clk.Now()`, so tests drive it
with `clock.Fake`.

### 9.3 Root package `kamune`

```go
// errors.go
var ErrUDPHandshakeTimeout = errors.New("udp path handshake timed out")

// udp.go (new)
type UDPOption func(*udpConfig) error

func UDPWithConnOptions(opts ...ConnOption) UDPOption
func UDPWithSourceFilter(fn func(from netip.AddrPort) bool) UDPOption
func UDPWithKnockKey(key []byte) UDPOption // 32 bytes, else error
func UDPWithPathLimits(l UDPPathLimits) UDPOption

type UDPPathLimits struct { // same meaning and defaults as udppath.Limits
    MaxPaths, MaxPathsPerSource, MaxPathsPerNetwork int
    MaxPending, MaxPendingPerSource                 int
}

// ListenUDP runs the path layer on pc and returns a Listener for
// ServeWithListener. It takes over reading and closing pc and clears its
// deadlines first; callers may still call pc.WriteTo (NAT kicks). On error
// pc stays the caller's.
func ListenUDP(pc net.PacketConn, opts ...UDPOption) (Listener, error)

// DialUDP runs the path handshake to raddr on pc and starts a KCP session.
// It returns an error wrapping ErrUDPHandshakeTimeout when ctx's deadline
// passes first. On error pc stays the caller's with its read deadline
// cleared; on success pc belongs to the returned Conn.
func DialUDP(ctx context.Context, pc net.PacketConn, raddr netip.AddrPort,
    opts ...UDPOption) (Conn, error)

// server.go, signature change: ConnOption... -> UDPOption...
func ServeWithUDP(opts ...UDPOption) ServerOptions
// dial.go, signature change; the dial timeout bounds the path handshake
func DialWithUDP(opts ...UDPOption) DialOption

// server.go, new (KAM-05)
type RateLimit struct {
    PerSecond float64 // 0 disables this level
    Burst     int
}
func ServeWithHandshakeRate(source, network, global RateLimit) ServerOptions
```

`ServeWithUDP` binds `s.addr` with `net.ListenUDP("udp", ...)` and calls
`ListenUDP`. The `kcp.Listen` call goes, and so does today's `udpListener`
in `server.go`, which wraps kcp-go's listener as a `net.Listener`.
`DialWithUDP` resolves the address, opens `udp4` for an IPv4 target and
`udp` otherwise, and calls `DialUDP` with a context bounded by
`DialWithDialTimeout` (default 10 s).

`ListenUDP` returns a new unexported type in `udp.go`, `pathListener`,
which wraps the `*udppath.Server`. `pathListener.Accept`:
`p, err := srv.Accept()`, then the setup of section 8.5, then return the
`pathConn`. `pathListener.Close` calls `srv.Close` (section 8.2).
`pathConn` embeds the kamune `conn` adapter, implements the close linger
(section 8.5) and `ReturnRoutable() bool { return true }`, and reports
`RemoteAddr()` as `p.RemoteUDPAddr()`.

A path conn satisfies the connection contract of SPEC §9.4: kcp-go still
delivers frames reliably, in order and without duplicates, and the KCP MTU
of 1200 only changes how a frame of up to `maxFrameSize` (65,471 bytes,
SPEC §4.1) is split into segments.

### 9.4 Server changes for KAM-05

**Return routability is structural.** `forgeable` stays, but it no longer
looks at the address type:

```go
// conn.go: unexported
type returnRoutable interface{ ReturnRoutable() bool }

// (*conn).ReturnRoutable is true when the wrapped net.Conn is a
// *net.TCPConn or *net.UnixConn, or implements returnRoutable and says so.
// pathConn returns true.

// server.go: replaces forgeableAddr(addr)
p.forgeable = !isReturnRoutable(cn)
```

A connection with an address but without return routability (a custom
`Listener` that wraps raw kcp-go, a test conn) keeps today's rule: it
counts against the per-source cap only once the dialer has shown that it
receives the server's replies (today at the introduction; after RFC007, on
entering the authenticated stage). Path connections and TCP count at
accept. Relay connections report no address and are not counted per
source. `NewConn` stays exported (the TUI's relay entry point in
`cmd/tui/client.go` uses it); its doc drops "P2P hole-punched sockets" and
says that wrapped conns are treated as forgeable unless they implement
`ReturnRoutable`.

**Handshake rate.** Checked first in `admit`, before the conn is recorded
and before any KEM work. Three levels, all `admit.Limiter`:

| Level | Key | Default | Slots |
| ----- | --- | ------- | ----- |
| source | `SourceKey` (IPv4, IPv6 /64) | 8/s, burst 16 | 65,536 |
| network | `NetworkKey` (IPv4 /24, IPv6 /48) | 32/s, burst 64 | 16,384 |
| global | one bucket | `512 * GOMAXPROCS`/s, burst twice that | 1 |

A conn that is forgeable or has no address uses no source or network key of
its own: it is checked against the network-level bucket under the fixed key
`"addressless"`, then against the global bucket. A spoofer therefore cannot
drain a real host's bucket through a forgeable listener. Over any limit,
`admit` returns false, the caller closes the conn, and a `slog.Debug` line
names the level. `RateLimit{}` disables a level; a negative value is an
error. Memory is about 1.3 MiB, allocated on the first `admit`.

The global default is sized from RFC007's cost of one X-Wing encapsulation
and one Ed25519 signature per ClientHello (KAM-05 measured 615 µs per server
handshake on the current protocol): 512/s per core keeps handshake work at
about a third of the machine.

## 10. Limits and Timeouts

| Name | Value | Where |
| ---- | ----- | ----- |
| HELLO, INIT size | 1200 B | wire |
| COOKIE, ACCEPT, CLOSE size | 28 B, 60 B, 32 B | wire |
| DATA size | 33 to 1232 B | wire |
| KCP MTU | 1200 | `SetMtu` before `Start` |
| Read buffer | 65,536 B per socket | section 8.1 |
| Read error backoff | after 64 in a row, 5 ms doubling to 1 s | section 8.1 |
| Cookie validity | `now-10 s <= t <= now+1 s` | server |
| Cookie secret | one per listener, no rotation | server |
| HALF_OPEN timeout | 5 s | server |
| QUEUED timeout | 10 s | server |
| Handshake queue | 256 packets, drop when full | server |
| Path inbound queue | 128 packets, drop when full | both |
| Max paths (all states) | 4096, evict from the network with most | server |
| Max paths per source / per network | 32 / 128 | server |
| Max pending (HALF_OPEN + QUEUED) | 256, evict from the network with most | server |
| Max pending per source | 4 | server |
| INIT rate per source | 4/s, burst 8 | server |
| Handshake rate: source / network / global | 8/s b16 / 32/s b64 / 512*GOMAXPROCS/s b2x | `Server` |
| HELLO schedule | 0, 0.5, 1.5, 3.5, 7.5 s; at most 5 before a COOKIE | client |
| INIT retransmit | 250 ms doubling to 2 s; 3 tries or cookie older than 8 s | client |
| Replay window | 2048 packets | both |
| Close linger | `clamp(3 * SRTT, 50 ms, 1 s)` | root |
| CLOSE copies | 2 | both |
| Hole-punch dial timeout (bus, daemon) | 10 s | clients |

The existing `Server` limits stay: the waiting cap of 256 with network
eviction, 16 per source, the 10 s introduction timeout, and the accept
backoff of 5 ms to 1 s.

State an attacker can cause: a kcp-go session exists only for an ACCEPTED
path, and a path needs a real, reachable address. Pending paths are capped
at 256 and live at most 15 s; all paths are capped per source, per network
and in total, and the total cap evicts from the largest network instead of
refusing new dialers.

## 11. Security Considerations

**Off-path attacker who can forge source addresses** (the KAM-11 and KAM-05
attacker).

- HELLO from a forged source: one HMAC and 28 bytes to the forged address; a
  reflector with 43:1 attenuation, not an amplifier. No state. A flood fills
  the handshake queue at worst; DATA is handled by the reader, never behind
  handshake work.
- INIT with a forged source: it needs a cookie MACed for that address, which
  went to that address. Dropped after one HMAC.
- DATA or CLOSE with a forged source: there is no path with that `rid` and
  address, or the tag fails. A raw KCP packet (KAM-11's 24-byte
  `conv`/`sn = 0` reset, or a 12-byte packet typed as FEC OOB) fails the
  header and length checks or the same lookup and tag check. Dropped;
  kcp-go never sees it, and with no kcp-go `Listener` there is no reset
  branch to reach.
- Any datagram, of any size, to any kamune UDP socket: read whole into a
  65,536-byte buffer or reported as a transient error; it never ends a
  session.
- Forged COOKIE to a dialer: needs the 32-bit `cid`; at worst one INIT round
  fails and the dialer retries. Forged ACCEPT: needs `c_eph`. Forged DATA or
  CLOSE to the dialer: the tag fails.
- Forged sources no longer reach the server's waiting cap or per-source
  counts: a path conn exists only after a completed path handshake, and any
  other conn without `ReturnRoutable` is counted as forgeable.

**Attacker with many real addresses** (botnet, IPv6 prefixes). Per-source
and per-network caps bound what each address and each /24 or /48 holds. At
`MaxPaths` the layer evicts from the network that holds the most paths, so a
dialer from a quiet network still gets in. The handshake rate limits KEM
work per /64, per /48 and in total; an attacker who uses up the global rate
causes refused handshakes instead of CPU exhaustion (the residual of
section 3).

**Attacker who aims a dialer at a victim** (a forged or replayed broker
match, RC-05, REL-12). The dialer sends at most 5 HELLOs (6,000 bytes) to an
address that never answers. Today's dialer (bus and daemon `HolePunch`,
`directP2PDial`) sends a 5-byte kick burst and then returns a kcp-go
session, on which the kamune handshake at once writes its first frame, the
1,216-byte MLKEM768-X25519 HPKE public key (SPEC §6.1, KAM-05). kcp-go
retransmits that segment to the unanswering address until the 30 s
handshake timeout ends, several kilobytes in all. RFC011 authenticates
matches, which removes the forged-match trigger.

**On-path attacker that reads traffic and sends with the peer's exact
address.** What it can still do:

- Drop, delay or reorder packets (DoS, as with TCP).
- Race the dialer's path setup: read the COOKIE and send its own INIT with
  the same `cid` first. The server drops the real INIT (`cid` matches,
  `c_eph` differs); the dialer restarts with a new `cid` after 3 tries. DoS
  only; the attacker's path carries only its own kamune handshake.
- Act as a path-layer MITM from the start (separate path handshakes with
  each end). It can read and alter KCP headers and drop or reorder kamune
  frames, which stay authenticated and encrypted end to end. DoS only.
- Replay a HELLO from its own address to get past a knock key. It gains a
  COOKIE for its own address, nothing more.

What it can no longer do: inject or reset KCP on a path it did not set up,
replay DATA or CLOSE (window), or end a path it did not set up.

**Not covered.** NAT rebinding: a path is bound to one address and port; a
dialer whose mapping changes loses the path and resumes the kamune session
on a new one. HELLO and INIT are fixed-size and easy to fingerprint; stealth
is not a goal of the direct UDP transport. A server restart is learned only
by the peer's read deadline or its next write timing out (no stateless
reset, section 15).

**Scope of the path keys.** See section 7.2: classical, no confidentiality
claim, and no other layer may rely on them.

## 12. Client Changes

Order: this RFC's `bus:` and `daemon:` commits land after the client commits
of RFC009, RFC011 and RFC010 in the same files (`broker.go`,
`p2plistener.go`, `directp2p.go`, `network.go`) and change only the KCP
lines. By then RFC011's `Endpoint` owns every broker punch socket and
consumes the broker's datagrams, which replaces the broker half of bus
`punchFilter` and daemon `punchConn`. When the RFC011, RFC010 and RFC008
client changes are made together, they go in one commit series.

### 12.1 bus (`cmd/bus`)

- `directp2p.go`:
  - `newDirectP2PListener`: replace `kcp.ServeConn(nil, 0, 0, l.filter)` and
    the `punchFilter` with:

    ```go
    kamune.ListenUDP(conn,
        kamune.UDPWithSourceFilter(isPeerIP),
        kamune.UDPWithKnockKey(k))
    ```

    `isPeerIP` accepts the IP of `peerAddr`, any port, as the filter does
    today: the dialer binds port 0, so its source port is never known in
    advance. `k` is RFC010's punch key (`PairKey.PunchKey()`, section 13),
    set only when the peer key is known; without one, the option is left
    out. The kick loop (`kickFor`) stays; it writes 1-byte `0x00` kicks with
    `conn.WriteTo`. `Accept` returns the inner listener's `kamune.Conn`;
    `Close` closes only the inner listener.
  - `directP2PDial`: drop `sendNATKick` and `kcp.NewConn4`; call
    `kamune.DialUDP(ctx, conn, peer, kamune.UDPWithKnockKey(k))` with a 10 s
    context derived from the attempt's context. On error, close `conn` and
    return an error wrapping `ErrHolePunchFailed`.
- `p2plistener.go`: RFC011's endpoint owns the punch socket
  (`brokerClient.NewEndpoint(conn)`); pass `ep.PacketConn()` to
  `kamune.ListenUDP`. Broker traffic (REGISTER refresh replies,
  PEER_MATCHED) is consumed by the endpoint before the path layer sees it.
  The deadline reset before `serve`, `serve`/`serveWith`, and the
  `heldSession` wrapper go. `Close` first closes every broker `Registration`
  (WITHDRAW, RFC011), then the kamune listener, which closes the endpoint's
  `PacketConn` and with it the endpoint once the last path ends. No knock
  key here: one listener socket serves every contact registered on it, and
  `UDPWithKnockKey` takes one key per listener. Whether the listener keeps a
  source filter fed from RFC011's `Match.Peer` is open question 1
  (section 20).
- `broker.go` `HolePunch`: today it takes no timeout and returns at once. It
  becomes a call that returns `(kamune.Conn, error)` from
  `kamune.DialUDP(ctx, ep.PacketConn(), peer, ...)` and takes a timeout
  (`timeout <= 0` means `DefaultHolePunchTimeout`, as in the daemon). Add
  `DefaultHolePunchTimeout` (10 s) and `ErrHolePunchFailed` to the bus; drop
  `sendNATKick` from the dial side, the conv id and `kcp.NewConn4`. Wrap
  failures in `ErrHolePunchFailed`, so `ConnectToServer` returns
  `hole_punch_failed` and the relay-fallback dialog opens within the punch
  timeout instead of after the 30 s handshake timeout. Rewrite the doc
  comments that describe kcp-go dropping non-KCP frames.
- `dialattempt.go` `dialUDP`: today it calls `kcp.Dial` and wraps the
  session with `kamune.NewConn`. It becomes a function of the attempt's
  context, like `dialTCPWithin`: resolve the address, open `udp4` for an
  IPv4 target and `udp` otherwise, and call `kamune.DialUDP` under the
  attempt's context bounded by `dialTimeout`.
- `network.go`: `ConnectToServer` stops wrapping the `HolePunch` result with
  `kamune.NewConn`. The broker and direct P2P branches of `ConnectToServer`
  and the direct-P2P branch of its `reconnectFn` call `HolePunch` or
  `directP2PDial`, which now block for up to 10 s; the reconnect function
  must absorb the wait (it already runs off the UI goroutine).
  `StartServer`'s `kamune.ServeWithUDP()` and the reconnect function's
  `kamune.DialWithUDP()` compile unchanged (variadic).
- `go.mod`: `kcp-go` becomes indirect.

### 12.2 daemon (`cmd/daemon`)

- `directp2p.go`: as the bus. `newDirectP2PListener` gains the
  `UDPWithSourceFilter(isPeerIP)` filter it lacks today and the knock key;
  `natKickLoop` stays. `directP2PDial` gains a context parameter and calls
  `kamune.DialUDP` with a 10 s context, wrapping errors in
  `ErrHolePunchFailed`.
- `p2plistener.go`: as the bus. `kcp.ServeConn(nil, 0, 0, &punchConn{...})`
  becomes `kamune.ListenUDP(ep.PacketConn())`; `punchConn` goes (RFC011
  removes its broker half, this RFC its KCP half). Close order as the bus.
- `broker.go` `HolePunch`: it already honours its timeout; the timeout now
  bounds `DialUDP`, and `DefaultHolePunchTimeout` rises from 5 s to 10 s.
  The synchronous kick burst and `kcp.NewConn4` go; it returns a
  `kamune.Conn`, and every failure wraps `ErrHolePunchFailed` (today only a
  burst that sent no kick does).
- `network.go`: `dial` stops wrapping the `HolePunch` result with
  `kamune.NewConn`. The `p2p` and `direct-p2p` cases of `dial` and the
  direct-P2P branch of `makeReconnectFn` block for up to 10 s, including the
  reconnect path. `listenDirect` for `udp` binds with `net.ListenUDP` and
  returns `kamune.ListenUDP(pc)` instead of `kcp.Listen` wrapped in
  `boundListener`; it still reports the bound address from `pc.LocalAddr()`.
  The `udp` case of `dial` keeps `kamune.DialWithUDP()`.
- `DAEMON.md` transport table: the `udp` row reads "`listenDirect`
  (`kamune.ListenUDP`) + `ServeWithListener`" (it says `ServeWithUDP` today,
  which the daemon does not use); the `p2p` row reads "`newP2PListener`
  (`kamune.ListenUDP`) + `ServeWithListener`" (it also says `ServeWithUDP`
  today) and "`WaitMatch` + `HolePunch` (`kamune.DialUDP`) via
  `DialWithFunc`"; the `direct-p2p` row likewise.
- `go.mod`: `kcp-go` becomes indirect.

### 12.3 tui, relay

TUI: no change (TCP and relay only). Relay: no change; RFC011 keeps the
first byte of every broker datagram at `0x10` or above (`"KBRK"` already
is).

## 13. Interfaces With Other RFCs

- **RFC007 (handshake):**
  - This RFC owns the handshake rate limit (`ServeWithHandshakeRate`, in
    `admit`). RFC007 adds no limiter of its own and keeps `admit` ahead of
    the first KEM operation. KAM-05 is listed under this RFC only. RFC007
    keeps `admit`, splits `introduced` into `helloReceived` and
    `authenticated`, and adds no limiter, which matches.
  - RFC007's rule "a forgeable conn is counted on entering the
    authenticated stage (frame 0x04, InitiatorAuth, verified)" applies only
    to conns without `ReturnRoutable`; path conns are not forgeable and
    count at accept. `forgeable` keeps its name and meaning; only its
    computation changes (section 9.4).
  - RFC007 uses the path keys for nothing (section 7.2). No channel binding
    is asked of RFC007.
  - RFC007 gives the frame sizes the path carries (ClientHello 1282 B,
    ServerHello 1154 B plus ResponderAuth 214 B) and the per-ClientHello
    cost used to size the global rate (one X-Wing encapsulation, one
    Ed25519 signature).
- **RFC010 (tokens):** a per-pair 32-byte punch key that both P2P peers
  hold: `PairKey.PunchKey() [32]byte` (purpose `p2p-punch`, zero `svc`,
  `dir = 0x00`; no epochs). This RFC uses it as `k_knock` on direct P2P only
  (`directp2p.go`), where listener and dialer serve one known peer. Broker
  P2P listeners serve many contacts on one socket and run without a knock
  key. If RFC010 does not ship the key, the knock key is not wired in the
  clients; the layer and its tests do not depend on RFC010. RFC010's
  `ExpectPeer` wrappers stay around the conns that `ListenUDP` and
  `DialUDP` return.
- **RFC011 (broker):**
  - Every broker v2 datagram starts with a byte `>= 0x10` (`"KBRK"`);
    `0x00` is reserved for NAT kicks and `0x01`-`0x0F` for this layer.
    Written into SPEC §9.2 and RELAY.md.
  - Clients use RFC011's `Client.NewEndpoint(conn)` on every broker punch
    socket and pass `Endpoint.PacketConn()` to `ListenUDP` and `DialUDP`.
    That `PacketConn` must: honour read deadlines (`DialUDP` uses them);
    deliver every non-broker datagram of up to 1,500 bytes unchanged with
    its source (it drops larger ones; no path-layer packet exceeds 1,232
    bytes); return only `net.ErrClosed`-wrapped or deadline errors from
    `ReadFrom`; read the socket with a buffer of at least 65,536 bytes and
    treat other read errors as transient (the rule of section 8.1); and
    close the socket on `Close`.
  - RFC011 delivers an authenticated `Match{Peer, Self}` to listener and
    dialer, and drops a MATCHED whose `Peer` fails its match address filter.
    The listener may kick `Match.Peer` with a 1-byte `0x00` through
    `PacketConn().WriteTo`.
  - Neither RFC011's endpoint nor the broker replies to a packet it did not
    expect.
- **RFC009 (relay leg):** none. The relay leg is TCP or WebSocket and relay
  conns have no `RemoteAddr`; they use the `"addressless"` rate bucket
  (section 9.4).

## 14. Test Plan

All tests use `a := require.New(t)`, real implementations, and table-driven
cases where there are several. `internal/udppath/udptest` provides an
in-memory packet network: `udptest.Net`, `Net.Listen(addr) net.PacketConn`,
`Net.Inject(from, to, pkt)` (send from any source, which is how spoofing is
tested without raw sockets), and
`Net.SetFilter(func(from, to netip.AddrPort, pkt []byte) int)` returning how
many copies to deliver (0 drops, 2 duplicates). Root tests import it.

`internal/clock.Fake` gains a `sync.Mutex`: the layer reads `Now()` on its
own goroutines while tests call `Advance`, and without the mutex `-race`
fails. Path expiry and limiter tests use `clock.Fake` and call the sweep
directly. Client retransmit timers use real time; the tests that take real
seconds are named below.

### 14.1 `internal/udppath` unit tests

- Cookie (table): valid at t and t+10 s; invalid at t+12 s and t-2 s; other
  IP; other port; other `cid`; one MAC bit flipped; IPv4 and IPv4-mapped
  IPv6 give the same result; a new `Server` rejects the old server's cookie.
- Header and length (table): HELLO of 1199 and 1201 bytes; non-zero
  padding; version 2; non-zero reserved; type `0x07`; zero `cid`; zero `sid`
  in ACCEPT; DATA with `ctr = 0` and `ctr = 2^63`; DATA of 33 and 1233
  bytes: no reply, counted, no state.
- First-byte rule: a `0x00` datagram counts `Kick`; `"KBRK..."` counts
  `Foreign`; neither creates state.
- Amplification invariant: for every datagram from an unverified source, the
  bytes sent in reply are no more than the bytes received. Checked in each
  test and in the fuzz target.
- Knock (table): server with a key, HELLO without `mac1`: no COOKIE; with a
  wrong key: none; with the right key: COOKIE; INIT with a valid cookie but a
  bad `mac1`: no ACCEPT; a server without a key ignores a non-zero `mac1`.
- INIT: valid gives one ACCEPT and one path; a duplicate gives identical
  ACCEPT bytes, still one path, no second X25519 (counter), and no limiter
  token used; the same `cid` with another `c_eph` is dropped; all-zero and
  small-order `c_eph` are dropped, no path; `Allow` false gives no COOKIE
  and no ACCEPT.
- Admission (fake clock): the 5th pending INIT from one /32 is dropped; the
  9th INIT in one second is dropped; the 33rd path from one source is
  dropped; the 129th from one /24 is dropped; pending full evicts from the
  network holding the most, a HALF_OPEN path before a QUEUED one, never from
  a network with one path; reaching `MaxPaths` evicts the oldest path of
  the largest network, ACCEPTED included; an INIT refused by a cap leaves
  the client's existing paths alone; HALF_OPEN expires at 5 s, QUEUED at
  10 s, and `Accept` never returns an expired path.
- Two paths from one address: both carry DATA; DATA for one never reaches
  the other; an old session cannot write on a new path; closing one leaves
  the other working.
- DATA (table): unknown `rid`; right `rid` from another address; bad tag;
  replay of an accepted counter; a counter older than the window; out of
  order within the window, accepted once; a far jump, accepted, and the
  window slides. Only valid ones reach `Path.ReadFrom`.
- CLOSE: a valid CLOSE ends the path, `ReadFrom` returns the queued DATA
  then `ErrPathClosed`, and no CLOSE is sent back; a CLOSE replayed after a
  new path from the same address does nothing (other `rid`); a CLOSE with a
  bad tag is dropped; eviction, expiry and `Server.Close` each send 2 CLOSEs
  to the client, whose `Path.ReadFrom` then returns `ErrPathClosed`;
  `errors.Is(ErrPathClosed, net.ErrClosed)`.
- Read errors: a fake `net.PacketConn` returns `io.ErrShortBuffer`, a
  `syscall.Errno` standing in for `WSAEMSGSIZE`, and deadline errors between
  valid datagrams; an established path keeps working and `ReadErrors`
  counts them. 100 errors in a row trigger the backoff, then traffic
  resumes. `net.ErrClosed` from the socket closes every path. A 1501-byte
  and a 65,000-byte datagram are dropped as `Malformed` and an established
  path keeps working.
- Client: COOKIE ignored in INIT_SENT; ACCEPT with a bad tag ignored; after
  3 unanswered INITs a new HELLO with a new `cid` (real time, about 1.75 s);
  ctx deadline gives `errors.Is(err, ErrUDPHandshakeTimeout)` (root) and
  `context.DeadlineExceeded`; ctx cancel gives `context.Canceled` and not
  `ErrUDPHandshakeTimeout`; `ErrBadAddr` for `0.0.0.0:1`, `224.0.0.1:1` and
  port 0; the read deadline is cleared after success and after failure.
- HELLO budget: dialing a sink that never answers, with a 9 s context,
  sends exactly 5 HELLOs and 6,000 bytes (real time, about 9 s; skipped
  under `-short`).
- Close: `Server.Close` with paths in HALF_OPEN and QUEUED and no `Accept`
  caller: they get CLOSE, and `runtime.NumGoroutine()` returns to its value
  before `NewServer` (polled for up to 2 s). With one ACCEPTED path: it
  keeps working, the socket closes after its `Close`, and binding the same
  port then succeeds.
- Concurrency: 8 paths sending both ways at once under `-race`.
- Fuzz: `FuzzServerInput` (random datagrams, including empty and
  65,535-byte ones, from random sources: no panic, amplification invariant,
  no path without a valid cookie) and `FuzzClientInput` (no panic, never
  ESTABLISHED without a valid tag), in their own commit.
- Benchmarks: `BenchmarkSealOpen1200`, and `BenchmarkDataUnderHelloFlood`
  (DATA latency while HELLOs flood the handshake queue). The second is a
  benchmark, not a pass/fail test, since its result depends on the machine.

### 14.2 `internal/admit` tests

- `SourceKey` and `NetworkKey`: the existing `TestSourceKey` table moves
  here.
- Limiter (fake clock, table): burst then refill; `PerSecond = 0` always
  allows; 5,000 keys from one /48 cannot exceed the network rate together;
  memory does not grow with distinct keys (no allocation per key after
  `NewLimiter`, checked with `testing.AllocsPerRun`).

### 14.3 Root package tests

- KAM-11 regression (`udp_test.go`, `udptest.Net`): establish a session
  through `ListenUDP` and `DialUDP`; from the dialer's address inject a raw
  24-byte KCP header with `conv = 1, sn = 0`, a valid-looking KCP PUSH, and a
  forged CLOSE; then exchange a message both ways. Assert that the session
  works and that `Stats` shows `Foreign`, `Malformed`, `NoPath` and `BadTag`
  grew. The same toward the dialer from the server's address: no effect.
- Spoof flood against a real dialer: 20,000 HELLOs and INITs with bogus
  cookies from forged addresses in 1,000 /24s while a real dialer connects;
  the dialer succeeds, no path exists besides the dialer's, and the
  `Server`'s waiting list never held a forged source.
- Exhaustion from many sources: 64 sources in 64 /24s each hold 32 ACCEPTED
  paths whose kamune handshakes wait in the verifier (2,048 paths, with
  `MaxPaths` lowered to 2,048 for the test); a dialer from a 65th network
  still connects, and one attacker path is evicted.
- Per-source accounting: a path conn counts against
  `ServeWithMaxPendingPerSource` at accept; a conn without `ReturnRoutable`
  (`newUDPSourceConn`, now a conn type without the method) counts at the
  introduction (at the authenticated stage after RFC007).
  `TestPendingCapsByTransport` is rewritten on this basis.
- `ServeWithHandshakeRate` (fake clock, through `server.admit`, no
  production hooks): 17 calls with `newSourceConn(nil, "10.0.0.1:N")` in one
  second, and the 17th returns `ok == false`; another source is unaffected;
  65 sources in one /24 are stopped by the network level; the global level
  with a low setting; addressless and forgeable conns share the
  `"addressless"` bucket; `RateLimit{}` disables a level; a negative rate is
  an error.
- Existing tests that dial `127.0.0.1` more than 16 times a second pass
  `ServeWithHandshakeRate(RateLimit{}, RateLimit{}, RateLimit{})`. The
  handshake-rate change audits root, bus and daemon tests for this.
- Unreachable server: `DialWithUDP` with a 500 ms dial timeout to a bound
  socket that never answers fails with `ErrUDPHandshakeTimeout` in under 1 s.
- Server drops the path after ESTABLISHED: a `udptest` filter drops all
  client-to-server DATA; the server expires the HALF_OPEN path at 5 s and
  sends CLOSE; the dial fails with `ErrConnClosed` within about 5 s instead
  of the 30 s handshake timeout.
- Large frame: a 65,471-byte frame round-trips (KCP splits it into
  1200-byte segments).
- `Server.Close` on UDP leaves a session already handed to the handler
  working; `Shutdown` waits for it as with TCP.
- A re-dial from the same socket after the first session ended completes a
  kamune handshake on a new path.
- Dual stack: `ServeWithUDP` on `[::]:0` with one `udp4` dialer and one
  `[::1]` dialer; both work and the IPv4 one is keyed unmapped (skipped when
  IPv6 loopback is unavailable).
- Close linger: on a lossless `udptest.Net`, `Transport.Close` on one side
  makes the other side's `Receive` return `ErrPeerDisconnected`; with a
  filter that drops the close frame's DATA, the other side gets
  `ErrConnClosed` from CLOSE.

### 14.4 End-to-end test (real loopback sockets)

`TestUDPEndToEnd`: `NewServer("127.0.0.1:0", ..., ServeWithUDP())` and
`NewDialer(..., DialWithUDP())` with real storage, through a UDP forwarder
goroutine (its own socket between dialer and server) that re-sends each
DATA datagram once more from the path address. Steps: cold handshake with a
verifier; 100 messages each way; ping and pong; `Transport.Close` with
`RouteCloseTransport` seen by the server as `ErrPeerDisconnected` (lossless
loopback); resume with `DialWithResume` over a new path. Meanwhile an
attacker goroutine on its own socket sends HELLOs, garbage, raw KCP headers,
oversize datagrams and copies of captured DATA to the server port. Assert
that every step passes, the attacker never gets a reply larger than its
request, the server holds no attacker path beyond HALF_OPEN,
`Stats.Replay > 0` (the forwarder's duplicates) and `Stats.NoPath > 0` (the
attacker's copies).

RFC011's broker end-to-end test gains a `DialUDP` variant on
`ep.PacketConn()`, and RFC006's cross-RFC run uses `ListenUDP` and
`DialUDP` on the endpoint with RFC010's `ExpectPeer` on both conns.

### 14.5 Client tests

- daemon `integration_test.go` and bus `p2p_test.go`: direct P2P on loopback
  with `newDirectP2PListener` and `directP2PDial`; a third socket bound to
  `127.0.0.2` gets no COOKIE (skipped when that bind fails, as the root
  tests that use other loopback addresses skip); with a knock key on both
  ends the session works, and a dialer with another key gets no COOKIE.
- bus and daemon `HolePunch` to a port with no listener, timeout 500 ms:
  returns `ErrHolePunchFailed` in under 1 s.
- bus `p2plistener_test.go`: with RFC011's endpoint on the punch socket, a
  broker datagram is consumed by the endpoint, and a KCP session still
  establishes on the same socket.

### 14.6 Existing tests to delete or rewrite

Root (`server_test.go`):

- `TestKCPFloodFromManySourcesDoesNotDropDialer`: uses `kcp.Listen`,
  `kcpPush` and `&udpListener{Listener: kl}`. Rewritten as the spoof flood
  of section 14.3, reusing its loopback sources (`127.1.x.y`) for the
  real-socket variant.
- `TestPendingCapsByTransport` (udp case) and `newUDPSourceConn`: rewritten
  on `ReturnRoutable`.
- `TestSourceKey`: moves to `internal/admit`.

bus:

- `TestHolePunch_HappyPath` and `TestHolePunch_KicksAfterReturn`
  (`p2p_test.go`): they assert that `HolePunch` returns at once with a KCP
  session and keeps kicking after it returns; rewritten to the blocking
  behaviour.
- `TestDirectP2PListener_AcceptsOnlyPeer` (`directp2p_test.go`),
  `TestP2PListener_AcceptsOnlyMatchedPeer` and
  `TestP2PListener_PeerMatchedWhileStarting` (`p2plistener_test.go`): they
  dial with raw `kcp.NewConn4` or depend on kcp-go reading the punch socket;
  rewritten to dial with `kamune.DialUDP`.
- `newP2PListenerNoBroker` (`p2plistener_test.go`): starts kcp-go through
  `serve`; rewritten.
- `punchfilter_test.go`: goes with `punchFilter`; a matched-peer filter
  test follows open question 1.

daemon:

- `TestHolePunchSendsKickBurst` and `TestHolePunchFailsWithoutKick`
  (`broker_test.go`): rewritten for `HolePunch` over `DialUDP`.
- `TestP2PListenerHandlesPeerMatched` (`p2plistener_test.go`): accepts with
  `l.kcp.AcceptKCP`; rewritten. `TestP2PListenerPeerExpires` follows open
  question 1.

### 14.7 Verification outside the test suite

The repository has no CI configuration. The root integration commit is also
checked with `GOOS=windows go vet ./...`, and the oversize-datagram test is
run once on Windows by hand. The fix does not depend on the platform: the
reader treats every non-close error as transient whatever its code, which
the fake-`PacketConn` test checks on any OS, and the 65,536-byte buffer
removes the Windows trigger.

## 15. Decisions

| Question | Decision |
| -------- | -------- |
| Rollout | **Maintainer decision: not implemented now.** Draft, targeted before v1.0, not scheduled. A wire-incompatible hard cut, as RFC004 is, with no version negotiation and no backward compatibility (section 17). |
| Where KCP packets are authenticated | In the layer, every packet from the first DATA, with the path key. Rejected: kcp-go `BlockCrypt` (fixed at session creation, before the kamune handshake; kcp-go's AEAD mode uses random nonces and has no replay check); rekeying from a kamune exporter after the handshake (needs an agreed switch point while KCP retransmits older packets, and adds nothing against an off-path attacker). Cost: one ChaCha20-Poly1305 operation per packet. |
| kcp-go `Listener` | Not used. One `NewConn4` session per path. Cost: one channel hop and one copy per inbound packet, and kcp-go's `readLoop` goroutine per server session. kcp-go's `recvmmsg`/`sendmmsg` batching (`newBatchConn` in `platform_linux.go`) needs a `*net.UDPConn`-like socket, so any wrapper loses it, as the clients' `punchFilter` and `punchConn` already do. |
| Several paths from one address | Allowed, with no takeover rule. DATA is routed by `rid`, and each kcp-go session holds its own `*Path`, so kcp-go never keys anything by address. |
| Path-layer confidentiality | None claimed; path keys are classical and no layer may rely on them (section 7.2). |
| ML-KEM in the path handshake | No (section 7.2). |
| Channel binding to RFC007 | Deferred. A path-layer MITM gains only DoS with or without it, since kamune frames are authenticated end to end; a binding changes which step fails, not what the attacker can do. RFC007 takes no transport input into its transcript, and making it depend on the transport type adds a cross-RFC dependency for no property. The `"binding"` label is reserved, so `ExpandLabel(prk, "binding", 32)` can be added later without a wire change. |
| Stateless reset (RFC 9000 10.3) | Deferred. CLOSE covers every case where the sender still holds the path keys. A stateless reset would cover a server restart only with a reset key persisted on disk, and it adds an unauthenticated server reply to unverified DATA that needs its own rate limit. The read deadline and kamune resumption cover restarts. |
| FEC | Stays off. No finding requires it; the layer sits below kcp-go, so FEC can be added later per session without changing this wire format. |
| Connection migration, version negotiation packet | None. |
| Cookie secret rotation | None (section 7.1). |
| HELLO flood handling | A separate handshake worker behind a 256-packet queue that drops when full. A global COOKIE budget was rejected: it would be a global lockout (20,000 1200-byte HELLOs a second, 24 MB/s from forged sources, would deny COOKIEs to every real dialer), while the queue drops under the same load with no tuned number. |
| Global INIT budget | None. X25519 work runs on one goroutine and never delays DATA, so a global budget would only add a lockout reachable by about 250 real addresses at 4 INIT/s each. |
| Rate limiter slot index | `hash/maphash` with a random per-process seed, not HMAC: the same property (an attacker cannot predict or aim collisions) at a fraction of the cost and with no key management. |
| Bounding KEM work | A rate bucket in `admit`, not a semaphore of concurrent `exchange.Accept` calls. A semaphore would sit inside RFC007's handshake code, where the responder also waits on the network and on the verifier (150 s), so a slow peer would hold a slot; the bucket bounds the same work from outside and is testable with the fake clock. |
| Owner of the handshake rate limit | This RFC; RFC007 adds none. |
| HELLO budget | 5 HELLOs at 0, 0.5, 1.5, 3.5 and 7.5 s (6,000 bytes). Four HELLOs on a 250 ms schedule would end at 1.75 s, and a punch whose listener-side kick lands later (the direct-P2P listener kicks every 2 s for 10 s) would fail. |
| Dial target check | Refuses unspecified, multicast, broadcast and port 0; allows loopback and link-local (section 8.6). |
| Direct-P2P source filter | Peer IP, any port: the direct-P2P dialer binds port 0, so an exact-port filter would reject every dial. The knock MAC covers the CGNAT-neighbour case. |
| Knock key on broker P2P listeners | None: one socket serves many contacts, and the key is per listener. |
| Raw kcp-go inside kamune | `NewConn` stays exported (the TUI's relay entry point, and it takes any `net.Conn`). With `ReturnRoutable`, a raw kcp-go conn wrapped by `NewConn` is forgeable and counted late, so the spoofing gap stays closed without removing the API. bus and daemon stop importing kcp-go directly. |
| Victim rule | Layer-local; `Server.dropCandidateLocked` is not touched and no shared waitlist type is added to `internal/admit`. |
| Broker datagrams on a shared socket | RFC011's Endpoint (`Client.NewEndpoint(conn)`) demultiplexes in front of the path layer: it consumes broker datagrams and hands the layer a plain `net.PacketConn` (`Endpoint.PacketConn()`, requirements in section 13). The layer drops every datagram outside its first-byte range and has no hook for broker traffic. Rejected: a foreign-packet handler in the layer (`UDPWithForeignHandler`) feeding a socket-free broker API (`HandlePacket(pkt, from) (Event, error)`). The Endpoint needs no hook API in this layer, keeps RFC011's source and authentication checks inside RFC011, and gives one integration for listeners and dialers. |
| `Stats` | Snapshot for tests and debugging; no periodic log. |

## 16. Proposed Defaults

These are the values this RFC proposes; they await maintainer confirmation.

| Setting | Proposed default | Notes |
| ------- | ---------------- | ----- |
| Paths per source / per network | 32 / 128 | TCP has no live-session cap per source; the server's 16 per source caps only connections in the handshake (`defaultMaxPendingPerSource`). Applying 16 to live UDP sessions would cap a NAT'd office or CGNAT address at 16 chats with one server. 32/128 keeps the fairness property, because eviction at `MaxPaths` protects quiet networks (the exhaustion test of section 14.3 holds with these values). Servers with many users behind one NAT raise them with `UDPWithPathLimits`, which SPEC §10.1 documents. |
| Pending paths per source, INIT rate per source | 4; 4/s, burst 8 | |
| Handshake rate per source / per network | 8/s burst 16 / 32/s burst 64 | Raised or disabled with `ServeWithHandshakeRate`. |
| Global handshake rate | On, `512 * GOMAXPROCS`/s, burst twice that | Sized in section 9.4. Operators who want it off pass `RateLimit{}` for the global level. |
| KCP MTU | 1200 | Fits every IPv6 path (DATA at most 1232 bytes). kcp-go's 1400 would send fewer packets but may fragment. |
| Hole-punch dial timeout | 10 s (`DefaultHolePunchTimeout`, bus and daemon) | Covers the direct-P2P listener's 10 s kick window. |

## 17. Compatibility

Wire-incompatible hard cut. The UDP datagram format changes completely: a
KCP packet from today's code starts with a little-endian `conv`, whose first
byte the path layer reads as a type and drops unless it is `0x01` to `0x0F`
with a valid header, and today's kcp-go listener parses path-layer packets
as KCP segments. There is no version negotiation and no fallback.
`ServeWithUDP(opts ...ConnOption)` becomes `ServeWithUDP(opts ...UDPOption)`
and `DialWithUDP` likewise; callers that pass no options compile unchanged.
Code that wraps raw kcp-go in `NewConn` still compiles and runs against
peers that do the same, but its conns are counted as forgeable. Before v1.0
kamune makes no backward-compatibility promise, and pre-1.0 version checks
already reject minor-version differences, so the cut is consistent with the
existing version policy (RFC006).

## 18. Implementation Plan

Commits follow AGENTS.md (`kamune:`, `bus:`, `daemon:`, `docs:`), each
small, in the order below. Groups 1 and 2 are mostly new packages
(`internal/admit`, `internal/udppath`, `internal/udppath/udptest`) and can
be developed in parallel with the new packages of RFC007, RFC009, RFC010
and RFC011. One group 1 commit edits files shared with RFC007:
`kamune: move source and network keys into internal/admit` edits
`server.go` (it removes `sourceKey`, `networkKey`, `prefixKey` and
`hostIP`) and `server_test.go` (it moves `TestSourceKey`) ahead of RFC007,
in the order the file table below gives. The fake-clock commit edits only
`internal/clock/fake.go`, which this RFC owns, but the tests of the other
RFCs depend on it, so it lands first as a shared prerequisite of the whole
rework (RFC006).

| Group | Module | Commits, in order | Depends on |
| ----- | ------ | ----------------- | ---------- |
| 1. Prerequisites | root | `kamune: guard the fake clock with a mutex`; `kamune: move source and network keys into internal/admit`; `kamune: add fixed-memory keyed rate limiter to internal/admit`; `kamune: add in-memory packet network for udp tests` | nothing; the fake-clock commit is a shared prerequisite of the whole rework and lands first |
| 2. Path layer | root (`internal/udppath`) | `kamune: add udp path handshake with return-routability cookies`; `kamune: seal udp path packets with a replay window and close`; `kamune: add udp path server with caps, eviction and accept` (each with its unit tests) | group 1 |
| 3. Root integration | root | `kamune: run udp listeners and dialers over the path layer` (`ListenUDP`, `DialUDP`, the new `ServeWithUDP` and `DialWithUDP`, `ErrUDPHandshakeTimeout`, close linger, KAM-11 regression); `kamune: trust source addresses only from return-routable conns`; `kamune: rate-limit handshakes per source, network and in total`; `kamune: add udp end-to-end test`; `kamune: fuzz udp path input` | group 2; `errors.go` after RFC010's `ErrPeerKeyMismatch`; lands before RFC007's root switch, which rebases once onto the first three commits and keeps the rate check first in `admit` and the `forgeable` computation |
| 4. Clients | bus, daemon | `bus: hole-punch over the kamune udp path layer`; `daemon: hole-punch over the kamune udp path layer` | group 3; after the RFC009, RFC011 and RFC010 client commits in the same files; before RFC010's reconnect-root commits and RFC007's client commits; the knock key needs RFC010's `PunchKey`; if `PunchKey` lands later, the knock-key wiring follows in its own commit |
| 5. Docs | docs | `docs: describe the udp path layer in SPEC 9.2`; `docs: update server limits, constants and errors for udp paths`; `docs: update daemon transport table and broker socket text`; `docs: list admit and udppath internal packages` | the code groups; SPEC after RFC007's SPEC edits; the RELAY.md broker text after RFC011's rewrite of that section; DAEMON.md after RFC009, RFC011 and RFC010 and before RFC007 |

Files shared with other RFCs, and the order of changes:

| File | Order | This RFC changes |
| ---- | ----- | ---------------- |
| `server.go` | RFC008, then RFC007 | `ServeWithUDP` body (binds and calls `ListenUDP`), `ServeWithHandshakeRate`, the rate check at the top of `admit`, `p.forgeable = !isReturnRoutable(cn)`, removal of `forgeableAddr`, `sourceKey`, `networkKey`, `prefixKey`, `hostIP` (moved to `internal/admit`) and of today's `udpListener` (`ListenUDP` returns the new `pathListener` in `udp.go`) |
| `dial.go` | RFC008, then RFC007 | `DialWithUDP` |
| `conn.go` | RFC008, then final cleanup | `returnRoutable`, `(*conn).ReturnRoutable`, `NewConn` doc |
| `errors.go` | RFC010, RFC008, RFC007 | `ErrUDPHandshakeTimeout` |
| `server_test.go` | RFC008, then RFC007 | KCP flood test rewrite, `TestPendingCapsByTransport` udp case, `TestSourceKey` move, rate-limit opt-outs |
| bus and daemon `broker.go`, `p2plistener.go`, `directp2p.go`, `network.go` | RFC009, RFC011, RFC010, RFC008, then RFC010 (reconnect roots), RFC007 | the KCP lines only (section 12) |
| `AGENTS.md` | RFC008, then final cleanup | `admit`, `udppath` in the root `internal/` list |

Rate-limit opt-outs that bus and daemon tests need go in their own `bus:`
and `daemon:` commits in the same merge as the handshake-rate commit.

## 19. Documentation Updates

- `docs/SPEC.md` §9.2: replace with "UDP (KCP over the path layer)": 9.2.1
  overview and diagram; 9.2.2 packet formats and the first-byte table
  (section 6); 9.2.3 cookie and knock MAC (sections 7.1, 7.4); 9.2.4 path
  keys, DATA, CLOSE, and the statement that path keys are classical, carry
  no confidentiality claim and that no layer may rely on them (sections 7.2,
  7.3); 9.2.5 state machines and timeouts, including the per-dial HELLO
  budget of 6,000 bytes (sections 8, 10); 9.2.6 security notes (section 11).
  Keep the statement that FEC is off.
- `docs/SPEC.md` §10.1: drop "Over UDP, where a source address can be
  forged, a connection counts only from its introduction"; say that
  per-source counting at accept needs return routability; add the three
  handshake-rate levels; replace the first gap ("Over UDP a sender that
  forges source addresses ...") with the real-address residual; add the UDP
  path limits and `UDPWithPathLimits`.
- `docs/SPEC.md` §12.7: KCP headers are encrypted on the wire; HELLO and
  INIT are fingerprintable; the knock key hides P2P listeners from scanners.
- `docs/SPEC.md` §13: add the constants of section 10.
- `docs/SPEC.md` §14: "the UDP path handshake does not complete before the
  dial deadline: `ErrUDPHandshakeTimeout`"; "a path-layer packet fails
  validation or authentication: dropped silently"; "the peer closes, evicts
  or expires the path: `ErrConnClosed`".
- `docs/DAEMON.md`: the transport table (section 12.2) and the hole-punch
  prose.
- `docs/RELAY.md`, section "Broker: STUN-Echo and Signal Introduction": the
  first-byte rule, and replace the paragraph under `REGISTER (peer → broker)`
  that tells clients to read NOTIFYs on the punch socket with
  `Client.ReadNotify` with the endpoint arrangement of section 13, together
  with RFC011's rewrite of that section.
- `AGENTS.md`: add `admit` and `udppath` to the root `internal/` list
  (`docs:` commit).
- Go doc comments: `ServeWithUDP` (the port stays bound until the last
  session ends), `DialWithUDP`, `ListenAndServe`,
  `ServeWithMaxPendingHandshakes`, `ServeWithMaxPendingPerSource`,
  `ServeWithListener` (`ReturnRoutable`), `NewConn`, and the new functions.
- `CHANGELOG.md` is not touched unless the maintainer asks.

## 20. Open Questions

1. **Source filter on broker P2P listeners.** Today both clients pass KCP
   packets on a broker punch socket only from IPs that a PEER_MATCHED named
   (bus `punchFilter.expect`, one minute; daemon `admitPeer`,
   `matchedPeerIdle`). This RFC gives broker P2P listeners no knock key, and
   RFC011 leaves the choice here: should the listener feed RFC011's
   authenticated `Match.Peer` IPs into `UDPWithSourceFilter` for a match
   window, or rely on the path layer's caps and RFC010's `ExpectPeer`? The
   filter is consulted for every HELLO and INIT, so a set that changes over
   time works. Keeping it stops scanners from starting path and kamune
   handshakes on the listener; dropping it removes the window logic and its
   cap on matched peers.
