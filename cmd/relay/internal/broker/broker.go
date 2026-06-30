// Package broker implements the kamune relay broker: a single UDP listener that
// combines STUN-like IP echo and signal introduction for P2P hole-punching. The
// server is stateless across restarts; the registry is in-memory and
// TTL-evicted.
package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/pkg/exchange"
	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
)

// readDeadline is the UDP read deadline. Short enough for responsive shutdown
// and TTL cleanup, long enough to avoid busy-looping.
const readDeadline = 500 * time.Millisecond

// AllowFunc is the rate limiter's Allow method, abstracted so the broker
// package does not import the relay's private ratelimit package. nil means "no
// rate limiting".
type AllowFunc func(key string) bool

// registration is the broker's per-token state. The peer is identified by their
// ephemeral public key — same key, NAT rebinding; different keys, different
// processes.
type registration struct {
	addr       *net.UDPAddr
	peerEphPub [32]byte
	expires    time.Time
}

// Broker is the UDP server. One instance per relay process.
type Broker struct {
	conn     *net.UDPConn
	registry map[string]*registration
	mu       sync.Mutex
	ttl      time.Duration
	allow    AllowFunc
	now      func() time.Time
}

// New binds the UDP socket and returns a Broker ready for Run.
func New(cfg config.Broker, allow AllowFunc) (*Broker, error) {
	addr, err := net.ResolveUDPAddr("udp4", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr %q: %w", cfg.Address, err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %q: %w", addr, err)
	}
	ttl := cfg.RegistrationTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &Broker{
		conn:     conn,
		registry: make(map[string]*registration),
		ttl:      ttl,
		allow:    allow,
		now:      time.Now,
	}, nil
}

// Run is the main loop. It returns when ctx is cancelled or the socket is
// closed. Single goroutine: read with a deadline, dispatch, tick cleanup at
// every deadline.
func (b *Broker) Run(ctx context.Context) error {
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		_ = b.conn.SetReadDeadline(b.now().Add(readDeadline))
		n, src, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				b.purgeExpired()
				continue
			}
			// Socket closed (Close called) or other fatal error.
			return nil
		}
		b.dispatch(buf[:n], src)
	}
}

// Close closes the UDP socket. Unblocks Run.
func (b *Broker) Close() error {
	return b.conn.Close()
}

// Addr returns the bound UDP address (useful for tests that need to dial the
// broker).
func (b *Broker) Addr() *net.UDPAddr {
	return b.conn.LocalAddr().(*net.UDPAddr)
}

// dispatch routes a packet by opcode. Length/magic/version checks happen here;
// the per-opcode handlers do their own per-payload validation.
func (b *Broker) dispatch(pkt []byte, src *net.UDPAddr) {
	if len(pkt) < 6 {
		return
	}
	if pkt[0] != 'K' || pkt[1] != 'B' || pkt[2] != 'R' || pkt[3] != 'K' {
		return
	}
	if pkt[4] != 0x01 {
		return
	}
	switch pkt[5] {
	case 0x01: // STUN_ECHO
		b.handleEcho(src)
	case 0x02: // REGISTER
		b.handleRegister(pkt, src)
	case 0x03: // NOTIFY
		// Sent by the broker only. Peers should not send NOTIFY.
	}
}

// handleEcho responds to the source with its perceived IP:port.
func (b *Broker) handleEcho(src *net.UDPAddr) {
	if !b.allowEcho(src) {
		return
	}
	resp := relaybroker.BuildEchoResponse(src)
	if _, err := b.conn.WriteToUDP(resp, src); err != nil {
		slog.Debug("broker: echo write", slog.Any("error", err))
	}
}

// handleRegister parses the REGISTER, branches on token, sends NOTIFY (
// TOKEN_ASSIGNED or PEER_MATCHED) as appropriate.
func (b *Broker) handleRegister(pkt []byte, src *net.UDPAddr) {
	if !b.allowRegister(src) {
		return
	}
	token, peerEphPub, ip, port, err := relaybroker.ParseRegister(pkt)
	if err != nil {
		return
	}
	if !validIPv4(ip) || port == 0 {
		return
	}
	if isZeroBytes(peerEphPub) {
		return
	}

	// Always normalise source to IPv4 so subsequent match comparisons are
	// stable across IPv4-mapped-IPv6 listeners.
	src4 := ipv4FromAddr(src)
	if src4 == nil {
		return
	}

	if isZeroBytes(token) {
		b.handleRandomRegister(peerEphPub, src4)
		return
	}
	b.handleStaticRegister(token, peerEphPub, src4, ip, port)
}

// handleRandomRegister is the empty-token case: generate a random 16-byte
// token, store the registration, send NOTIFY(TOKEN_ASSIGNED).
func (b *Broker) handleRandomRegister(peerEphPub []byte, src *net.UDPAddr) {
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		slog.Debug("broker: random token", slog.Any("error", err))
		return
	}
	var pub [32]byte
	copy(pub[:], peerEphPub)

	b.mu.Lock()
	b.registry[hexKey(key[:])] = &registration{
		addr:       src,
		peerEphPub: pub,
		expires:    b.now().Add(b.ttl),
	}
	b.mu.Unlock()

	b.sendTokenAssigned(key[:], pub, src)
}

// handleStaticRegister is the non-empty-token case: lookup, then match,
// refresh, or hold.
func (b *Broker) handleStaticRegister(
	token, peerEphPub []byte, src *net.UDPAddr, ip net.IP, port uint16,
) {
	var pub [32]byte
	copy(pub[:], peerEphPub)

	b.mu.Lock()
	held, exists := b.registry[hexKey(token)]
	if exists && bytes.Equal(held.peerEphPub[:], pub[:]) {
		// Self-match: same peer, refresh TTL, no NOTIFY.
		held.expires = b.now().Add(b.ttl)
		b.mu.Unlock()
		return
	}
	if !exists {
		// Hold: no match yet, no NOTIFY.
		b.registry[hexKey(token)] = &registration{
			addr:       src,
			peerEphPub: pub,
			expires:    b.now().Add(b.ttl),
		}
		b.mu.Unlock()
		return
	}
	// Match: held peer has a different PEER_EPH_PUB than this peer. Send
	// NOTIFY(PEER_MATCHED) to BOTH, each with its own fresh broker ephemeral
	// key. Clear the entry.
	heldEntry := held
	delete(b.registry, hexKey(token))
	b.mu.Unlock()

	b.sendPeerMatched(token, heldEntry, pub, src, ip, port)
}

// sendTokenAssigned builds and sends NOTIFY(TOKEN_ASSIGNED) to the given peer
// address.
func (b *Broker) sendTokenAssigned(token []byte, peerEphPub [32]byte, dst *net.UDPAddr) {
	plaintext := relaybroker.TokenAssignedPlaintext(token, uint32(b.ttl.Seconds()))
	b.sendNotify(plaintext, peerEphPub, dst)
}

// sendPeerMatched sends two NOTIFY(PEER_MATCHED) packets — one to each peer —
// each with its own fresh broker ephemeral key. The held peer's NOTIFY carries
// the new peer's IP:port + eph pub; the new peer's NOTIFY carries the held
// peer's IP:port + eph pub.
func (b *Broker) sendPeerMatched(
	token []byte,
	held *registration,
	newPub [32]byte,
	newAddr *net.UDPAddr,
	newIP net.IP,
	newPort uint16,
) {
	heldIP := ipv4FromAddr(held.addr)
	if heldIP == nil {
		return
	}
	// NOTIFY to the new peer: held's IP:port + eph pub.
	heldPlain := relaybroker.PeerMatchedPlaintext(
		token, held.peerEphPub[:], heldIP.IP, uint16(held.addr.Port),
	)
	b.sendNotify(heldPlain, newPub, newAddr)

	// NOTIFY to the held peer: new's IP:port + eph pub.
	newPlain := relaybroker.PeerMatchedPlaintext(
		token, newPub[:], newIP, newPort,
	)
	b.sendNotify(newPlain, held.peerEphPub, held.addr)
}

// sendNotify performs the per-NOTIFY crypto: generate a fresh broker ephemeral
// X25519 key, compute the shared secret, derive the AEAD key, seal the
// plaintext, write the NOTIFY to dst. The broker ephemeral private key is GC'd
// on return — forward secrecy per NOTIFY, not per REGISTER.
func (b *Broker) sendNotify(
	plaintext []byte, peerEphPub [32]byte, dst *net.UDPAddr,
) {
	brokerECDH, err := exchange.NewECDH()
	if err != nil {
		slog.Debug("broker: gen key", slog.Any("error", err))
		return
	}
	shared, err := brokerECDH.Exchange(peerEphPub[:])
	if err != nil {
		return
	}
	aeadKey := sha256.Sum256(shared)

	brokerEphPub := brokerECDH.MarshalPublicKey()
	nonce, sealed := relaybroker.SealNotify(aeadKey[:], brokerEphPub, plaintext)

	var pkt []byte
	switch relaybroker.NotifyType(plaintext[0]) {
	case relaybroker.NotifyPeerMatched:
		pkt = relaybroker.BuildNotifyPeerMatched(brokerEphPub, nonce, sealed)
	case relaybroker.NotifyTokenAssigned:
		pkt = relaybroker.BuildNotifyTokenAssigned(brokerEphPub, nonce, sealed)
	}

	if _, err := b.conn.WriteToUDP(pkt, dst); err != nil {
		slog.Debug("broker: notify write", slog.Any("error", err))
	}
}

func (b *Broker) allowEcho(src *net.UDPAddr) bool {
	if b.allow == nil {
		return true
	}
	return b.allow(ipv4KeyFromAddr(src))
}

func (b *Broker) allowRegister(src *net.UDPAddr) bool {
	if b.allow == nil {
		return true
	}
	return b.allow(ipv4KeyFromAddr(src))
}

// purgeExpired evicts entries whose TTL has passed. Best-effort cleanup; the
// lock is held briefly.
func (b *Broker) purgeExpired() {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, r := range b.registry {
		if now.After(r.expires) {
			delete(b.registry, k)
		}
	}
}

// hexKey renders a 16-byte token as a 32-char hex string for the registry map.
// Same encoding as cmd/relay SessionManager.
func hexKey(token []byte) string {
	var buf [32]byte
	hex.Encode(buf[:], token)
	return string(buf[:])
}

func ipv4FromAddr(addr *net.UDPAddr) *net.UDPAddr {
	ip := addr.IP.To4()
	if ip == nil {
		return nil
	}
	return &net.UDPAddr{IP: ip, Port: addr.Port}
}

func ipv4KeyFromAddr(addr *net.UDPAddr) string {
	ip := addr.IP.To4()
	if ip == nil {
		return ""
	}
	return ip.String()
}

func validIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return !isZeroBytes(ip4)
}

func isZeroBytes(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
