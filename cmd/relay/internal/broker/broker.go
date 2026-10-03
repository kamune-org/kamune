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
	"math"
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

// readBufSize holds the largest IPv4 UDP payload, so no datagram is too long
// to read. With a shorter buffer Windows fails the read with WSAEMSGSIZE.
const readBufSize = 64 << 10

// readErrBurst is the number of reads in a row that may fail before Run backs
// off. Once the buffer fits any datagram, no packet a remote host sends makes
// a read fail, so a run of failures points to a local socket fault.
const readErrBurst = 16

// readErrBackoff is the pause before each further read while reads keep
// failing, so a persistent socket fault cannot spin the loop.
const readErrBackoff = 100 * time.Millisecond

const defaultMaxRegistry = 100_000

// AllowFunc is a rate limiter's Allow method, called with the packet's source
// IPv4. It is abstracted so the broker package does not import the relay's
// private ratelimit package.
type AllowFunc func(key string) bool

// Limits holds the broker's per-IP rate limiters. A nil field means no limit
// for that packet type.
//
// UDP source addresses are not verified: a spoofed packet spends the quota of
// the address it names, and a spray of forged sources evicts real addresses
// from a limiter's history. The limiters must not be shared with the TCP, TLS
// and WS listeners, and Echo and Register must be separate limiters so that
// spoofed echoes cannot spend or evict REGISTER budgets.
type Limits struct {
	Echo     AllowFunc
	Register AllowFunc
}

// registration is the broker's per-token state. The peer is identified by their
// ephemeral public key — same key, NAT rebinding; different keys, different
// processes.
type registration struct {
	addr       *net.UDPAddr
	peerEphPub [32]byte
	expires    time.Time
}

// packetConn is the part of *net.UDPConn the broker uses. Tests wrap it to
// inject read errors.
type packetConn interface {
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	SetReadDeadline(t time.Time) error
	LocalAddr() net.Addr
	Close() error
}

// Broker is the UDP server. One instance per relay process.
type Broker struct {
	conn        packetConn
	registry    map[string]*registration
	mu          sync.Mutex
	ttl         time.Duration
	limits      Limits
	now         func() time.Time
	maxRegistry int
}

// New binds the UDP socket and returns a Broker ready for Run.
func New(cfg config.Broker, limits Limits) (*Broker, error) {
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
		conn:        conn,
		registry:    make(map[string]*registration),
		ttl:         ttl,
		limits:      limits,
		now:         time.Now,
		maxRegistry: defaultMaxRegistry,
	}, nil
}

// Run is the main loop. It returns nil when ctx is cancelled or the socket is
// closed, and does not return otherwise. Single goroutine: read with a
// deadline, dispatch, tick cleanup at every deadline. A failed read is logged
// and skipped, so no packet a remote host sends can stop the loop. Once
// readErrBurst reads in a row have failed, Run waits readErrBackoff before
// each further read until one succeeds or times out.
func (b *Broker) Run(ctx context.Context) error {
	buf := make([]byte, readBufSize)
	lastPurge := b.now()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		now := b.now()
		if now.Sub(lastPurge) >= readDeadline {
			b.purgeExpired()
			lastPurge = now
		}
		n, src, err := b.read(buf)
		if err == nil {
			logReadRecovered(failures)
			failures = 0
			b.dispatch(buf[:n], src)
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			logReadRecovered(failures)
			failures = 0
			b.purgeExpired()
			lastPurge = b.now()
			continue
		}
		if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
			return nil
		}
		failures++
		if failures < readErrBurst {
			slog.Debug("broker: read packet", slog.Any("error", err))
			continue
		}
		if failures == readErrBurst {
			slog.Warn(
				"broker: udp reads keep failing, backing off",
				slog.Int("failures", failures),
				slog.Any("error", err),
			)
		}
		if !sleepCtx(ctx, readErrBackoff) {
			return nil
		}
	}
}

// read sets the read deadline and reads one datagram into buf.
func (b *Broker) read(buf []byte) (int, *net.UDPAddr, error) {
	if err := b.conn.SetReadDeadline(b.now().Add(readDeadline)); err != nil {
		return 0, nil, fmt.Errorf("set udp read deadline: %w", err)
	}
	return b.conn.ReadFromUDP(buf)
}

// logReadRecovered logs the end of a run of failed reads that made Run back
// off.
func logReadRecovered(failures int) {
	if failures >= readErrBurst {
		slog.Info(
			"broker: udp reads recovered", slog.Int("failures", failures),
		)
	}
}

// sleepCtx waits for d and reports false if ctx was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
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
	// Only well-formed REGISTERs are charged, so junk cannot spend a
	// source's budget.
	if !b.allowRegister(src4) {
		return
	}

	if isZeroBytes(token) {
		b.handleRandomRegister(peerEphPub, src4)
		return
	}
	b.handleStaticRegister(token, peerEphPub, src4)
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
	if b.registryFullLocked() {
		b.mu.Unlock()
		return
	}
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
	token, peerEphPub []byte, src *net.UDPAddr,
) {
	var pub [32]byte
	copy(pub[:], peerEphPub)

	b.mu.Lock()
	held, exists := b.registry[hexKey(token)]
	if exists && b.now().After(held.expires) {
		delete(b.registry, hexKey(token))
		exists = false
		held = nil
	}
	if exists && bytes.Equal(held.peerEphPub[:], pub[:]) {
		held.expires = b.now().Add(b.ttl)
		held.addr = src
		b.mu.Unlock()
		return
	}
	if !exists {
		if b.registryFullLocked() {
			b.mu.Unlock()
			return
		}
		b.registry[hexKey(token)] = &registration{
			addr:       src,
			peerEphPub: pub,
			expires:    b.now().Add(b.ttl),
		}
		b.mu.Unlock()
		return
	}
	heldEntry := held
	delete(b.registry, hexKey(token))
	b.mu.Unlock()

	b.sendPeerMatched(token, heldEntry, pub, src)
}

// sendTokenAssigned builds and sends NOTIFY(TOKEN_ASSIGNED) to the given peer
// address.
func (b *Broker) sendTokenAssigned(token []byte, peerEphPub [32]byte, dst *net.UDPAddr) {
	plaintext := relaybroker.TokenAssignedPlaintext(
		token, durationSeconds(b.ttl),
	)
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
) {
	heldIP := ipv4FromAddr(held.addr)
	newIP := ipv4FromAddr(newAddr)
	if heldIP == nil || newIP == nil {
		return
	}
	heldPlain := relaybroker.PeerMatchedPlaintext(
		token, held.peerEphPub[:], heldIP.IP, uint16(held.addr.Port),
	)
	b.sendNotify(heldPlain, newPub, newAddr)

	newPlain := relaybroker.PeerMatchedPlaintext(
		token, newPub[:], newIP.IP, uint16(newAddr.Port),
	)
	b.sendNotify(newPlain, held.peerEphPub, held.addr)
}

// registryFullLocked reports whether the registry is at maxRegistry. It does
// not purge: Run purges expired entries every readDeadline, so a REGISTER that
// arrives while the registry is full costs O(1) instead of a walk over every
// entry. A full registry of expired entries frees up within readDeadline.
func (b *Broker) registryFullLocked() bool {
	if b.maxRegistry <= 0 {
		return false
	}
	return len(b.registry) >= b.maxRegistry
}

func durationSeconds(d time.Duration) uint32 {
	if d <= 0 {
		return 0
	}
	s := math.Ceil(d.Seconds())
	if s > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(s)
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
	if b.limits.Echo == nil {
		return true
	}
	return b.limits.Echo(ipv4KeyFromAddr(src))
}

func (b *Broker) allowRegister(src *net.UDPAddr) bool {
	if b.limits.Register == nil {
		return true
	}
	return b.limits.Register(ipv4KeyFromAddr(src))
}

func (b *Broker) purgeExpiredLocked() {
	now := b.now()
	for k, r := range b.registry {
		if now.After(r.expires) {
			delete(b.registry, k)
		}
	}
}

// purgeExpired evicts entries whose TTL has passed. Best-effort cleanup; the
// lock is held briefly.
func (b *Broker) purgeExpired() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.purgeExpiredLocked()
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
