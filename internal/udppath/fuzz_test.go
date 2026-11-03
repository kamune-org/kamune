package udppath

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/internal/udppath/udptest"
)

// fuzzSecret is the cookie secret of every FuzzServerInput server. Seeds
// can carry an INIT whose cookie validCookie accepts.
var fuzzSecret = bytes.Repeat([]byte{0x42}, secretLen)

// fuzzSources is the address set a fuzz input can send from. Index 1 is
// the IPv4-mapped form of index 0, so the two share a server source.
var fuzzSources = []netip.AddrPort{
	netip.MustParseAddrPort("203.0.113.8:40000"),
	netip.MustParseAddrPort("[::ffff:203.0.113.8]:40000"),
	netip.MustParseAddrPort("[2001:db8::8]:40000"),
	netip.MustParseAddrPort("198.51.100.8:9"),
	netip.MustParseAddrPort("[2001:db8::80]:9"),
	netip.MustParseAddrPort("192.0.2.8:443"),
	netip.MustParseAddrPort("[2001:db8:1::8]:443"),
	netip.MustParseAddrPort("203.0.113.80:65535"),
}

const (
	// fuzzMetaSource is the low bits of a frame's meta byte. They select
	// an entry of fuzzSources.
	fuzzMetaSource = 0x07
	// fuzzMetaGenuine asks FuzzClientInput to replace the datagram with
	// the genuine ACCEPT for the dialer's INIT.
	fuzzMetaGenuine = 0x10
	// fuzzMetaClock advances the server's fake clock and sends nothing.
	// The step is the first payload byte times 100ms.
	fuzzMetaClock = 0x20
	// fuzzMetaSeal replaces the payload with a sealed DATA or CLOSE for
	// the newest live path of that source. The first payload byte's low
	// bit picks CLOSE, the next 8 bytes are the counter, and the rest is
	// the KCP payload.
	fuzzMetaSeal = 0x40
	// fuzzMetaPatchCID asks FuzzClientInput to write the dialer's cid
	// into a datagram shaped as a COOKIE or an ACCEPT.
	fuzzMetaPatchCID = 0x80
	// fuzzAcceptSID is the server id of an ACCEPT the client harness builds.
	fuzzAcceptSID = 1
	// fuzzLiveCID is the client id of the server seeds that open a path.
	fuzzLiveCID = 7
)

// fuzzDatagram is one frame of a fuzz input.
type fuzzDatagram struct {
	pkt  []byte
	meta byte
}

// fuzzSaved is the newest ACCEPT a source has been sent, plus the cookie
// of the INIT that produced it.
type fuzzSaved struct {
	pkt     []byte
	keys    pathKeys
	cookie  [cookieLen]byte
	sid     uint32
	derived bool
	good    bool
}

// fuzzFrame prefixes pkt with a 2-byte big-endian length and a meta byte.
func fuzzFrame(meta byte, pkt []byte) []byte {
	out := make([]byte, 3+len(pkt))
	binary.BigEndian.PutUint16(out[:2], uint16(len(pkt)))
	out[2] = meta
	copy(out[3:], pkt)
	return out
}

// fuzzCat appends frames into one fuzz input.
func fuzzCat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// fuzzCtrBody is a seal-bit payload. lowBit 1 selects CLOSE. ctr is the
// packet counter the fuzzer wants the window to see.
func fuzzCtrBody(lowBit byte, ctr uint64, payload []byte) []byte {
	b := make([]byte, 1+8+len(payload))
	b[0] = lowBit
	binary.BigEndian.PutUint64(b[1:9], ctr)
	copy(b[9:], payload)
	return b
}

// splitFuzzDatagrams reads frames of uint16be length, one meta byte, then
// that many payload bytes. A frame whose payload is short is dropped, so
// a length counts only when every byte is present.
func splitFuzzDatagrams(in []byte) []fuzzDatagram {
	var out []fuzzDatagram
	for len(in) >= 3 {
		n := int(binary.BigEndian.Uint16(in))
		meta := in[2]
		in = in[3:]
		if len(in) < n {
			return out
		}
		out = append(out, fuzzDatagram{pkt: in[:n:n], meta: meta})
		in = in[n:]
	}
	return out
}

// fuzzClientKey returns the fixed X25519 key of the seed INITs.
func fuzzClientKey(t testing.TB) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatalf("client eph: %v", err)
	}
	return priv
}

// fuzzSealed builds a DATA or CLOSE opened by aead. rid is the receiver's
// id: the server path's sid, or the client path's cid. An empty body has
// no type bit, and the caller keeps the original datagram.
func fuzzSealed(aead cipher.AEAD, rid uint32, body []byte) ([]byte, bool) {
	if len(body) == 0 {
		return nil, false
	}
	typ := byte(typeData)
	if body[0]&1 == 1 {
		typ = typeClose
	}
	var ctr uint64
	rest := body[1:]
	if len(rest) >= 8 {
		ctr = binary.BigEndian.Uint64(rest[:8])
		rest = rest[8:]
	}
	var payload []byte
	if typ == typeData {
		if len(rest) == 0 {
			rest = []byte{0}
		}
		if len(rest) > KCPMTU {
			rest = rest[:KCPMTU]
		}
		payload = rest
	}
	return sealPacket(nil, aead, typ, rid, ctr, payload), true
}

// fuzzServer counts bytes on one server. in is what sources sent. out is
// what the server sent, including to addresses with no listener: the
// udptest filter runs before that drop.
type fuzzServer struct {
	s         *Server
	priv      *ecdh.PrivateKey
	clk       *clock.Fake
	srv       netip.AddrPort
	in        map[netip.AddrPort]int
	out       map[netip.AddrPort]int
	accepts   map[netip.AddrPort]fuzzSaved
	verified  map[initKey]struct{}
	armSrc    netip.AddrPort
	armCookie [cookieLen]byte
	armed     bool
	mu        sync.Mutex
}

// newFuzzServer starts a server on a fresh udptest network. The fake clock
// starts at testEpoch. Close runs when the test ends.
func newFuzzServer(t testing.TB, priv *ecdh.PrivateKey) *fuzzServer {
	t.Helper()
	n := udptest.New()
	pc, err := n.Listen("203.0.113.10:7000")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	clk := clock.NewFake(testEpoch)
	s, err := NewServer(pc, Config{Clock: clk})
	if err != nil {
		_ = pc.Close()
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if len(s.secret) != len(fuzzSecret) {
		t.Fatalf("secret is %d bytes", len(s.secret))
	}
	copy(s.secret, fuzzSecret)
	h := &fuzzServer{
		s:        s,
		priv:     priv,
		clk:      clk,
		srv:      listenAddr(s),
		in:       make(map[netip.AddrPort]int),
		out:      make(map[netip.AddrPort]int),
		accepts:  make(map[netip.AddrPort]fuzzSaved),
		verified: make(map[initKey]struct{}),
	}
	n.SetFilter(func(from, to netip.AddrPort, pkt []byte) int {
		if from != h.srv {
			return 1
		}
		h.mu.Lock()
		h.out[to] += len(pkt)
		if h.armed && to == h.armSrc &&
			len(pkt) == AcceptSize && pkt[0] == typeAccept {
			prev := h.accepts[to]
			if prev.pkt == nil || !bytes.Equal(prev.pkt, pkt) {
				h.accepts[to] = fuzzSaved{
					pkt:    bytes.Clone(pkt),
					cookie: h.armCookie,
				}
			}
		}
		h.mu.Unlock()
		return 1
	})
	return h
}

// recv records n bytes from src. src is the unmapped source the server uses.
func (h *fuzzServer) recv(src netip.AddrPort, n int) {
	h.mu.Lock()
	h.in[src] += n
	h.mu.Unlock()
}

// noteInit records src and the INIT's cid when validCookie accepts it.
// The server creates a path only after that check. The clock is the
// server's clock, so a clock frame changes the result.
func (h *fuzzServer) noteInit(src netip.AddrPort, pkt []byte) {
	m, err := parseInit(pkt)
	if err != nil {
		return
	}
	if !validCookie(h.s.secret, m.cookie, m.cid, src, h.s.clk.Now()) {
		return
	}
	h.verified[initKey{src: src, cid: m.cid}] = struct{}{}
}

// feed mirrors one iteration of reader.run. HELLO and INIT go to handshake
// on this goroutine, so the reply is written before feed returns. DATA,
// CLOSE and any other valid packet go to handle, as the reader does.
func (h *fuzzServer) feed(raw netip.AddrPort, pkt []byte) {
	switch classify(pkt) {
	case classKick, classForeign:
		h.recv(fuzzSourceKey(raw), len(pkt))
		return
	case classOurs:
	}
	src, ok := udpSource(net.UDPAddrFromAddrPort(raw))
	if !ok || !validPacket(pkt) {
		h.recv(fuzzSourceKey(raw), len(pkt))
		return
	}
	h.recv(src, len(pkt))
	if pkt[0] == typeInit {
		h.noteInit(src, pkt)
	}
	if pkt[0] == typeHello || pkt[0] == typeInit {
		h.answer(src, pkt)
		return
	}
	h.s.handle(src, pkt)
}

// answer runs handshake and remembers an ACCEPT sent for an INIT.
func (h *fuzzServer) answer(src netip.AddrPort, pkt []byte) {
	var cookie [cookieLen]byte
	arm := false
	if len(pkt) > 0 && pkt[0] == typeInit {
		if m, err := parseInit(pkt); err == nil {
			cookie = m.cookie
			arm = true
		}
	}
	if arm {
		h.mu.Lock()
		h.armSrc = src
		h.armCookie = cookie
		h.armed = true
		h.mu.Unlock()
	}
	h.s.handshake(src, pkt)
	if arm {
		h.mu.Lock()
		h.armed = false
		h.mu.Unlock()
	}
}

// seal replaces body with a packet the newest path of src can open.
// It keeps body when that path has no captured ACCEPT for this key.
func (h *fuzzServer) seal(src netip.AddrPort, body []byte) ([]byte, bool) {
	if len(body) == 0 {
		return nil, false
	}
	h.mu.Lock()
	saved, found := h.accepts[src]
	h.mu.Unlock()
	if !found {
		return nil, false
	}
	if !saved.derived {
		saved = h.derive(src, saved)
	}
	if !saved.good {
		return nil, false
	}
	h.s.mu.Lock()
	p := h.s.byID[saved.sid]
	live := p != nil && p.raddr == src && p.entry != nil && !p.entry.removed
	h.s.mu.Unlock()
	if !live {
		return nil, false
	}
	return fuzzSealed(saved.keys.c2s, saved.sid, body)
}

// derive caches clientKeys for a captured ACCEPT. A fuzzer INIT whose
// ephemeral key is not h.priv fails the tag check and is not sealed.
func (h *fuzzServer) derive(src netip.AddrPort, saved fuzzSaved) fuzzSaved {
	saved.derived = true
	msg, err := parseAccept(saved.pkt)
	if err != nil {
		h.store(src, saved)
		return saved
	}
	keys, err := clientKeys(h.priv, saved.cookie, saved.pkt, msg)
	if err != nil {
		h.store(src, saved)
		return saved
	}
	saved.keys = keys
	saved.sid = msg.sid
	saved.good = true
	h.store(src, saved)
	return saved
}

// store keeps saved when it is still the ACCEPT last captured for src.
func (h *fuzzServer) store(src netip.AddrPort, saved fuzzSaved) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cur, ok := h.accepts[src]
	if !ok || !bytes.Equal(cur.pkt, saved.pkt) {
		return
	}
	if cur.derived {
		return
	}
	h.accepts[src] = saved
}

// step applies one frame. A clock frame moves the fake clock and does not
// send. A seal frame becomes a DATA or CLOSE when an ACCEPT is known.
func (h *fuzzServer) step(dg fuzzDatagram) {
	if dg.meta&fuzzMetaClock != 0 {
		var n byte
		if len(dg.pkt) > 0 {
			n = dg.pkt[0]
		}
		h.clk.Advance(time.Duration(n) * 100 * time.Millisecond)
		return
	}
	src := fuzzSources[int(dg.meta&fuzzMetaSource)%len(fuzzSources)]
	pkt := dg.pkt
	if dg.meta&fuzzMetaSeal != 0 {
		if sealed, ok := h.seal(src, pkt); ok {
			pkt = sealed
		}
	}
	h.feed(src, pkt)
}

// run applies every frame of in.
func (h *fuzzServer) run(in []byte) {
	for _, dg := range splitFuzzDatagrams(in) {
		h.step(dg)
	}
}

// fuzzSourceKey is the unmapped source a datagram is counted against.
func fuzzSourceKey(raw netip.AddrPort) netip.AddrPort {
	src, ok := udpSource(net.UDPAddrFromAddrPort(raw))
	if !ok {
		return unmap(raw)
	}
	return src
}

// check checks the amplification invariant and that every path has a
// verified INIT. A source is unverified when no INIT from it had a cookie
// validCookie accepts.
func (h *fuzzServer) check(t *testing.T) {
	t.Helper()
	h.mu.Lock()
	in := make(map[netip.AddrPort]int, len(h.in))
	for src, n := range h.in {
		in[src] = n
	}
	out := make(map[netip.AddrPort]int, len(h.out))
	for dst, n := range h.out {
		out[dst] = n
	}
	h.mu.Unlock()

	verifiedSrc := make(map[netip.AddrPort]bool, len(h.verified))
	for key := range h.verified {
		verifiedSrc[key.src] = true
	}
	for dst, sent := range out {
		if verifiedSrc[dst] {
			continue
		}
		got := in[dst]
		if sent > got {
			t.Fatalf(
				"amplification to %s: sent %d, received %d",
				dst, sent, got,
			)
		}
	}

	h.s.mu.Lock()
	keys := make([]initKey, len(h.s.paths))
	for i, p := range h.s.paths {
		keys[i] = initKey{src: p.raddr, cid: p.cid}
	}
	h.s.mu.Unlock()
	for _, key := range keys {
		if _, ok := h.verified[key]; !ok {
			t.Fatalf(
				"path without a valid cookie: %s cid %d", key.src, key.cid,
			)
		}
	}
}

// fuzzServerLiveSeed is HELLO, a valid INIT, two DATA frames with counter
// 1, and a CLOSE with counter 2. The second DATA is a replay.
func fuzzServerLiveSeed(pub []byte) []byte {
	src := fuzzSources[0]
	cookie := makeCookie(
		fuzzSecret, testEpoch, fuzzLiveCID, fuzzSourceKey(src),
	)
	return fuzzCat(
		fuzzFrame(0, encodeHello(fuzzLiveCID, nil)),
		fuzzFrame(0, encodeInit(fuzzLiveCID, cookie, pub, nil)),
		fuzzFrame(fuzzMetaSeal, fuzzCtrBody(0, 1, []byte{1})),
		fuzzFrame(fuzzMetaSeal, fuzzCtrBody(0, 1, []byte{1})),
		fuzzFrame(fuzzMetaSeal, fuzzCtrBody(1, 2, nil)),
	)
}

// FuzzServerInput feeds framed datagrams from a fixed set of sources. Each
// input must not panic, must not amplify an unverified source, and must
// not leave a path whose INIT cookie validCookie rejects.
func FuzzServerInput(f *testing.F) {
	if !fuzzSources[1].Addr().Is4In6() {
		f.Fatalf("source 1 is %s, want an IPv4-mapped address", fuzzSources[1])
	}
	priv := fuzzClientKey(f)
	pub := priv.PublicKey().Bytes()
	f.Add([]byte{})
	f.Add(fuzzFrame(0, []byte{firstKick}))
	f.Add(fuzzFrame(1, encodeHello(fuzzLiveCID, nil)))
	f.Add(fuzzServerLiveSeed(pub))
	f.Add(fuzzFrame(fuzzMetaClock, []byte{60}))
	big := make([]byte, 65535)
	big[0] = typeHello
	big[1] = Version
	f.Add(fuzzFrame(2, big))
	data := make([]byte, DataOverhead+1)
	putHeader(data, typeData)
	binary.BigEndian.PutUint32(data[4:], 0xA1B2C3D4)
	binary.BigEndian.PutUint64(data[sealedCtr:], 1)
	f.Add(fuzzFrame(3, data))

	f.Fuzz(func(t *testing.T, in []byte) {
		h := newFuzzServer(t, priv)
		h.run(in)
		h.check(t)
	})
}

// TestFuzzServerSeedReachesInput checks the live seed: the first DATA
// queues the path, the second is a replay, and the CLOSE removes it.
func TestFuzzServerSeedReachesInput(t *testing.T) {
	a := require.New(t)
	priv := fuzzClientKey(t)
	h := newFuzzServer(t, priv)
	frames := splitFuzzDatagrams(fuzzServerLiveSeed(priv.PublicKey().Bytes()))
	a.Len(frames, 5)
	h.step(frames[0])
	h.step(frames[1])
	a.Equal(1, h.s.pathCount())
	h.step(frames[2])
	a.Equal(1, h.s.queuedCount())
	h.step(frames[3])
	a.Equal(uint64(1), h.s.Stats().Replay)
	a.Equal(1, h.s.queuedCount())
	h.step(frames[4])
	a.Zero(h.s.pathCount())
	a.Equal(uint64(1), h.s.Stats().CloseReceived)
	h.check(t)
}

// TestFuzzServerClockMoves checks that a clock frame is not a datagram and
// that a later INIT sees the new time. Six seconds expires a half-open
// path and still leaves the seed cookie inside its lifetime, so sweep runs.
func TestFuzzServerClockMoves(t *testing.T) {
	a := require.New(t)
	priv := fuzzClientKey(t)
	h := newFuzzServer(t, priv)
	pub := priv.PublicKey().Bytes()
	cookie := makeCookie(
		fuzzSecret, testEpoch, fuzzLiveCID, fuzzSourceKey(fuzzSources[0]),
	)
	h.run(fuzzFrame(0, encodeHello(fuzzLiveCID, nil)))
	h.run(fuzzFrame(0, encodeInit(fuzzLiveCID, cookie, pub, nil)))
	a.Equal(1, h.s.pathCount())
	h.run(fuzzFrame(fuzzMetaClock, []byte{60}))
	a.True(h.clk.Now().Equal(testEpoch.Add(6 * time.Second)))
	a.Equal(1, h.s.pathCount(), "a clock frame sends nothing")
	h.run(fuzzFrame(0, encodeInit(fuzzLiveCID, cookie, pub, nil)))
	a.Equal(uint64(1), h.s.Stats().Expired)
	a.Equal(1, h.s.pathCount())
	h.check(t)
}

// shapedHandshake reports whether pkt is long enough to carry the cid of
// a COOKIE or an ACCEPT.
func shapedHandshake(pkt []byte) bool {
	if len(pkt) < 8 {
		return false
	}
	return pkt[0] == typeCookie || pkt[0] == typeAccept
}

// genuineAccept is the ACCEPT responderAccept would send for the dialer's
// INIT. Its tag verifies. A mutated tag does not.
func genuineAccept(t *testing.T, d *dialer) acceptOut {
	t.Helper()
	m, err := parseInit(d.initPkt)
	if err != nil {
		t.Fatalf("parse dialer INIT: %v", err)
	}
	out, err := responderAccept(m, fuzzAcceptSID)
	if err != nil {
		t.Fatalf("responderAccept: %v", err)
	}
	return out
}

// feedClientPath mirrors reader.run for an established client path. src is
// the dialer's target.
func feedClientPath(p *Path, target netip.AddrPort, pkt []byte) {
	switch classify(pkt) {
	case classKick, classForeign:
		return
	case classOurs:
	}
	src, ok := udpSource(net.UDPAddrFromAddrPort(target))
	if !ok || !validPacket(pkt) {
		return
	}
	clientSocket{p: p}.handle(src, pkt)
}

// pathDone reports whether p has been closed.
func pathDone(p *Path) bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// fuzzReadClosed drains p without blocking and checks that ReadFrom then
// returns ErrPathClosed. p is already closed.
func fuzzReadClosed(t *testing.T, p *Path) {
	t.Helper()
	for {
		select {
		case in := <-p.in:
			inPool.Put(in.buf)
		default:
			_, _, err := p.ReadFrom(make([]byte, KCPMTU))
			if !errors.Is(err, ErrPathClosed) {
				t.Fatalf("ReadFrom after CLOSE: %v", err)
			}
			return
		}
	}
}

// fuzzClientLiveSeed establishes a path, then sends a sealed DATA and a
// sealed CLOSE. The CLOSE counter is past the DATA, so the path accepts it.
func fuzzClientLiveSeed() []byte {
	return fuzzCat(
		fuzzFrame(fuzzMetaPatchCID, encodeCookie(1, [cookieLen]byte{})),
		fuzzFrame(fuzzMetaGenuine, nil),
		fuzzFrame(fuzzMetaSeal, fuzzCtrBody(0, 1, []byte{'k'})),
		fuzzFrame(fuzzMetaSeal, fuzzCtrBody(1, 2, nil)),
	)
}

// FuzzClientInput feeds framed datagrams to a dialer that has sent its
// first HELLO. Before establishment, onPacket must not panic, must not
// return an error, and must return a path only for a genuine ACCEPT.
// After that, frames follow the client reader. A sealed CLOSE that the
// path accepts makes ReadFrom return ErrPathClosed once the queue is empty.
func FuzzClientInput(f *testing.F) {
	f.Add([]byte{})
	f.Add(fuzzFrame(0, []byte{firstKick}))
	f.Add(fuzzCat(
		fuzzFrame(fuzzMetaPatchCID, encodeCookie(1, [cookieLen]byte{})),
		fuzzFrame(fuzzMetaGenuine, nil),
	))
	f.Add(fuzzClientLiveSeed())
	big := make([]byte, 65535)
	big[0] = typeAccept
	f.Add(fuzzFrame(fuzzMetaPatchCID, big))

	f.Fuzz(func(t *testing.T, in []byte) {
		_ = runFuzzClient(t, in)
	})
}

// runFuzzClient drives one FuzzClientInput input. It returns the dialer's
// counters so a seed test can see that a sealed CLOSE reached the path.
func runFuzzClient(t *testing.T, in []byte) Stats {
	t.Helper()
	target := netip.MustParseAddrPort("203.0.113.50:9")
	n := udptest.New()
	pc, err := n.Listen("198.51.100.20:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = pc.Close() }()
	d := &dialer{
		pc:       pc,
		raddr:    target,
		raddrUDP: net.UDPAddrFromAddrPort(target),
		stats:    &counters{},
		budget:   MaxHellos,
	}
	now := testEpoch
	if err = d.startHello(now); err != nil {
		t.Fatalf("startHello: %v", err)
	}
	var live *Path
	var keys pathKeys
	defer func() {
		if live != nil {
			_ = live.Close()
		}
	}()
	for _, dg := range splitFuzzDatagrams(in) {
		if live != nil {
			feedEstablished(t, live, keys, target, dg)
			continue
		}
		pkt := dg.pkt
		if dg.meta&fuzzMetaPatchCID != 0 && shapedHandshake(pkt) {
			pkt = bytes.Clone(pkt)
			binary.BigEndian.PutUint32(pkt[4:], d.cid)
		}
		// The genuine bit replaces this datagram with the ACCEPT only the
		// dialer's private key can verify. A fuzzer cannot forge another
		// tag: the tag is ChaCha20-Poly1305 under a key derived from that
		// private key and a fresh server ephemeral.
		var genuine []byte
		var out acceptOut
		if dg.meta&fuzzMetaGenuine != 0 && d.step == initSent {
			out = genuineAccept(t, d)
			genuine = out.pkt
			pkt = genuine
		}
		p, err := d.onPacket(pkt, now)
		if err != nil {
			t.Fatalf("onPacket: %v", err)
		}
		if p != nil && !bytes.Equal(pkt, genuine) {
			t.Fatalf(
				"established on a packet that is not the genuine ACCEPT",
			)
		}
		if genuine != nil && p == nil {
			t.Fatalf("genuine ACCEPT did not establish")
		}
		if p != nil {
			live = p
			keys = out.keys
		}
	}
	return d.stats.snapshot()
}

// TestFuzzClientSeedCloses checks that the sealed CLOSE seed reaches the
// client path and that ReadFrom then returns ErrPathClosed.
func TestFuzzClientSeedCloses(t *testing.T) {
	a := require.New(t)
	st := runFuzzClient(t, fuzzClientLiveSeed())
	a.Equal(uint64(1), st.CloseReceived)
}

// feedEstablished sends one frame through the client path. A seal bit
// builds the packet with the server's send key, which is the client's
// receive key.
func feedEstablished(
	t *testing.T,
	p *Path,
	keys pathKeys,
	target netip.AddrPort,
	dg fuzzDatagram,
) {
	t.Helper()
	pkt := dg.pkt
	sealedClose := false
	if dg.meta&fuzzMetaSeal != 0 {
		sealed, ok := fuzzSealed(keys.s2c, p.cid, pkt)
		if ok {
			pkt = sealed
			sealedClose = pkt[0] == typeClose
		}
	}
	closed := pathDone(p)
	feedClientPath(p, target, pkt)
	if sealedClose && !closed && pathDone(p) {
		fuzzReadClosed(t, p)
	}
}
