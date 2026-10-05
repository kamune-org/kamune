package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A punchFilter passes on packets from the direct peer's IP, from a
// matched peer's IP until matchWindow after the match, whatever it sends
// meanwhile, and from the exact address of a held session until it is
// released. A peer matched on a token that is forgotten is not expected
// any more, though a session it holds is kept.
func TestPunchFilterAdmits(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.1")
	direct := netip.MustParseAddr("203.0.113.1")
	held := netip.MustParseAddrPort("198.51.100.1:4000")
	tests := []struct {
		name   string
		after  time.Duration
		forget bool
		src    netip.AddrPort
		admits bool
	}{
		{
			name:   "matched peer",
			src:    netip.AddrPortFrom(peer, 1234),
			admits: true,
		},
		{
			name:   "matched peer near the window's end",
			after:  matchWindow - time.Second,
			src:    netip.AddrPortFrom(peer, 1),
			admits: true,
		},
		{
			name:  "matched peer after the window",
			after: matchWindow,
			src:   netip.AddrPortFrom(peer, 1234),
		},
		{
			name:   "matched peer whose token was removed",
			forget: true,
			src:    netip.AddrPortFrom(peer, 1234),
		},
		{
			name: "other address",
			src:  netip.MustParseAddrPort("192.0.2.2:1234"),
		},
		{
			name:   "held session",
			after:  matchWindow * 10,
			forget: true,
			src:    held,
			admits: true,
		},
		{
			name: "other port of a held session",
			src:  netip.AddrPortFrom(held.Addr(), 4001),
		},
		{
			name:   "direct peer",
			after:  matchWindow * 10,
			src:    netip.AddrPortFrom(direct, 5),
			admits: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			now := time.Unix(1000, 0)
			f := newPunchFilter(nil)
			f.now = func() time.Time { return now }
			f.direct = direct
			f.expect(peer, "token")
			f.hold(net.UDPAddrFromAddrPort(held))
			// Packets from the matched peer do not renew its window.
			now = now.Add(tt.after / 2)
			f.admits(netip.AddrPortFrom(peer, 1234))
			now = now.Add(tt.after - tt.after/2)
			if tt.forget {
				f.forget("token")
			}
			a.Equal(tt.admits, f.admits(tt.src))
		})
	}
}

// A held address is dropped once each of its holds is released, and
// each hold is released once.
func TestPunchFilterRelease(t *testing.T) {
	a := require.New(t)
	f := newPunchFilter(nil)
	src := netip.MustParseAddrPort("198.51.100.1:4000")
	r1 := f.hold(net.UDPAddrFromAddrPort(src))
	r2 := f.hold(net.UDPAddrFromAddrPort(src))
	r1()
	r1()
	a.True(f.admits(src))
	r2()
	a.False(f.admits(src))
}

// A punchFilter expects at most maxMatchedPeers peers and drops the one
// expected the longest first.
func TestPunchFilterMatchedCap(t *testing.T) {
	a := require.New(t)
	now := time.Unix(1000, 0)
	f := newPunchFilter(nil)
	f.now = func() time.Time { return now }
	ip := func(i int) netip.Addr {
		return netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
	}
	for i := range maxMatchedPeers + 1 {
		f.expect(ip(i), "token")
		now = now.Add(time.Millisecond)
	}
	a.Len(f.matched, maxMatchedPeers)
	a.False(f.admits(netip.AddrPortFrom(ip(0), 1)))
	a.True(f.admits(netip.AddrPortFrom(ip(maxMatchedPeers), 1)))
}
