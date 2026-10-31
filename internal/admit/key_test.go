package admit_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/admit"
)

// stringAddr is a net.Addr with a fixed string form.
type stringAddr string

func (stringAddr) Network() string  { return "test" }
func (a stringAddr) String() string { return string(a) }

func TestSourceKey(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		source  string
		network string
	}{
		{
			name:    "ipv4",
			addr:    "192.0.2.7:4000",
			source:  "192.0.2.7",
			network: "192.0.2.0/24",
		},
		{
			name:    "ipv4-mapped ipv6",
			addr:    "[::ffff:192.0.2.7]:4000",
			source:  "192.0.2.7",
			network: "192.0.2.0/24",
		},
		{
			name:    "ipv6",
			addr:    "[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:4000",
			source:  "2001:db8:1:2::/64",
			network: "2001:db8:1::/48",
		},
		{
			name:    "ipv6 with zone",
			addr:    "[fe80::1%eth0]:4000",
			source:  "fe80::/64",
			network: "fe80::/48",
		},
		{
			name:    "ipv6 without port",
			addr:    "2001:db8::1",
			source:  "2001:db8::/64",
			network: "2001:db8::/48",
		},
		{
			name:    "host name",
			addr:    "example.com:80",
			source:  "example.com",
			network: "example.com",
		},
		{
			name:    "not an ip address",
			addr:    "pipe",
			source:  "pipe",
			network: "pipe",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tc.source, admit.SourceKey(stringAddr(tc.addr)))
			a.Equal(tc.network, admit.NetworkKey(stringAddr(tc.addr)))
		})
	}

	addrPorts := []struct {
		name    string
		addr    string
		source  string
		network string
	}{
		{
			name:    "addrport ipv4",
			addr:    "192.0.2.7:4000",
			source:  "192.0.2.7",
			network: "192.0.2.0/24",
		},
		{
			name:    "addrport ipv4-mapped ipv6",
			addr:    "[::ffff:192.0.2.7]:4000",
			source:  "192.0.2.7",
			network: "192.0.2.0/24",
		},
	}
	for _, tc := range addrPorts {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			ap := netip.MustParseAddrPort(tc.addr)
			a.Equal(tc.source, admit.SourceKeyAddrPort(ap))
			a.Equal(tc.network, admit.NetworkKeyAddrPort(ap))
		})
	}
}
