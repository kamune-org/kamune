package handlers

import (
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// clientIP
// ---------------------------------------------------------------------------

type headerLine struct{ name, value string }

func newRequest(remoteAddr string, lines ...headerLine) *http.Request {
	r, _ := http.NewRequest("GET", "/ip", nil)
	r.RemoteAddr = remoteAddr
	for _, l := range lines {
		r.Header.Add(l.name, l.value)
	}
	return r
}

var testTrustedProxies = func() []*net.IPNet {
	var ranges []*net.IPNet
	for _, cidr := range []string{"10.0.0.0/8", "127.0.0.0/8", "::1/128"} {
		_, block, _ := net.ParseCIDR(cidr)
		ranges = append(ranges, block)
	}
	return ranges
}()

func TestClientIP(t *testing.T) {
	const (
		xff = "X-Forwarded-For"
		cf  = "Cf-Connecting-Ip"
		xri = "X-Real-Ip"
	)
	tests := []struct {
		name   string
		remote string
		header string
		lines  []headerLine
		want   string
	}{
		{
			name:   "untrusted peer ignores headers",
			remote: "198.51.100.1:12345",
			header: xff,
			lines: []headerLine{
				{xff, "203.0.113.50"},
				{xri, "203.0.113.51"},
			},
			want: "198.51.100.1",
		},
		{
			name:   "untrusted peer without port",
			remote: "198.51.100.1",
			header: xff,
			want:   "198.51.100.1",
		},
		{
			name:   "untrusted ipv6 peer",
			remote: "[2001:db8::1]:12345",
			header: xff,
			want:   "2001:db8::1",
		},
		{
			name:   "client x-real-ip does not override x-forwarded-for",
			remote: "127.0.0.1:12345",
			header: xff,
			lines: []headerLine{
				{cf, "198.51.100.7"},
				{xff, "203.0.113.50, 198.51.100.7"},
				{xri, "203.0.113.99"},
			},
			want: "198.51.100.7",
		},
		{
			name:   "configured cf-connecting-ip ignores spoofed headers",
			remote: "127.0.0.1:12345",
			header: cf,
			lines: []headerLine{
				{cf, "198.51.100.7"},
				{xff, "203.0.113.50"},
				{xri, "203.0.113.99"},
			},
			want: "198.51.100.7",
		},
		{
			name:   "configured header missing falls back to peer",
			remote: "127.0.0.1:12345",
			header: cf,
			lines:  []headerLine{{xri, "203.0.113.99"}},
			want:   "127.0.0.1",
		},
		{
			name:   "configured single header with port",
			remote: "10.0.0.1:12345",
			header: xri,
			lines:  []headerLine{{xri, "93.184.216.34:8080"}},
			want:   "93.184.216.34",
		},
		{
			name:   "configured single header ipv6",
			remote: "[::1]:12345",
			header: xri,
			lines:  []headerLine{{xri, "2001:db8::1"}},
			want:   "2001:db8::1",
		},
		{
			name:   "single header sent twice is not trusted",
			remote: "10.0.0.1:12345",
			header: xri,
			lines: []headerLine{
				{xri, "203.0.113.99"},
				{xri, "198.51.100.7"},
			},
			want: "10.0.0.1",
		},
		{
			name:   "single header holding a list is not trusted",
			remote: "10.0.0.1:12345",
			header: xri,
			lines:  []headerLine{{xri, "203.0.113.99, 198.51.100.7"}},
			want:   "10.0.0.1",
		},
		{
			name:   "single header garbage falls back to peer",
			remote: "10.0.0.1:12345",
			header: xri,
			lines:  []headerLine{{xri, "not-a-valid-ip"}},
			want:   "10.0.0.1",
		},
		{
			name:   "x-forwarded-for single entry",
			remote: "10.0.0.1:12345",
			header: xff,
			lines:  []headerLine{{xff, "203.0.113.50"}},
			want:   "203.0.113.50",
		},
		{
			name:   "x-forwarded-for skips trusted hops from the right",
			remote: "10.0.0.1:12345",
			header: xff,
			lines:  []headerLine{{xff, "192.0.2.9, 203.0.113.8, 10.0.0.2"}},
			want:   "203.0.113.8",
		},
		{
			name:   "x-forwarded-for takes the right-most untrusted entry",
			remote: "10.0.0.1:12345",
			header: xff,
			lines:  []headerLine{{xff, "192.168.1.1, 10.0.0.5, 8.8.8.8"}},
			want:   "8.8.8.8",
		},
		{
			name:   "x-forwarded-for reads every header line",
			remote: "10.0.0.1:12345",
			header: xff,
			lines: []headerLine{
				{xff, "203.0.113.99"},
				{xff, "198.51.100.7"},
			},
			want: "198.51.100.7",
		},
		{
			name:   "x-forwarded-for entry with port",
			remote: "10.0.0.1:12345",
			header: xff,
			lines:  []headerLine{{xff, "203.0.113.50:5678"}},
			want:   "203.0.113.50",
		},
		{
			name:   "x-forwarded-for garbage stops the search",
			remote: "10.0.0.1:12345",
			header: xff,
			lines:  []headerLine{{xff, "203.0.113.99, not-an-ip, 10.0.0.2"}},
			want:   "10.0.0.1",
		},
		{
			name:   "x-forwarded-for all trusted falls back to peer",
			remote: "10.0.0.1:12345",
			header: xff,
			lines:  []headerLine{{xff, "10.0.0.3, 10.0.0.2"}},
			want:   "10.0.0.1",
		},
		{
			name:   "x-forwarded-for missing falls back to peer",
			remote: "10.0.0.1:12345",
			header: xff,
			lines:  []headerLine{{xri, "203.0.113.99"}},
			want:   "10.0.0.1",
		},
		{
			name:   "x-forwarded-for empty falls back to peer",
			remote: "10.0.0.1:12345",
			header: xff,
			lines:  []headerLine{{xff, ""}},
			want:   "10.0.0.1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			r := newRequest(tc.remote, tc.lines...)
			a.Equal(tc.want, clientIP(r, testTrustedProxies, tc.header))
		})
	}
}

// ---------------------------------------------------------------------------
// extractIP
// ---------------------------------------------------------------------------

func TestExtractIP_BareIPv4(t *testing.T) {
	a := require.New(t)
	a.Equal("1.2.3.4", extractIP("1.2.3.4"))
}

func TestExtractIP_IPv4WithPort(t *testing.T) {
	a := require.New(t)
	a.Equal("1.2.3.4", extractIP("1.2.3.4:8080"))
}

func TestExtractIP_BareIPv6(t *testing.T) {
	a := require.New(t)
	a.Equal("::1", extractIP("::1"))
}

func TestExtractIP_IPv6WithPort(t *testing.T) {
	a := require.New(t)
	a.Equal("::1", extractIP("[::1]:8080"))
}

func TestExtractIP_Empty(t *testing.T) {
	a := require.New(t)
	a.Equal("", extractIP(""))
}

func TestExtractIP_Whitespace(t *testing.T) {
	a := require.New(t)
	a.Equal("1.2.3.4", extractIP("  1.2.3.4  "))
}

// ---------------------------------------------------------------------------
// validateIP
// ---------------------------------------------------------------------------

func TestValidateIP_ValidIPv4(t *testing.T) {
	a := require.New(t)
	a.Equal("1.2.3.4", validateIP("1.2.3.4"))
}

func TestValidateIP_ValidIPv4WithPort(t *testing.T) {
	a := require.New(t)
	a.Equal("1.2.3.4", validateIP("1.2.3.4:80"))
}

func TestValidateIP_ValidIPv6(t *testing.T) {
	a := require.New(t)
	a.Equal("2001:db8::1", validateIP("2001:db8::1"))
}

func TestValidateIP_Invalid(t *testing.T) {
	a := require.New(t)
	a.Equal("", validateIP("not-an-ip"))
}

func TestValidateIP_Empty(t *testing.T) {
	a := require.New(t)
	a.Equal("", validateIP(""))
}

func TestValidateIP_Hostname(t *testing.T) {
	a := require.New(t)
	a.Equal("", validateIP("example.com"))
}

// ---------------------------------------------------------------------------
// rateLimitKey
// ---------------------------------------------------------------------------

func TestRateLimitKey(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{ip: "203.0.113.7", want: "203.0.113.7"},
		{ip: "::ffff:203.0.113.7", want: "203.0.113.7"},
		{ip: "2001:db8:1:2::1", want: "2001:db8:1:2::/64"},
		{ip: "2001:db8:1:2:aaaa:bbbb:cccc:dddd", want: "2001:db8:1:2::/64"},
		{ip: "2001:db8:1:3::1", want: "2001:db8:1:3::/64"},
		{ip: "fe80::1%eth0", want: "fe80::/64"},
		{ip: "::1", want: "::/64"},
		{ip: "pipe", want: "pipe"},
		{ip: "", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			require.New(t).Equal(tc.want, rateLimitKey(tc.ip))
		})
	}
}
