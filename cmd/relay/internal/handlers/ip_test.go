package handlers

import (
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// ParseForwardedIP
// ---------------------------------------------------------------------------

func TestParseForwardedIP_Empty(t *testing.T) {
	a := assert.New(t)
	a.Equal("", ParseForwardedIP(""))
}

func TestParseForwardedIP_SinglePublicIP(t *testing.T) {
	a := assert.New(t)
	a.Equal("203.0.113.50", ParseForwardedIP("203.0.113.50"))
}

func TestParseForwardedIP_SinglePublicIPWithPort(t *testing.T) {
	a := assert.New(t)
	a.Equal("203.0.113.50", ParseForwardedIP("203.0.113.50:8080"))
}

func TestParseForwardedIP_MultiplePublicIPs(t *testing.T) {
	a := assert.New(t)
	// Left-most public IP should be returned.
	a.Equal("203.0.113.50", ParseForwardedIP("203.0.113.50, 70.41.3.18, 150.172.238.178"))
}

func TestParseForwardedIP_PrivateThenPublic(t *testing.T) {
	a := assert.New(t)
	// Should skip private 10.x and return first public.
	a.Equal("203.0.113.50", ParseForwardedIP("10.0.0.1, 203.0.113.50"))
}

func TestParseForwardedIP_MultiplePrivateThenPublic(t *testing.T) {
	a := assert.New(t)
	a.Equal("8.8.8.8", ParseForwardedIP("192.168.1.1, 10.0.0.2, 8.8.8.8"))
}

func TestParseForwardedIP_AllPrivate(t *testing.T) {
	a := assert.New(t)
	// When everything is private, return the left-most valid IP.
	a.Equal("192.168.1.1", ParseForwardedIP("192.168.1.1, 10.0.0.1"))
}

func TestParseForwardedIP_Loopback(t *testing.T) {
	a := assert.New(t)
	// Loopback is private; if it's the only entry, return it as fallback.
	a.Equal("127.0.0.1", ParseForwardedIP("127.0.0.1"))
}

func TestParseForwardedIP_LoopbackThenPublic(t *testing.T) {
	a := assert.New(t)
	a.Equal("93.184.216.34", ParseForwardedIP("127.0.0.1, 93.184.216.34"))
}

func TestParseForwardedIP_IPv6Public(t *testing.T) {
	a := assert.New(t)
	result := ParseForwardedIP("2001:db8::1")
	a.Equal("2001:db8::1", result)
}

func TestParseForwardedIP_IPv6Private(t *testing.T) {
	a := assert.New(t)
	// fc00::/7 is private; when followed by a public one, skip it.
	a.Equal("2001:db8::1", ParseForwardedIP("fd00::1, 2001:db8::1"))
}

func TestParseForwardedIP_IPv6Loopback(t *testing.T) {
	a := assert.New(t)
	a.Equal("2001:db8::2", ParseForwardedIP("::1, 2001:db8::2"))
}

func TestParseForwardedIP_GarbageEntries(t *testing.T) {
	a := assert.New(t)
	// Invalid entries should be skipped.
	a.Equal("1.2.3.4", ParseForwardedIP("not-an-ip, , 1.2.3.4"))
}

func TestParseForwardedIP_AllGarbage(t *testing.T) {
	a := assert.New(t)
	a.Equal("", ParseForwardedIP("not-an-ip, also-bad"))
}

func TestParseForwardedIP_WhitespaceHandling(t *testing.T) {
	a := assert.New(t)
	a.Equal("1.2.3.4", ParseForwardedIP("  1.2.3.4  "))
	a.Equal("1.2.3.4", ParseForwardedIP("  1.2.3.4  ,  5.6.7.8  "))
}

func TestParseForwardedIP_PortInList(t *testing.T) {
	a := assert.New(t)
	a.Equal("203.0.113.50", ParseForwardedIP("10.0.0.1:1234, 203.0.113.50:5678"))
}

func TestParseForwardedIP_LinkLocal(t *testing.T) {
	a := assert.New(t)
	// 169.254.x.x is link-local (private), should be skipped.
	a.Equal("8.8.4.4", ParseForwardedIP("169.254.1.1, 8.8.4.4"))
}

func TestParseForwardedIP_172Private(t *testing.T) {
	a := assert.New(t)
	// 172.16.0.0/12 is private.
	a.Equal("5.5.5.5", ParseForwardedIP("172.16.0.1, 172.31.255.255, 5.5.5.5"))
	// 172.32.x is NOT private.
	a.Equal("172.32.0.1", ParseForwardedIP("172.32.0.1, 5.5.5.5"))
}

// ---------------------------------------------------------------------------
// clientIP
// ---------------------------------------------------------------------------

func newRequest(headers map[string]string, remoteAddr string) *http.Request {
	r, _ := http.NewRequest("GET", "/ip", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestClientIP_XRealIP(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{"X-Real-Ip": "93.184.216.34"}, "10.0.0.1:12345")
	a.Equal("93.184.216.34", clientIP(r))
}

func TestClientIP_XRealIPWithPort(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{"X-Real-Ip": "93.184.216.34:8080"}, "10.0.0.1:12345")
	a.Equal("93.184.216.34", clientIP(r))
}

func TestClientIP_TrueClientIP(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{"True-Client-IP": "1.2.3.4"}, "10.0.0.1:12345")
	a.Equal("1.2.3.4", clientIP(r))
}

func TestClientIP_CFConnectingIP(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{"CF-Connecting-IP": "104.16.0.1"}, "10.0.0.1:12345")
	a.Equal("104.16.0.1", clientIP(r))
}

func TestClientIP_FlyClientIP(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{"Fly-Client-IP": "5.6.7.8"}, "10.0.0.1:12345")
	a.Equal("5.6.7.8", clientIP(r))
}

func TestClientIP_FastlyClientIP(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{"Fastly-Client-IP": "9.10.11.12"}, "10.0.0.1:12345")
	a.Equal("9.10.11.12", clientIP(r))
}

func TestClientIP_XForwardedFor(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{"X-Forwarded-For": "203.0.113.50, 10.0.0.1"}, "10.0.0.1:12345")
	a.Equal("203.0.113.50", clientIP(r))
}

func TestClientIP_FallbackToRemoteAddr(t *testing.T) {
	a := assert.New(t)
	r := newRequest(nil, "198.51.100.1:54321")
	a.Equal("198.51.100.1", clientIP(r))
}

func TestClientIP_FallbackToRemoteAddrNoPort(t *testing.T) {
	a := assert.New(t)
	r := newRequest(nil, "198.51.100.1")
	a.Equal("198.51.100.1", clientIP(r))
}

func TestClientIP_HeaderPriority_XRealIPOverXFF(t *testing.T) {
	a := assert.New(t)
	// X-Real-Ip should take priority over X-Forwarded-For.
	r := newRequest(map[string]string{
		"X-Real-Ip":       "1.1.1.1",
		"X-Forwarded-For": "2.2.2.2",
	}, "10.0.0.1:12345")
	a.Equal("1.1.1.1", clientIP(r))
}

func TestClientIP_HeaderPriority_TrueClientIPOverCF(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{
		"True-Client-IP":   "3.3.3.3",
		"CF-Connecting-IP": "4.4.4.4",
	}, "10.0.0.1:12345")
	a.Equal("3.3.3.3", clientIP(r))
}

func TestClientIP_XFFSkipsPrivateReturnsPublic(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{
		"X-Forwarded-For": "192.168.1.1, 10.0.0.5, 8.8.8.8",
	}, "10.0.0.1:12345")
	a.Equal("8.8.8.8", clientIP(r))
}

func TestClientIP_InvalidXRealIPFallsThrough(t *testing.T) {
	a := assert.New(t)
	// Invalid X-Real-Ip should be skipped, falling through to XFF.
	r := newRequest(map[string]string{
		"X-Real-Ip":       "not-a-valid-ip",
		"X-Forwarded-For": "4.4.4.4",
	}, "10.0.0.1:12345")
	a.Equal("4.4.4.4", clientIP(r))
}

func TestClientIP_IPv6RemoteAddr(t *testing.T) {
	a := assert.New(t)
	r := newRequest(nil, "[2001:db8::1]:12345")
	a.Equal("2001:db8::1", clientIP(r))
}

func TestClientIP_IPv6XRealIP(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{"X-Real-Ip": "2001:db8::1"}, "[::1]:12345")
	a.Equal("2001:db8::1", clientIP(r))
}

func TestClientIP_AllHeadersEmpty(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{
		"X-Real-Ip":        "",
		"True-Client-IP":   "",
		"CF-Connecting-IP": "",
		"Fly-Client-IP":    "",
		"Fastly-Client-IP": "",
		"X-Forwarded-For":  "",
	}, "192.0.2.1:9999")
	a.Equal("192.0.2.1", clientIP(r))
}

// ---------------------------------------------------------------------------
// extractIP
// ---------------------------------------------------------------------------

func TestExtractIP_BareIPv4(t *testing.T) {
	a := assert.New(t)
	a.Equal("1.2.3.4", extractIP("1.2.3.4"))
}

func TestExtractIP_IPv4WithPort(t *testing.T) {
	a := assert.New(t)
	a.Equal("1.2.3.4", extractIP("1.2.3.4:8080"))
}

func TestExtractIP_BareIPv6(t *testing.T) {
	a := assert.New(t)
	a.Equal("::1", extractIP("::1"))
}

func TestExtractIP_IPv6WithPort(t *testing.T) {
	a := assert.New(t)
	a.Equal("::1", extractIP("[::1]:8080"))
}

func TestExtractIP_Empty(t *testing.T) {
	a := assert.New(t)
	a.Equal("", extractIP(""))
}

func TestExtractIP_Whitespace(t *testing.T) {
	a := assert.New(t)
	a.Equal("1.2.3.4", extractIP("  1.2.3.4  "))
}

// ---------------------------------------------------------------------------
// validateIP
// ---------------------------------------------------------------------------

func TestValidateIP_ValidIPv4(t *testing.T) {
	a := assert.New(t)
	a.Equal("1.2.3.4", validateIP("1.2.3.4"))
}

func TestValidateIP_ValidIPv4WithPort(t *testing.T) {
	a := assert.New(t)
	a.Equal("1.2.3.4", validateIP("1.2.3.4:80"))
}

func TestValidateIP_ValidIPv6(t *testing.T) {
	a := assert.New(t)
	a.Equal("2001:db8::1", validateIP("2001:db8::1"))
}

func TestValidateIP_Invalid(t *testing.T) {
	a := assert.New(t)
	a.Equal("", validateIP("not-an-ip"))
}

func TestValidateIP_Empty(t *testing.T) {
	a := assert.New(t)
	a.Equal("", validateIP(""))
}

func TestValidateIP_Hostname(t *testing.T) {
	a := assert.New(t)
	a.Equal("", validateIP("example.com"))
}

// ---------------------------------------------------------------------------
// isPrivateIP
// ---------------------------------------------------------------------------

func TestIsPrivateIP_RFC1918_10(t *testing.T) {
	a := assert.New(t)
	a.True(isPrivateIP(net.ParseIP("10.0.0.1")))
	a.True(isPrivateIP(net.ParseIP("10.255.255.255")))
}

func TestIsPrivateIP_RFC1918_172(t *testing.T) {
	a := assert.New(t)
	a.True(isPrivateIP(net.ParseIP("172.16.0.1")))
	a.True(isPrivateIP(net.ParseIP("172.31.255.255")))
	a.False(isPrivateIP(net.ParseIP("172.32.0.1")))
}

func TestIsPrivateIP_RFC1918_192(t *testing.T) {
	a := assert.New(t)
	a.True(isPrivateIP(net.ParseIP("192.168.0.1")))
	a.True(isPrivateIP(net.ParseIP("192.168.255.255")))
}

func TestIsPrivateIP_Loopback(t *testing.T) {
	a := assert.New(t)
	a.True(isPrivateIP(net.ParseIP("127.0.0.1")))
	a.True(isPrivateIP(net.ParseIP("127.255.255.255")))
}

func TestIsPrivateIP_LinkLocal(t *testing.T) {
	a := assert.New(t)
	a.True(isPrivateIP(net.ParseIP("169.254.0.1")))
	a.True(isPrivateIP(net.ParseIP("169.254.255.255")))
}

func TestIsPrivateIP_IPv6Loopback(t *testing.T) {
	a := assert.New(t)
	a.True(isPrivateIP(net.ParseIP("::1")))
}

func TestIsPrivateIP_IPv6ULA(t *testing.T) {
	a := assert.New(t)
	a.True(isPrivateIP(net.ParseIP("fd00::1")))
	a.True(isPrivateIP(net.ParseIP("fc00::1")))
}

func TestIsPrivateIP_IPv6LinkLocal(t *testing.T) {
	a := assert.New(t)
	a.True(isPrivateIP(net.ParseIP("fe80::1")))
}

func TestIsPrivateIP_PublicIPv4(t *testing.T) {
	a := assert.New(t)
	a.False(isPrivateIP(net.ParseIP("8.8.8.8")))
	a.False(isPrivateIP(net.ParseIP("93.184.216.34")))
	a.False(isPrivateIP(net.ParseIP("1.1.1.1")))
}

func TestIsPrivateIP_PublicIPv6(t *testing.T) {
	a := assert.New(t)
	a.False(isPrivateIP(net.ParseIP("2001:db8::1")))
	a.False(isPrivateIP(net.ParseIP("2606:4700::1111")))
}

// ---------------------------------------------------------------------------
// singleHeader
// ---------------------------------------------------------------------------

func TestSingleHeader_Present(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{"X-Real-Ip": "1.2.3.4"}, "")
	a.Equal("1.2.3.4", singleHeader(r, "X-Real-Ip"))
}

func TestSingleHeader_Missing(t *testing.T) {
	a := assert.New(t)
	r := newRequest(nil, "")
	a.Equal("", singleHeader(r, "X-Real-Ip"))
}

func TestSingleHeader_Invalid(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{"X-Real-Ip": "garbage"}, "")
	a.Equal("", singleHeader(r, "X-Real-Ip"))
}

func TestSingleHeader_WithPort(t *testing.T) {
	a := assert.New(t)
	r := newRequest(map[string]string{"X-Real-Ip": "1.2.3.4:9090"}, "")
	a.Equal("1.2.3.4", singleHeader(r, "X-Real-Ip"))
}
