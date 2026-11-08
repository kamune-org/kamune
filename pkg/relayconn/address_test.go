package relayconn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/relayconn/relayleg"
)

func fixedRelayKey() relayleg.PublicKey {
	var k relayleg.PublicKey
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func fixedCertPin() []byte {
	pin := make([]byte, sha256.Size)
	for i := range pin {
		pin[i] = byte(i + 1)
	}
	return pin
}

func colonFingerprint(pin []byte) string {
	const digits = "0123456789ABCDEF"
	var b strings.Builder
	for i, c := range pin {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteByte(digits[c>>4])
		b.WriteByte(digits[c&0x0f])
	}
	return b.String()
}

// dnsOfLen builds a DNS name of n letters and dots. Every label is
// LDH and the last label is not all digits.
func dnsOfLen(n int) string {
	var parts []string
	left := n
	for left > 0 {
		size := left
		if size > 63 {
			size = 63
		}
		if size == left {
			parts = append(parts, strings.Repeat("a", size))
			break
		}
		if left-size == 1 {
			size--
		}
		parts = append(parts, strings.Repeat("a", size))
		left -= size + 1
	}
	return strings.Join(parts, ".")
}

type addrCase struct {
	name    string
	in      string
	want    Address
	str     string
	store   string
	display string
	bad     bool
}

type addrFix struct {
	key    relayleg.PublicKey
	pin    []byte
	pinHex string
	rk     string
}

func newAddrFix() *addrFix {
	key := fixedRelayKey()
	pin := fixedCertPin()
	return &addrFix{
		key:    key,
		pin:    pin,
		pinHex: hex.EncodeToString(pin),
		rk:     key.String(),
	}
}

func makeAddr(
	scheme, host, path string,
	key *relayleg.PublicKey,
	pin []byte,
	skip bool,
) Address {
	return Address{
		Scheme:        scheme,
		Host:          host,
		Path:          path,
		RelayKey:      key,
		CertPin:       bytes.Clone(pin),
		SkipTLSVerify: skip,
	}
}

func (f *addrFix) ok(
	name, in, scheme, host, path string,
	hasKey, hasPin, skip bool,
) addrCase {
	var key *relayleg.PublicKey
	var pin []byte
	if hasKey {
		key = &f.key
	}
	if hasPin {
		pin = f.pin
	}
	str := scheme + "://" + host
	display := str
	store := host
	if path != "" && path != "/ws" {
		str += path
		display += path
		store += path
	}
	var params []string
	if hasKey {
		params = append(params, "rk="+f.rk)
	}
	if hasPin {
		params = append(params, "cert="+f.pinHex)
	}
	if skip {
		params = append(params, "tls=skip")
	}
	if len(params) > 0 {
		str += "?" + strings.Join(params, "&")
	}
	if skip {
		display += "?tls=skip"
	}
	return addrCase{
		name:    name,
		in:      in,
		want:    makeAddr(scheme, host, path, key, pin, skip),
		str:     str,
		store:   store,
		display: display,
	}
}

func bad(name, in string) addrCase {
	return addrCase{name: name, in: in, bad: true}
}

func addressCases() []addrCase {
	f := newAddrFix()
	label63 := strings.Repeat("a", 63) + ".com"
	label64 := strings.Repeat("b", 64) + ".com"
	name253 := dnsOfLen(253)
	name254 := dnsOfLen(254)
	var zero relayleg.PublicKey
	return []addrCase{
		{
			name:    "anchor bare",
			in:      "Example.COM.",
			want:    makeAddr("wss", "example.com:443", "/ws", nil, nil, false),
			str:     "wss://example.com:443",
			store:   "example.com:443",
			display: "wss://example.com:443",
		},
		{
			name:    "anchor skip",
			in:      "WSS://Example.COM./?tls=skip",
			want:    makeAddr("wss", "example.com:443", "/ws", nil, nil, true),
			str:     "wss://example.com:443?tls=skip",
			store:   "example.com:443",
			display: "wss://example.com:443?tls=skip",
		},
		{
			name: "anchor order",
			in: "wss://example.com/ws?cert=" + f.pinHex +
				"&rk=" + f.key.Display(),
			want: makeAddr(
				"wss", "example.com:443", "/ws", &f.key, f.pin, false,
			),
			str: "wss://example.com:443?rk=" + f.rk +
				"&cert=" + f.pinHex,
			store:   "example.com:443",
			display: "wss://example.com:443",
		},
		f.ok("bare", "example.com",
			"wss", "example.com:443", "/ws", false, false, false),
		f.ok("wss", "wss://example.com",
			"wss", "example.com:443", "/ws", false, false, false),
		f.ok("case dot", "WSS://Example.COM.",
			"wss", "example.com:443", "/ws", false, false, false),
		f.ok("ws", "ws://example.com",
			"ws", "example.com:80", "/ws", false, false, false),
		f.ok("ws explicit", "ws://example.com:80",
			"ws", "example.com:80", "/ws", false, false, false),
		f.ok("wss explicit", "wss://example.com:443",
			"wss", "example.com:443", "/ws", false, false, false),
		f.ok("port 8443", "wss://example.com:8443/Kamune",
			"wss", "example.com:8443", "/Kamune", false, false, false),
		f.ok("tls", "tls://example.com:8890",
			"tls", "example.com:8890", "", false, false, false),
		f.ok("tcp", "tcp://example.com:8891",
			"tcp", "example.com:8891", "", false, false, false),
		f.ok("tcp case", "TCP://Example.COM.:9",
			"tcp", "example.com:9", "", false, false, false),
		f.ok("slash", "wss://example.com/",
			"wss", "example.com:443", "/ws", false, false, false),
		f.ok("explicit ws path", "wss://example.com/ws",
			"wss", "example.com:443", "/ws", false, false, false),
		f.ok("path proxy", "wss://example.com/kamune/ws",
			"wss", "example.com:443", "/kamune/ws", false, false, false),
		f.ok("ws path", "ws://example.com/kamune/ws",
			"ws", "example.com:80", "/kamune/ws", false, false, false),
		f.ok("path ws slash", "wss://example.com/ws/",
			"wss", "example.com:443", "/ws/", false, false, false),
		f.ok("double slash", "wss://example.com//",
			"wss", "example.com:443", "//", false, false, false),
		f.ok("unreserved", "wss://example.com/~._-Az9",
			"wss", "example.com:443", "/~._-Az9", false, false, false),
		f.ok("ipv6 loop", "wss://[::1]",
			"wss", "[::1]:443", "/ws", false, false, false),
		f.ok("ipv6 unspec", "wss://[::]",
			"wss", "[::]:443", "/ws", false, false, false),
		f.ok("ipv6 full loop", "wss://[0:0:0:0:0:0:0:1]",
			"wss", "[::1]:443", "/ws", false, false, false),
		f.ok("ipv6 compress",
			"wss://[2001:0db8:0000:0000:0000:0000:0000:0001]",
			"wss", "[2001:db8::1]:443", "/ws", false, false, false),
		f.ok("ipv6 upper", "wss://[2001:DB8::1]",
			"wss", "[2001:db8::1]:443", "/ws", false, false, false),
		f.ok("ipv6 path", "wss://[::1]/kamune/ws",
			"wss", "[::1]:443", "/kamune/ws", false, false, false),
		f.ok("ipv4 mapped", "wss://[::ffff:192.0.2.1]",
			"wss", "192.0.2.1:443", "/ws", false, false, false),
		f.ok("ipv4 mapped upper", "WSS://[::FFFF:192.0.2.1]/",
			"wss", "192.0.2.1:443", "/ws", false, false, false),
		f.ok("mapped port", "tcp://[::ffff:192.0.2.1]:8890",
			"tcp", "192.0.2.1:8890", "", false, false, false),
		f.ok("ipv4", "192.0.2.1",
			"wss", "192.0.2.1:443", "/ws", false, false, false),
		f.ok("ipv4 dot", "wss://192.0.2.1.",
			"wss", "192.0.2.1:443", "/ws", false, false, false),
		f.ok("ipv4 zero", "tcp://0.0.0.0:9",
			"tcp", "0.0.0.0:9", "", false, false, false),
		f.ok("port min", "tcp://example.com:1",
			"tcp", "example.com:1", "", false, false, false),
		f.ok("port max", "wss://example.com:65535",
			"wss", "example.com:65535", "/ws", false, false, false),
		f.ok("label 63", label63,
			"wss", label63+":443", "/ws", false, false, false),
		f.ok("dns 253", name253,
			"wss", name253+":443", "/ws", false, false, false),
		f.ok("consecutive hyphen", "a--b.example",
			"wss", "a--b.example:443", "/ws", false, false, false),
		f.ok("digit label", "1abc.example",
			"wss", "1abc.example:443", "/ws", false, false, false),
		f.ok("a-label", "XN--BCHER-KVA.Example.",
			"wss", "xn--bcher-kva.example:443", "/ws",
			false, false, false),
		f.ok("rk", "wss://example.com?rk="+f.rk,
			"wss", "example.com:443", "/ws", true, false, false),
		f.ok("rk grouped", "wss://example.com?rk="+f.key.Display(),
			"wss", "example.com:443", "/ws", true, false, false),
		f.ok("rk upper", "wss://example.com?rk="+strings.ToUpper(f.rk),
			"wss", "example.com:443", "/ws", true, false, false),
		f.ok("cert", "wss://example.com?cert="+f.pinHex,
			"wss", "example.com:443", "/ws", false, true, false),
		f.ok("cert upper",
			"wss://example.com?cert="+strings.ToUpper(f.pinHex),
			"wss", "example.com:443", "/ws", false, true, false),
		f.ok("cert colons",
			"wss://example.com?cert="+colonFingerprint(f.pin),
			"wss", "example.com:443", "/ws", false, true, false),
		f.ok("tls skip", "wss://example.com?tls=skip",
			"wss", "example.com:443", "/ws", false, false, true),
		f.ok("reorder",
			"example.com?cert="+f.pinHex+"&rk="+f.rk,
			"wss", "example.com:443", "/ws", true, true, false),
		f.ok("rk and skip",
			"wss://example.com?tls=skip&rk="+f.rk,
			"wss", "example.com:443", "/ws", true, false, true),
		f.ok("tls cert",
			"tls://example.com:8890?cert="+f.pinHex,
			"tls", "example.com:8890", "", false, true, false),
		f.ok("tls scheme skip",
			"tls://example.com:8890?tls=skip",
			"tls", "example.com:8890", "", false, false, true),
		f.ok("tcp rk", "tcp://example.com:9?rk="+f.rk,
			"tcp", "example.com:9", "", true, false, false),
		f.ok("ws rk", "ws://example.com?rk="+f.rk,
			"ws", "example.com:80", "/ws", true, false, false),
		f.ok("path rk",
			"wss://example.com/kamune/ws?rk="+f.rk,
			"wss", "example.com:443", "/kamune/ws", true, false, false),
		f.ok("ipv6 skip", "wss://[::1]?tls=skip",
			"wss", "[::1]:443", "/ws", false, false, true),
		bad("empty", ""),
		bad("http", "http://example.com"),
		bad("https", "https://example.com"),
		bad("ftp", "ftp://example.com"),
		bad("empty scheme", "://example.com"),
		bad("empty host", "wss://"),
		bad("only dot", "wss://."),
		bad("non-ascii", "wss://ex\u00e4mple.com"),
		bad("unicode", "wss://\u65e5\u672c.jp"),
		bad("high byte", "wss://ex\xff.com"),
		bad("user", "wss://user@example.com"),
		bad("user pass", "wss://user:pass@example.com"),
		bad("fragment", "wss://example.com#f"),
		bad("fragment path", "wss://example.com/ws#x"),
		bad("fragment query", "wss://example.com?rk="+f.rk+"#f"),
		bad("at path", "wss://example.com/a@b"),
		bad("semicolon", "wss://example.com;x=1"),
		bad("semi path", "wss://example.com/a;b"),
		bad("backslash", "wss://example.com\\x"),
		bad("space", "wss://example .com"),
		bad("space key", "wss://example.com?rk= "+f.rk),
		bad("percent path", "wss://example.com/%2f"),
		bad("percent host", "wss://ex%61mple.com"),
		bad("star path", "wss://example.com/*"),
		bad("zone", "wss://[fe80::1%eth0]"),
		bad("zone encoded", "wss://[fe80::1%25eth0]"),
		bad("unbracketed", "wss://::1"),
		bad("bracket ipv4", "wss://[192.0.2.1]"),
		bad("unclosed", "wss://[::1"),
		bad("not ip", "192.168.1.300"),
		bad("numeric last", "example.123"),
		bad("short ip", "1.2.3"),
		bad("ipv4 zero pad", "192.168.001.1"),
		bad("port 0", "wss://example.com:0"),
		bad("port big", "wss://example.com:65536"),
		bad("port pad", "wss://example.com:0443"),
		bad("port plus", "wss://example.com:+443"),
		bad("port minus", "wss://example.com:-1"),
		bad("port junk", "wss://example.com:443a"),
		bad("tls no port", "tls://example.com"),
		bad("tcp no port", "tcp://example.com"),
		bad("empty port", "wss://example.com:"),
		bad("ipv6 empty port", "wss://[::1]:/ws"),
		bad("tcp path", "tcp://example.com:1/ws"),
		bad("tls path", "tls://example.com:1/kamune/ws"),
		bad("tcp slash", "tcp://example.com:1/"),
		bad("double dot", "wss://example..com"),
		bad("leading dot", "wss://.example.com"),
		bad("hyphen start", "wss://-ab.com"),
		bad("hyphen end", "wss://ab-.com"),
		bad("underscore", "wss://a_b.com"),
		bad("label 64", label64),
		bad("dns 254", name254),
		bad("long label", "wss://"+strings.Repeat("a", 300)+".com"),
		bad("insecure", "wss://example.com?insecure=true"),
		bad("unknown", "wss://example.com?foo=bar"),
		bad("dup rk", "wss://example.com?rk="+f.rk+"&rk="+f.rk),
		bad("dup cert", "wss://example.com?cert="+f.pinHex+"&cert=ab"),
		bad("dup tls", "wss://example.com?tls=skip&tls=skip"),
		bad("empty rk", "wss://example.com?rk="),
		bad("empty cert", "wss://example.com?cert="),
		bad("empty tls", "wss://example.com?tls="),
		bad("empty key", "wss://example.com?=x"),
		bad("rk bare", "wss://example.com?rk"),
		bad("tls upper", "wss://example.com?tls=SKIP"),
		bad("tls value", "wss://example.com?tls=yes"),
		bad("tls name", "wss://example.com?TLS=skip"),
		bad("rk name", "wss://example.com?RK="+f.rk),
		bad("cert ws", "ws://example.com?cert="+f.pinHex),
		bad("tls ws", "ws://example.com?tls=skip"),
		bad("cert tcp", "tcp://example.com:1?cert="+f.pinHex),
		bad("tls tcp", "tcp://example.com:1?tls=skip"),
		bad("cert and skip",
			"wss://example.com?cert="+f.pinHex+"&tls=skip"),
		bad("cert and skip tls",
			"tls://example.com:1?tls=skip&cert="+f.pinHex),
		bad("bare query", "wss://example.com?"),
		bad("trail amp", "wss://example.com?rk="+f.rk+"&"),
		bad("double amp",
			"wss://example.com?rk="+f.rk+"&&cert="+f.pinHex),
		bad("double quest", "wss://example.com??rk="+f.rk),
		bad("zero key", "wss://example.com?rk="+zero.String()),
		bad("bad rk", "wss://example.com?rk=rk1-!!!!"),
		bad("short cert", "wss://example.com?cert=abcd"),
		bad("long cert", "wss://example.com?cert="+f.pinHex+"aa"),
		bad("odd cert", "wss://example.com?cert=abc"),
	}
}

func TestParseAddress(t *testing.T) {
	a := require.New(t)
	a.Len(dnsOfLen(253), 253)
	a.Len(dnsOfLen(254), 254)
	a.False(strings.HasSuffix(dnsOfLen(253), "."))
	for _, c := range addressCases() {
		t.Run(c.name, func(t *testing.T) {
			a := require.New(t)
			got, err := ParseAddress(c.in)
			if c.bad {
				a.ErrorIs(err, ErrInvalidAddress)
				a.Less(len(err.Error()), 160)
				if len(c.in) >= 48 {
					a.NotContains(err.Error(), c.in)
				}
				return
			}
			a.NoError(err)
			a.Equal(c.want, got)
			a.Equal(c.str, got.String())
			a.Equal(c.store, got.StoreName())
			a.Equal(c.display, got.Display())
		})
	}
}

func TestAddressRoundTrip(t *testing.T) {
	for _, c := range addressCases() {
		if c.bad {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			a := require.New(t)
			got, err := ParseAddress(c.in)
			a.NoError(err)
			text := got.String()
			a.Equal(c.str, text)
			again, err := ParseAddress(text)
			a.NoError(err)
			a.Equal(got, again)
			a.Equal(text, again.String())
		})
	}
}

func TestAddressStoreName(t *testing.T) {
	key := fixedRelayKey()
	pin := hex.EncodeToString(fixedCertPin())
	same := []struct{ name, in string }{
		{"bare", "example.com"},
		{"case", "Example.COM"},
		{"dot", "example.com."},
		{"case dot", "WSS://Example.COM."},
		{"explicit port", "wss://example.com:443"},
		{"slash", "wss://example.com/"},
		{"ws path", "wss://example.com/ws"},
		{"ws same port", "ws://example.com:443"},
		{
			"with key and pin",
			"WSS://Example.COM./ws?rk=" + key.String() +
				"&cert=" + pin,
		},
		{"skip", "wss://example.com?tls=skip"},
	}
	for _, c := range same {
		t.Run("same/"+c.name, func(t *testing.T) {
			a := require.New(t)
			got, err := ParseAddress(c.in)
			a.NoError(err)
			a.Equal("example.com:443", got.StoreName())
		})
	}

	ipv6 := []string{
		"wss://[2001:db8::1]",
		"wss://[2001:0db8:0000:0000:0000:0000:0000:0001]",
		"WSS://[2001:DB8::1]:443/",
		"wss://[2001:db8::1]/ws?rk=" + key.String(),
	}
	for i, in := range ipv6 {
		t.Run("ipv6/"+string(rune('a'+i)), func(t *testing.T) {
			a := require.New(t)
			got, err := ParseAddress(in)
			a.NoError(err)
			a.Equal("[2001:db8::1]:443", got.StoreName())
		})
	}

	mapped := []string{
		"wss://192.0.2.1",
		"wss://192.0.2.1.",
		"wss://192.0.2.1:443",
		"wss://[::ffff:192.0.2.1]",
		"wss://[::FFFF:192.0.2.1]/",
	}
	for i, in := range mapped {
		t.Run("mapped/"+string(rune('a'+i)), func(t *testing.T) {
			a := require.New(t)
			got, err := ParseAddress(in)
			a.NoError(err)
			a.Equal("192.0.2.1:443", got.StoreName())
		})
	}

	diff := []struct{ name, in, store string }{
		{"path", "wss://example.com/kamune/ws",
			"example.com:443/kamune/ws"},
		{"path slash", "wss://example.com/kamune/ws/",
			"example.com:443/kamune/ws/"},
		{"path case", "wss://example.com/WS", "example.com:443/WS"},
		{"ws port", "ws://example.com", "example.com:80"},
		{"tls port", "tls://example.com:8890", "example.com:8890"},
		{"tcp port", "tcp://example.com:8891", "example.com:8891"},
		{"other host", "wss://relay.example", "relay.example:443"},
	}
	seen := map[string]string{"example.com:443": "same"}
	for _, c := range diff {
		t.Run("diff/"+c.name, func(t *testing.T) {
			a := require.New(t)
			got, err := ParseAddress(c.in)
			a.NoError(err)
			a.Equal(c.store, got.StoreName())
			a.NotEqual("example.com:443", got.StoreName())
			if prev, ok := seen[got.StoreName()]; ok {
				a.Failf("store name collision",
					"%s and %s", prev, c.name)
			}
			seen[got.StoreName()] = c.name
		})
	}
}

func TestAddressWithRelayKey(t *testing.T) {
	a := require.New(t)
	pin := bytes.Repeat([]byte{0x42}, sha256.Size)
	base := Address{
		Scheme:        "wss",
		Host:          "example.com:443",
		Path:          "/kamune/ws",
		CertPin:       pin,
		SkipTLSVerify: false,
	}
	k := fixedRelayKey()
	got := base.WithRelayKey(k)
	k[0] ^= 0x01
	a.NotEqual(k[0], got.RelayKey[0])
	a.NotSame(got.RelayKey, &k)
	pin[0] = 0x99
	a.Equal(byte(0x42), got.CertPin[0])
	got.CertPin[0] = 0x11
	a.Equal(byte(0x99), pin[0])
	a.Equal(byte(0x99), base.CertPin[0])
	a.Equal("/kamune/ws", got.Path)
	a.Nil(base.RelayKey)

	k = fixedRelayKey()
	base.RelayKey = &k
	base.CertPin = bytes.Repeat([]byte{0x42}, sha256.Size)
	stripped := base.WithoutRelayKey()
	a.Nil(stripped.RelayKey)
	a.NotNil(base.RelayKey)
	a.Equal(k, *base.RelayKey)
	stripped.CertPin[0] = 0x01
	a.Equal(byte(0x42), base.CertPin[0])
	a.Equal(base.Host, stripped.Host)
	a.Equal(base.Path, stripped.Path)

	other := fixedRelayKey()
	other[0] ^= 0xff
	replaced := got.WithRelayKey(other)
	a.NotSame(replaced.RelayKey, got.RelayKey)
	a.NotSame(replaced.RelayKey, &other)
	a.Equal(other, *replaced.RelayKey)
	other[1] ^= 0xff
	a.NotEqual(other, *replaced.RelayKey)

	text := replaced.String()
	again, err := ParseAddress(text)
	a.NoError(err)
	a.Equal(replaced, again)
	cleared := replaced.WithoutRelayKey()
	again, err = ParseAddress(cleared.String())
	a.NoError(err)
	a.Equal(cleared, again)
	a.Nil(cleared.RelayKey)
}

func FuzzParseAddress(f *testing.F) {
	seen := map[string]struct{}{}
	for _, c := range addressCases() {
		if _, ok := seen[c.in]; ok {
			continue
		}
		seen[c.in] = struct{}{}
		f.Add(c.in)
		if c.str != "" {
			if _, ok := seen[c.str]; !ok {
				seen[c.str] = struct{}{}
				f.Add(c.str)
			}
		}
	}
	f.Fuzz(func(t *testing.T, in string) {
		a := require.New(t)
		got, err := ParseAddress(in)
		if err != nil {
			a.ErrorIs(err, ErrInvalidAddress)
			return
		}
		text := got.String()
		again, err := ParseAddress(text)
		a.NoError(err)
		a.Equal(got, again)
		a.Equal(text, again.String())
	})
}
