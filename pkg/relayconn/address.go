package relayconn

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/kamune-org/kamune/pkg/relayconn/relayleg"
)

// ErrInvalidAddress means the text is not a relay address.
var ErrInvalidAddress = errors.New("invalid address")

// Address is one relay endpoint in canonical form.
type Address struct {
	// Scheme is "wss", "tls", "ws", or "tcp".
	Scheme string
	// Host is the canonical host:port.
	Host string
	// Path is the WebSocket request path for ws and wss.
	// An empty path and "/" are stored as "/ws".
	// tcp and tls leave Path empty.
	Path string
	// RelayKey is the rk parameter, or nil when it was absent.
	RelayKey *relayleg.PublicKey
	// CertPin is the SHA-256 certificate pin, or nil when cert
	// was absent.
	CertPin []byte
	// SkipTLSVerify is true when the address carried tls=skip.
	SkipTLSVerify bool
}

// String returns the canonical address. The path is omitted when it
// is /ws. Parameters that are present are written in the order rk,
// cert, tls.
func (a Address) String() string {
	var b strings.Builder
	b.WriteString(strings.ToLower(a.Scheme))
	b.WriteString("://")
	b.WriteString(a.Host)
	if a.Path != "" && a.Path != "/ws" {
		b.WriteString(a.Path)
	}
	var params []string
	if a.RelayKey != nil {
		params = append(params, "rk="+a.RelayKey.String())
	}
	if len(a.CertPin) > 0 {
		params = append(params, "cert="+hex.EncodeToString(a.CertPin))
	}
	if a.SkipTLSVerify {
		params = append(params, "tls=skip")
	}
	if len(params) > 0 {
		b.WriteByte('?')
		b.WriteString(strings.Join(params, "&"))
	}
	return b.String()
}

// Display returns String without the rk and cert parameters.
func (a Address) Display() string {
	a.RelayKey = nil
	a.CertPin = nil
	return a.String()
}

// StoreName returns the key-store name for this relay. It is
// host:port, plus the path when the path is not /ws.
func (a Address) StoreName() string {
	if a.Path != "" && a.Path != "/ws" {
		return a.Host + a.Path
	}
	return a.Host
}

// WithRelayKey returns a copy of a that uses k. The copy does not
// alias k or a.CertPin.
func (a Address) WithRelayKey(k relayleg.PublicKey) Address {
	out := a
	out.RelayKey = &k
	out.CertPin = bytes.Clone(a.CertPin)
	return out
}

// WithoutRelayKey returns a copy of a with no relay key. The copy
// does not alias a.CertPin.
func (a Address) WithoutRelayKey() Address {
	out := a
	out.RelayKey = nil
	out.CertPin = bytes.Clone(a.CertPin)
	return out
}

// ParseAddress parses a relay address into canonical form.
//
// The grammar is parsed by hand. net/url accepts percent-encoding,
// user info, and semicolons, which this grammar rejects. A missing
// scheme means wss. Every error wraps ErrInvalidAddress and the
// text does not echo the input.
func ParseAddress(s string) (Address, error) {
	if s == "" {
		return Address{}, invalidAddress("empty address")
	}
	if err := rejectForbidden(s); err != nil {
		return Address{}, err
	}
	scheme, rest, err := splitScheme(s)
	if err != nil {
		return Address{}, err
	}
	hostport, path, query, err := splitRest(rest)
	if err != nil {
		return Address{}, err
	}
	rawHost, rawPort, bracketed, err := splitHostPort(hostport)
	if err != nil {
		return Address{}, err
	}
	host, err := canonicalHost(rawHost, bracketed)
	if err != nil {
		return Address{}, err
	}
	port, err := parsePort(rawPort, scheme)
	if err != nil {
		return Address{}, err
	}
	path, err = canonicalPath(scheme, path)
	if err != nil {
		return Address{}, err
	}
	key, pin, skip, err := parseParams(scheme, query)
	if err != nil {
		return Address{}, err
	}
	return Address{
		Scheme:        scheme,
		Host:          net.JoinHostPort(host, strconv.Itoa(port)),
		Path:          path,
		RelayKey:      key,
		CertPin:       pin,
		SkipTLSVerify: skip,
	}, nil
}

func invalidAddress(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidAddress, reason)
}

func rejectForbidden(s string) error {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c > 127:
			return invalidAddress("non-ASCII address")
		case c <= ' ' || c == 0x7f:
			return invalidAddress("invalid character")
		case c == '@':
			return invalidAddress("user info")
		case c == '#':
			return invalidAddress("fragment")
		case c == '\\' || c == ';':
			return invalidAddress("invalid character")
		}
	}
	return nil
}

func splitScheme(s string) (string, string, error) {
	i := strings.Index(s, "://")
	if i < 0 {
		return "wss", s, nil
	}
	scheme := strings.ToLower(s[:i])
	if strings.Contains(scheme, "%") {
		return "", "", invalidAddress("percent-encoding")
	}
	switch scheme {
	case "wss", "ws", "tls", "tcp":
		return scheme, s[i+3:], nil
	default:
		return "", "", invalidAddress("unsupported scheme")
	}
}

func splitRest(rest string) (string, string, string, error) {
	query := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
		if query == "" {
			return "", "", "", invalidAddress("empty parameter")
		}
		if strings.Contains(query, "?") {
			return "", "", "", invalidAddress("invalid query")
		}
	}
	if rest == "" {
		return "", "", "", invalidAddress("empty host")
	}
	if rest[0] != '[' {
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			return rest, "", query, nil
		}
		if slash == 0 {
			return "", "", "", invalidAddress("empty host")
		}
		return rest[:slash], rest[slash:], query, nil
	}
	end := strings.IndexByte(rest, ']')
	if end < 0 {
		return "", "", "", invalidAddress("invalid host")
	}
	after := rest[end+1:]
	switch {
	case after == "":
		return rest, "", query, nil
	case after[0] == '/':
		return rest[:end+1], after, query, nil
	case after[0] == ':':
		slash := strings.IndexByte(after, '/')
		if slash < 0 {
			return rest, "", query, nil
		}
		return rest[:end+1+slash], after[slash:], query, nil
	default:
		return "", "", "", invalidAddress("invalid host")
	}
}

func splitHostPort(hostport string) (string, string, bool, error) {
	if strings.HasPrefix(hostport, "[") {
		end := strings.IndexByte(hostport, ']')
		if end < 0 {
			return "", "", false, invalidAddress("invalid host")
		}
		host := hostport[1:end]
		if end+1 == len(hostport) {
			return host, "", true, nil
		}
		if hostport[end+1] != ':' || end+2 >= len(hostport) {
			return "", "", false, invalidAddress("invalid port")
		}
		return host, hostport[end+2:], true, nil
	}
	if strings.Count(hostport, ":") > 1 {
		if strings.Contains(hostport, "%") {
			return "", "", false, invalidAddress("IPv6 zone")
		}
		return "", "", false, invalidAddress(
			"IPv6 must be bracketed",
		)
	}
	host, port, ok := strings.Cut(hostport, ":")
	if !ok {
		return host, "", false, nil
	}
	if port == "" {
		return "", "", false, invalidAddress("invalid port")
	}
	return host, port, false, nil
}

// canonicalHost returns the host with no port. One trailing dot is
// stripped before a name is classified. DNS names are lowercased
// LDH. An IP literal is parsed with netip, unmapped, and printed
// with Addr.String, so IPv4-mapped text becomes IPv4 and IPv6 is
// compressed.
func canonicalHost(literal string, bracketed bool) (string, error) {
	if bracketed {
		if strings.Contains(literal, "%") {
			return "", invalidAddress("IPv6 zone")
		}
		return canonicalIP(literal)
	}
	literal = strings.TrimSuffix(literal, ".")
	if literal == "" {
		return "", invalidAddress("empty host")
	}
	if strings.Contains(literal, "%") {
		return "", invalidAddress("percent-encoding")
	}
	if strings.Contains(literal, ":") {
		return "", invalidAddress("IPv6 must be bracketed")
	}
	if addr, err := netip.ParseAddr(literal); err == nil {
		if addr.Zone() != "" || addr.Is6() {
			return "", invalidAddress("invalid host")
		}
		return addr.Unmap().String(), nil
	}
	return canonicalDNS(literal)
}

func canonicalIP(literal string) (string, error) {
	if literal == "" {
		return "", invalidAddress("empty host")
	}
	addr, err := netip.ParseAddr(literal)
	if err != nil || addr.Zone() != "" {
		return "", invalidAddress("invalid host")
	}
	// Brackets are for IPv6 text. An IPv4-mapped address is IPv6
	// text and unmaps to IPv4. An IPv4 literal has no colon.
	if !strings.Contains(literal, ":") {
		return "", invalidAddress("invalid host")
	}
	return addr.Unmap().String(), nil
}

func canonicalDNS(name string) (string, error) {
	name = strings.ToLower(name)
	if name == "" || len(name) > 253 {
		return "", invalidAddress("invalid host")
	}
	labels := strings.Split(name, ".")
	last := len(labels) - 1
	for i, lab := range labels {
		if err := checkLabel(lab, i == last); err != nil {
			return "", err
		}
	}
	return name, nil
}

// checkLabel reports whether lab is an LDH label. A label is one to
// 63 letters, digits, or hyphens, and it must not start or end with
// a hyphen. A digit may start a label. Consecutive hyphens are
// allowed. The last label must not be all digits, because that text
// is not a canonical host.
func checkLabel(lab string, last bool) error {
	if len(lab) < 1 || len(lab) > 63 {
		return invalidAddress("invalid host")
	}
	if lab[0] == '-' || lab[len(lab)-1] == '-' {
		return invalidAddress("invalid host")
	}
	digits := true
	for i := 0; i < len(lab); i++ {
		c := lab[i]
		if c < '0' || c > '9' {
			digits = false
		}
		ok := (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-'
		if !ok {
			return invalidAddress("invalid host")
		}
	}
	if last && digits {
		return invalidAddress("invalid host")
	}
	return nil
}

// parsePort accepts a decimal port from 1 to 65535 with no sign and
// no leading zero. An empty port means 443 for wss and 80 for ws.
// tls and tcp require a port. The canonical spelling is the same
// decimal, so a leading zero is rejected rather than stripped.
func parsePort(port, scheme string) (int, error) {
	if port == "" {
		switch scheme {
		case "wss":
			return 443, nil
		case "ws":
			return 80, nil
		default:
			return 0, invalidAddress("port required")
		}
	}
	if strings.Contains(port, "%") {
		return 0, invalidAddress("percent-encoding")
	}
	if len(port) > 5 || (len(port) > 1 && port[0] == '0') {
		return 0, invalidAddress("invalid port")
	}
	n := 0
	for i := 0; i < len(port); i++ {
		d := port[i]
		if d < '0' || d > '9' {
			return 0, invalidAddress("invalid port")
		}
		n = n*10 + int(d-'0')
	}
	if n < 1 || n > 65535 {
		return 0, invalidAddress("invalid port")
	}
	return n, nil
}

func canonicalPath(scheme, path string) (string, error) {
	if scheme == "tcp" || scheme == "tls" {
		if path != "" {
			return "", invalidAddress("path not allowed")
		}
		return "", nil
	}
	if path == "" || path == "/" {
		return "/ws", nil
	}
	if path[0] != '/' {
		return "", invalidAddress("invalid path")
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c == '%' {
			// Percent-encoding is not in the grammar.
			return "", invalidAddress("percent-encoding")
		}
		if c != '/' && !isUnreserved(c) {
			return "", invalidAddress("invalid path")
		}
	}
	return path, nil
}

func isUnreserved(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func parseParams(
	scheme, query string,
) (*relayleg.PublicKey, []byte, bool, error) {
	if query == "" {
		return nil, nil, false, nil
	}
	if strings.Contains(query, "%") {
		return nil, nil, false, invalidAddress("percent-encoding")
	}
	var (
		rk, cert, tls          string
		hasRK, hasCert, hasTLS bool
	)
	for _, part := range strings.Split(query, "&") {
		if part == "" {
			return nil, nil, false, invalidAddress(
				"empty parameter",
			)
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok || k == "" || v == "" {
			return nil, nil, false, invalidAddress(
				"empty parameter",
			)
		}
		switch k {
		case "rk":
			if hasRK {
				return nil, nil, false, invalidAddress(
					"duplicate parameter",
				)
			}
			hasRK, rk = true, v
		case "cert":
			if hasCert {
				return nil, nil, false, invalidAddress(
					"duplicate parameter",
				)
			}
			hasCert, cert = true, v
		case "tls":
			if hasTLS {
				return nil, nil, false, invalidAddress(
					"duplicate parameter",
				)
			}
			hasTLS, tls = true, v
		default:
			return nil, nil, false, invalidAddress(
				"unknown parameter",
			)
		}
	}
	if scheme == "ws" || scheme == "tcp" {
		if hasCert {
			return nil, nil, false, invalidAddress(
				"cert not allowed",
			)
		}
		if hasTLS {
			return nil, nil, false, invalidAddress(
				"tls not allowed",
			)
		}
	}
	if hasTLS && tls != "skip" {
		return nil, nil, false, invalidAddress(
			"invalid tls parameter",
		)
	}
	if hasCert && hasTLS {
		return nil, nil, false, invalidAddress("cert and tls=skip")
	}
	var key *relayleg.PublicKey
	if hasRK {
		parsed, err := relayleg.ParsePublicKey(rk)
		if err != nil {
			return nil, nil, false, fmt.Errorf(
				"%w: invalid rk: %w",
				ErrInvalidAddress, err,
			)
		}
		key = new(relayleg.PublicKey)
		*key = parsed
	}
	var pin []byte
	if hasCert {
		fp, err := ParseCertFingerprint(cert)
		if err != nil {
			return nil, nil, false, fmt.Errorf(
				"%w: invalid cert: %w",
				ErrInvalidAddress, err,
			)
		}
		pin = fp
	}
	return key, pin, hasTLS, nil
}
