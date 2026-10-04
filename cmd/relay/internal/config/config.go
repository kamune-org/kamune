package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server    Server    `toml:"server"`
	Diagnose  Diagnose  `toml:"diagnose"`
	Session   Session   `toml:"session"`
	RateLimit RateLimit `toml:"rate_limit"`
	WS        WS        `toml:"ws"`
	TCP       TCP       `toml:"tcp"`
	TLS       TLS       `toml:"tls"`
	WSS       WSS       `toml:"wss"`
	Broker    Broker    `toml:"broker"`
}

type Server struct {
	Password string `toml:"password"`
	// ClientIPHeader is the one request header read for the client address
	// when the TCP peer is in TrustedProxies. X-Forwarded-For is read from
	// the right, skipping trusted hops. Any other header must hold a single
	// address that the proxy sets itself. Empty means
	// DefaultClientIPHeader.
	ClientIPHeader string `toml:"client_ip_header"`
	// DataDir is where the relay keeps state across restarts: the
	// self-signed certificate it creates for a [tls] or [wss] listener
	// with no cert_file and key_file. Keeping it lets clients pin the
	// certificate. Empty means DefaultDataDir.
	DataDir        string   `toml:"data_dir"`
	TrustedProxies []string `toml:"trusted_proxies"`
}

// DefaultDataDir returns the directory used when server.data_dir is
// empty: kamune-relay in the user's configuration directory, such as
// ~/.config/kamune-relay on Linux (see os.UserConfigDir).
func DefaultDataDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf(
			"no default data dir, set server.data_dir: %w", err,
		)
	}
	return filepath.Join(dir, "kamune-relay"), nil
}

// DefaultClientIPHeader is the client address header read from a trusted
// proxy when server.client_ip_header is not set.
const DefaultClientIPHeader = "X-Forwarded-For"

type Diagnose struct {
	Enabled bool   `toml:"enabled"`
	Address string `toml:"address"`
}

type WS struct {
	Enabled bool   `toml:"enabled"`
	Address string `toml:"address"`
}

type TCP struct {
	Enabled bool   `toml:"enabled"`
	Address string `toml:"address"`
}

type TLS struct {
	Enabled  bool   `toml:"enabled"`
	Address  string `toml:"address"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

type WSS struct {
	Enabled  bool   `toml:"enabled"`
	Address  string `toml:"address"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

type Session struct {
	TokenTTL              time.Duration `toml:"token_ttl"`
	SessionTTL            time.Duration `toml:"session_ttl"`
	HandshakeTimeout      time.Duration `toml:"handshake_timeout"`
	MaxConcurrentSessions int           `toml:"max_concurrent_sessions"`
	MaxMessageSize        int           `toml:"max_message_size"`
}

// Broker configures the UDP signaling broker (STUN-like IP echo + signal
// introduction for P2P hole-punching).
type Broker struct {
	Enabled         bool          `toml:"enabled"`
	Address         string        `toml:"address"`
	RegistrationTTL time.Duration `toml:"registration_ttl"`
}

type RateLimit struct {
	Disabled   bool          `toml:"disabled"`
	TimeWindow time.Duration `toml:"time_window"`
	Quota      uint64        `toml:"quota"`
	MaxEntries int           `toml:"max_entries"`
}

const (
	defaultRateLimitWindow     = time.Minute
	defaultRateLimitQuota      = uint64(20)
	defaultRateLimitMaxEntries = 100_000
)

func (rl RateLimit) IsEnabled() bool {
	return !rl.Disabled
}

// Validate returns an error if any field of c has a value that would put
// the relay into a degraded state. It is deliberately permissive about
// zero values that have an established "no limit" meaning (session_ttl,
// max_message_size) and restrictive about values that would silently
// degrade behavior (token_ttl, max_concurrent_sessions).
func (c Config) Validate() error {
	for _, cidr := range c.Server.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("server.trusted_proxies contains invalid CIDR %q", cidr)
		}
	}
	if h := c.Server.ClientIPHeader; h != "" && !validHeaderName(h) {
		return fmt.Errorf(
			"server.client_ip_header is not a valid header name: %q", h,
		)
	}
	if c.Session.MaxConcurrentSessions <= 0 {
		return fmt.Errorf(
			"session.max_concurrent_sessions must be > 0, got %d",
			c.Session.MaxConcurrentSessions,
		)
	}
	if c.Session.TokenTTL <= 0 {
		return fmt.Errorf(
			"session.token_ttl must be > 0, got %s",
			c.Session.TokenTTL,
		)
	}
	if c.Session.SessionTTL < 0 {
		return fmt.Errorf(
			"session.session_ttl must be >= 0 (0 = no limit), got %s",
			c.Session.SessionTTL,
		)
	}
	if c.Session.MaxMessageSize < 0 {
		return fmt.Errorf(
			"session.max_message_size must be >= 0 (0 = no limit), got %d",
			c.Session.MaxMessageSize,
		)
	}
	if c.RateLimit.IsEnabled() {
		if c.RateLimit.TimeWindow <= 0 {
			return fmt.Errorf(
				"rate_limit.time_window must be > 0, got %s",
				c.RateLimit.TimeWindow,
			)
		}
		if c.RateLimit.Quota == 0 {
			return fmt.Errorf("rate_limit.quota must be > 0")
		}
		maxInt := uint64(^uint(0) >> 1)
		if c.RateLimit.Quota > maxInt {
			return fmt.Errorf(
				"rate_limit.quota exceeds platform int maximum: %d",
				c.RateLimit.Quota,
			)
		}
		if c.RateLimit.MaxEntries < 0 {
			return fmt.Errorf(
				"rate_limit.max_entries must be >= 0, got %d",
				c.RateLimit.MaxEntries,
			)
		}
	}
	// Cert file paths must both be set or both be empty. Both-empty with
	// tls.enabled = true uses the self-signed cert kept in server.data_dir.
	if c.TLS.Enabled && (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return fmt.Errorf(
			"tls.cert_file and tls.key_file must both be set or "+
				"both be empty, got cert_file=%q key_file=%q",
			c.TLS.CertFile, c.TLS.KeyFile,
		)
	}
	if c.WSS.Enabled && (c.WSS.CertFile == "") != (c.WSS.KeyFile == "") {
		return fmt.Errorf(
			"wss.cert_file and wss.key_file must both be set or "+
				"both be empty, got cert_file=%q key_file=%q",
			c.WSS.CertFile, c.WSS.KeyFile,
		)
	}
	if c.Session.HandshakeTimeout < 0 {
		return fmt.Errorf(
			"session.handshake_timeout must be >= 0 (0 = no limit), got %s",
			c.Session.HandshakeTimeout,
		)
	}
	if c.Diagnose.Enabled && c.Diagnose.Address == "" {
		return fmt.Errorf("diagnose.address must not be empty when enabled")
	}
	if c.WS.Enabled && c.WS.Address == "" {
		return fmt.Errorf("ws.address must not be empty when enabled")
	}
	if c.TCP.Enabled && c.TCP.Address == "" {
		return fmt.Errorf("tcp.address must not be empty when enabled")
	}
	if c.TLS.Enabled && c.TLS.Address == "" {
		return fmt.Errorf("tls.address must not be empty when enabled")
	}
	if c.WSS.Enabled && c.WSS.Address == "" {
		return fmt.Errorf("wss.address must not be empty when enabled")
	}
	if c.Broker.Enabled && c.Broker.Address == "" {
		return fmt.Errorf("broker.address must not be empty when enabled")
	}
	if !c.Diagnose.Enabled && !c.WS.Enabled && !c.TCP.Enabled &&
		!c.TLS.Enabled && !c.WSS.Enabled && !c.Broker.Enabled {
		return fmt.Errorf(
			"at least one server must be enabled " +
				"(diagnose, ws, tcp, tls, wss, or broker)",
		)
	}
	return nil
}

// validHeaderName reports whether s is an HTTP field name (RFC 9110 token).
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

const EnvKey = "KAMUNE_RELAY_CONFIG"

// New loads config from the given file path. If path is empty, it falls back to
// the KAMUNE_RELAY_CONFIG environment variable. Returns an error if neither
// source is available or parsing fails.
func New(path string) (Config, error) {
	var data []byte
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("reading config %q: %w", path, err)
		}
		data = raw
	} else {
		raw, ok := os.LookupEnv(EnvKey)
		if !ok || raw == "" {
			return Config{}, fmt.Errorf(
				"no config file (-c) and %s env var not set", EnvKey,
			)
		}
		data = []byte(raw)
	}

	cfg := Config{
		Server: Server{
			ClientIPHeader: DefaultClientIPHeader,
		},
		Session: Session{
			HandshakeTimeout: 30 * time.Second,
		},
		RateLimit: RateLimit{
			TimeWindow: defaultRateLimitWindow,
			Quota:      defaultRateLimitQuota,
			MaxEntries: defaultRateLimitMaxEntries,
		},
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshal: %w", err)
	}
	return cfg, nil
}
