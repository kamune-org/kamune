package config

import (
	"fmt"
	"os"
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
}

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

func (rl RateLimit) IsEnabled() bool {
	return !rl.Disabled
}

// Validate returns an error if any field of c has a value that would put
// the relay into a degraded state. It is deliberately permissive about
// zero values that have an established "no limit" meaning (session_ttl,
// max_message_size) and restrictive about values that would silently
// degrade behavior (token_ttl, max_concurrent_sessions).
func (c Config) Validate() error {
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
	// Cert file paths must both be set or both be empty. Both-empty with
	// tls.enabled = true triggers an in-memory self-signed cert at runtime.
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
	if !c.Diagnose.Enabled && !c.WS.Enabled && !c.TCP.Enabled &&
		!c.TLS.Enabled && !c.WSS.Enabled && !c.Broker.Enabled {
		return fmt.Errorf(
			"at least one server must be enabled " +
				"(diagnose, ws, tcp, tls, wss, or broker)",
		)
	}
	return nil
}

func New(path string) (Config, error) {
	cfg := Config{}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading file: %w", err)
	}
	if err = toml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("unmarshal: %w", err)
	}
	return cfg, nil
}
