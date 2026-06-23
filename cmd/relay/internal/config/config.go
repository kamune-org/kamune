package config

import (
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server    Server    `toml:"server"`
	WS        WS        `toml:"ws"`
	Session   Session   `toml:"session"`
	RateLimit RateLimit `toml:"rate_limit"`
	TCP       TCP       `toml:"tcp"`
	TLS       TLS       `toml:"tls"`
}

type Server struct {
	Address      string `toml:"address"`
	Password     string `toml:"password"`
	ExposeHealth bool   `toml:"expose_health"`
	ExposeIP     bool   `toml:"expose_ip"`
}

type WS struct {
	Enabled bool `toml:"enabled"`
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

type Session struct {
	TokenTTL              time.Duration `toml:"token_ttl"`
	SessionTTL            time.Duration `toml:"session_ttl"`
	HandshakeTimeout      time.Duration `toml:"handshake_timeout"`
	MaxConcurrentSessions int           `toml:"max_concurrent_sessions"`
	MaxMessageSize        int           `toml:"max_message_size"`
}

type RateLimit struct {
	Enabled    bool          `toml:"enabled"`
	TimeWindow time.Duration `toml:"time_window"`
	Quota      uint64        `toml:"quota"`
	MaxEntries int           `toml:"max_entries"`
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
