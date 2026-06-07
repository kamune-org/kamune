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
	MaxConcurrentSessions int           `toml:"max_concurrent_sessions"`
	MaxMessageSize        int           `toml:"max_message_size"`
}

type RateLimit struct {
	Enabled    bool          `toml:"enabled"`
	TimeWindow time.Duration `toml:"time_window"`
	Quota      uint64        `toml:"quota"`
	MaxEntries int           `toml:"max_entries"`
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
