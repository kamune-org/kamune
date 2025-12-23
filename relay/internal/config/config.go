package config

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/kamune-org/kamune/pkg/attest"
)

type Config struct {
	Server    Server    `toml:"server"`
	Storage   Storage   `toml:"storage"`
	RateLimit RateLimit `toml:"rate_limit"`
}

type Server struct {
	Address  string           `toml:"address"`
	Identity attest.Algorithm `toml:"identity"`
}

type Storage struct {
	Path           string        `toml:"path"`
	LogLevel       slog.Level    `toml:"log_level"`
	InMemory       bool          `toml:"in_memory"`
	RegisterTTL    time.Duration `toml:"register_ttl"`
	MaxMessageSize int           `toml:"max_message_size"`
	MaxQueueSize   uint64        `toml:"max_queue_size"`
}

type RateLimit struct {
	Enabled    bool          `toml:"enabled"`
	TimeWindow time.Duration `toml:"time_window"`
	Quota      uint64        `toml:"quota"`
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
