package config

import (
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/kamune-org/kamune/pkg/attest"
)

type Config struct {
	Storage     string          `toml:"storage"`
	Identity    attest.Identity `toml:"identity"`
	Address     string          `toml:"address"`
	RegisterTTL time.Duration   `toml:"register_ttl"`
	RateLimit   RateLimit       `toml:"rate_limit"`
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
