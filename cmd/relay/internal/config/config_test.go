package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validConfig returns a config that passes Validate. Tests mutate
// individual fields to exercise specific failure modes.
func validConfig() Config {
	return Config{
		Server: Server{
			Address:      "127.0.0.1:0",
			Password:     "",
			ExposeHealth: true,
			ExposeIP:     true,
		},
		Session: Session{
			TokenTTL:              5 * time.Minute,
			SessionTTL:            30 * time.Minute,
			HandshakeTimeout:      30 * time.Second,
			MaxConcurrentSessions: 100,
			MaxMessageSize:        65536,
		},
		RateLimit: RateLimit{
			Enabled: false,
		},
	}
}

func TestConfig_Validate_OK(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Errorf("validConfig().Validate() = %v, want nil", err)
	}
}

func TestConfig_Validate_RejectsZeroMaxConns(t *testing.T) {
	cfg := validConfig()
	cfg.Session.MaxConcurrentSessions = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for MaxConcurrentSessions=0, got nil")
	}
	if !strings.Contains(err.Error(), "max_concurrent_sessions") {
		t.Errorf("error = %v, want it to mention max_concurrent_sessions", err)
	}
}

func TestConfig_Validate_RejectsNegativeMaxConns(t *testing.T) {
	cfg := validConfig()
	cfg.Session.MaxConcurrentSessions = -1
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for MaxConcurrentSessions=-1, got nil")
	}
	if !strings.Contains(err.Error(), "max_concurrent_sessions") {
		t.Errorf("error = %v, want it to mention max_concurrent_sessions", err)
	}
}

func TestConfig_Validate_RejectsZeroTokenTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Session.TokenTTL = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for TokenTTL=0, got nil")
	}
	if !strings.Contains(err.Error(), "token_ttl") {
		t.Errorf("error = %v, want it to mention token_ttl", err)
	}
}

func TestConfig_Validate_RejectsNegativeTokenTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Session.TokenTTL = -time.Second
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative TokenTTL, got nil")
	}
	if !strings.Contains(err.Error(), "token_ttl") {
		t.Errorf("error = %v, want it to mention token_ttl", err)
	}
}

func TestConfig_Validate_RejectsNegativeSessionTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Session.SessionTTL = -time.Second
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative SessionTTL, got nil")
	}
	if !strings.Contains(err.Error(), "session_ttl") {
		t.Errorf("error = %v, want it to mention session_ttl", err)
	}
}

func TestConfig_Validate_AllowsZeroSessionTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Session.SessionTTL = 0 // documented "no limit" mode
	if err := cfg.Validate(); err != nil {
		t.Errorf("0 = no limit should be allowed, got %v", err)
	}
}

func TestConfig_Validate_RejectsNegativeMaxMessageSize(t *testing.T) {
	cfg := validConfig()
	cfg.Session.MaxMessageSize = -1
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for MaxMessageSize=-1, got nil")
	}
	if !strings.Contains(err.Error(), "max_message_size") {
		t.Errorf("error = %v, want it to mention max_message_size", err)
	}
}

func TestConfig_Validate_AllowsZeroMaxMessageSize(t *testing.T) {
	cfg := validConfig()
	cfg.Session.MaxMessageSize = 0 // documented "no limit" mode
	if err := cfg.Validate(); err != nil {
		t.Errorf("0 = no limit should be allowed, got %v", err)
	}
}

func TestConfig_Validate_AllowsTLSWithoutCerts(t *testing.T) {
	a := assert.New(t)
	cfg := validConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = ""
	a.NoError(cfg.Validate(),
		"empty cert/key paths should trigger in-memory cert")
}

func TestConfig_Validate_AllowsTLSWithBothCertPaths(t *testing.T) {
	a := assert.New(t)
	cfg := validConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "assets/cert/server.crt"
	cfg.TLS.KeyFile = "assets/cert/server.key"
	a.NoError(cfg.Validate(), "both paths set should be allowed")
}

func TestConfig_Validate_RejectsTLSWithOnlyCertFile(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	cfg := validConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "assets/cert/server.crt"
	cfg.TLS.KeyFile = ""
	err := cfg.Validate()
	r.Error(err, "expected error for half-configured TLS")
	a.Contains(err.Error(), "cert_file")
	a.Contains(err.Error(), "key_file")
}

func TestConfig_Validate_RejectsTLSWithOnlyKeyFile(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	cfg := validConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = "assets/cert/server.key"
	err := cfg.Validate()
	r.Error(err, "expected error for half-configured TLS")
	a.Contains(err.Error(), "cert_file")
	a.Contains(err.Error(), "key_file")
}

func TestConfig_Validate_IgnoresTLSWhenDisabled(t *testing.T) {
	a := assert.New(t)
	cfg := validConfig()
	cfg.TLS.Enabled = false
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = "assets/cert/server.key"
	a.NoError(cfg.Validate(),
		"disabled TLS should skip cert_file/key_file check")
}
