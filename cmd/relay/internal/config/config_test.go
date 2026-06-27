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
			Password: "",
		},
		Diagnose: Diagnose{
			Enabled: true,
			Address: "127.0.0.1:0",
		},
		WS: WS{
			Enabled: true,
			Address: "127.0.0.1:0",
		},
		TCP: TCP{
			Enabled: true,
			Address: "127.0.0.1:0",
		},
		TLS: TLS{
			Enabled:  true,
			Address:  "127.0.0.1:0",
			CertFile: "",
			KeyFile:  "",
		},
		WSS: WSS{
			Enabled: false, // off by default in tests
			Address: "127.0.0.1:0",
		},
		Session: Session{
			TokenTTL:              5 * time.Minute,
			SessionTTL:            30 * time.Minute,
			HandshakeTimeout:      30 * time.Second,
			MaxConcurrentSessions: 100,
			MaxMessageSize:        65536,
		},
		RateLimit: RateLimit{
			// Disabled is false by default — rate limit is on.
			TimeWindow: time.Minute,
			Quota:      20,
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

func TestConfig_Validate_AllowsWSSWithBothCertPaths(t *testing.T) {
	a := assert.New(t)
	cfg := validConfig()
	cfg.WSS.Enabled = true
	cfg.WSS.CertFile = "assets/cert/server.crt"
	cfg.WSS.KeyFile = "assets/cert/server.key"
	a.NoError(cfg.Validate(), "both paths set should be allowed")
}

func TestConfig_Validate_AllowsWSSWithBothCertPathsEmpty(t *testing.T) {
	a := assert.New(t)
	cfg := validConfig()
	cfg.WSS.Enabled = true
	cfg.WSS.CertFile = ""
	cfg.WSS.KeyFile = ""
	a.NoError(cfg.Validate(),
		"empty cert/key paths should trigger in-memory cert")
}

func TestConfig_Validate_RejectsWSSWithOnlyCertFile(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	cfg := validConfig()
	cfg.WSS.Enabled = true
	cfg.WSS.CertFile = "assets/cert/server.crt"
	cfg.WSS.KeyFile = ""
	err := cfg.Validate()
	r.Error(err, "expected error for half-configured WSS")
	a.Contains(err.Error(), "cert_file")
	a.Contains(err.Error(), "key_file")
}

func TestConfig_Validate_RejectsWSSWithOnlyKeyFile(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	cfg := validConfig()
	cfg.WSS.Enabled = true
	cfg.WSS.CertFile = ""
	cfg.WSS.KeyFile = "assets/cert/server.key"
	err := cfg.Validate()
	r.Error(err, "expected error for half-configured WSS")
	a.Contains(err.Error(), "cert_file")
	a.Contains(err.Error(), "key_file")
}

func TestConfig_Validate_IgnoresWSSWhenDisabled(t *testing.T) {
	a := assert.New(t)
	cfg := validConfig()
	cfg.WSS.Enabled = false
	cfg.WSS.CertFile = ""
	cfg.WSS.KeyFile = "assets/cert/server.key"
	a.NoError(cfg.Validate(),
		"disabled WSS should skip cert_file/key_file check")
}

func TestConfig_Validate_RateLimit_DefaultOnWhenSectionMissing(t *testing.T) {
	a := assert.New(t)
	cfg := validConfig()
	cfg.RateLimit = RateLimit{}
	a.True(cfg.RateLimit.IsEnabled(),
		"zero-value RateLimit should have IsEnabled() == true")
}

func TestConfig_Validate_RateLimit_DefaultOnWhenKeyMissing(t *testing.T) {
	a := assert.New(t)
	cfg := validConfig()
	cfg.RateLimit.Disabled = false
	a.True(cfg.RateLimit.IsEnabled(),
		"explicit false should have IsEnabled() == true")
}

func TestConfig_Validate_RateLimit_DisabledTrueTurnsOff(t *testing.T) {
	a := assert.New(t)
	cfg := validConfig()
	cfg.RateLimit.Disabled = true
	a.False(cfg.RateLimit.IsEnabled(),
		"disabled = true should have IsEnabled() == false")
}

func TestConfig_Validate_RateLimit_DisabledFalseExplicitOn(t *testing.T) {
	a := assert.New(t)
	cfg := validConfig()
	cfg.RateLimit.Disabled = false
	a.True(cfg.RateLimit.IsEnabled(),
		"disabled = false explicit should have IsEnabled() == true")
}

func TestConfig_Validate_RejectsNoServersEnabled(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	cfg := validConfig()
	cfg.Diagnose.Enabled = false
	cfg.WS.Enabled = false
	cfg.TCP.Enabled = false
	cfg.TLS.Enabled = false
	cfg.WSS.Enabled = false
	err := cfg.Validate()
	r.Error(err, "expected error when no servers are enabled")
	a.Contains(err.Error(), "at least one server")
}
