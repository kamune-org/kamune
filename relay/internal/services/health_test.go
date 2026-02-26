package services

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// formatDuration
// ---------------------------------------------------------------------------

func TestFormatDuration_SubMillisecond(t *testing.T) {
	a := assert.New(t)
	d := 500 * time.Microsecond
	result := formatDuration(d)
	a.Equal("500µs", result)
}

func TestFormatDuration_Milliseconds(t *testing.T) {
	a := assert.New(t)
	d := 123 * time.Millisecond
	result := formatDuration(d)
	a.Equal("123ms", result)
}

func TestFormatDuration_SubSecond(t *testing.T) {
	a := assert.New(t)
	d := 999 * time.Millisecond
	result := formatDuration(d)
	// Should use default String() since < 1s
	a.Contains(result, "ms")
}

func TestFormatDuration_ExactlyOneSecond(t *testing.T) {
	a := assert.New(t)
	d := 1 * time.Second
	result := formatDuration(d)
	a.Equal("1s", result)
}

func TestFormatDuration_Seconds(t *testing.T) {
	a := assert.New(t)
	d := 45 * time.Second
	result := formatDuration(d)
	a.Equal("45s", result)
}

func TestFormatDuration_MinutesAndSeconds(t *testing.T) {
	a := assert.New(t)
	d := 3*time.Minute + 22*time.Second
	result := formatDuration(d)
	a.Equal("3m 22s", result)
}

func TestFormatDuration_ExactMinutes(t *testing.T) {
	a := assert.New(t)
	d := 5 * time.Minute
	result := formatDuration(d)
	a.Equal("5m 0s", result)
}

func TestFormatDuration_HoursMinutesSeconds(t *testing.T) {
	a := assert.New(t)
	d := 2*time.Hour + 15*time.Minute + 30*time.Second
	result := formatDuration(d)
	a.Equal("2h 15m 30s", result)
}

func TestFormatDuration_ExactHours(t *testing.T) {
	a := assert.New(t)
	d := 3 * time.Hour
	result := formatDuration(d)
	a.Equal("3h 0m 0s", result)
}

func TestFormatDuration_DaysHoursMinutesSeconds(t *testing.T) {
	a := assert.New(t)
	d := 25*time.Hour + 30*time.Minute + 10*time.Second
	result := formatDuration(d)
	a.Equal("1d 1h 30m 10s", result)
}

func TestFormatDuration_MultipleDays(t *testing.T) {
	a := assert.New(t)
	d := 72 * time.Hour // 3 days exactly
	result := formatDuration(d)
	a.Equal("3d 0h 0m 0s", result)
}

func TestFormatDuration_ZeroDuration(t *testing.T) {
	a := assert.New(t)
	result := formatDuration(0)
	// 0 is < 1s, so uses default String()
	a.Equal("0s", result)
}

func TestFormatDuration_Nanoseconds(t *testing.T) {
	a := assert.New(t)
	d := 42 * time.Nanosecond
	result := formatDuration(d)
	a.Equal("42ns", result)
}

func TestFormatDuration_FractionalSeconds_UsesDefault(t *testing.T) {
	a := assert.New(t)
	// 1.5ms should use default Go string since < 1s
	d := 1500 * time.Microsecond
	result := formatDuration(d)
	a.Equal("1.5ms", result)
}

func TestFormatDuration_TruncatesSubSeconds(t *testing.T) {
	a := assert.New(t)
	// 1 minute + 30.999 seconds — sub-second part should be dropped
	d := 1*time.Minute + 30*time.Second + 999*time.Millisecond
	result := formatDuration(d)
	a.Equal("1m 30s", result)
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestHealth_OK(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	status, err := svc.Health()
	a.NoError(err)
	a.NotNil(status)
	a.Equal("ok", status.Status)
	a.Equal("ok", status.Storage)

	// Latency should be a readable string, not nanosecond integer.
	a.NotEmpty(status.Latency)
	// Uptime should be a readable string.
	a.NotEmpty(status.Uptime)
	// StartedAt should be a readable timestamp (not RFC3339Nano).
	a.NotEmpty(status.StartedAt)
	a.NotContains(status.StartedAt, "T") // not RFC3339 format with T separator
	// Identity should be set.
	a.NotEmpty(status.Identity)
}

func TestHealth_TimeFieldsAreReadable(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	status, err := svc.Health()
	a.NoError(err)

	// Latency: should contain a time unit suffix (ns, µs, ms, or s).
	hasUnit := strings.ContainsAny(status.Latency, "nµms")
	a.True(hasUnit, "latency should contain time unit, got: %s", status.Latency)

	// Uptime: for a freshly started service should be sub-second or a few seconds.
	hasUnit = strings.ContainsAny(status.Uptime, "nµms")
	a.True(hasUnit, "uptime should contain time unit, got: %s", status.Uptime)

	// StartedAt: should match "2006-01-02 15:04:05 MST" layout pattern.
	// At minimum it should contain spaces between date, time, and timezone.
	parts := strings.Fields(status.StartedAt)
	a.GreaterOrEqual(len(parts), 3, "started_at should have date, time, and timezone: %s", status.StartedAt)
}

// ---------------------------------------------------------------------------
// Identity with format variants
// ---------------------------------------------------------------------------

func TestIdentity_DefaultFormat(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	resp := svc.Identity("")
	a.Equal("base64", resp.Format)
	a.NotEmpty(resp.Key)
	a.NotEmpty(resp.Algorithm)

	// Should match PublicKey() output.
	a.Equal(svc.PublicKey(), resp.Key)
}

func TestIdentity_Base64Format(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	resp := svc.Identity("base64")
	a.Equal("base64", resp.Format)
	a.NotEmpty(resp.Key)
	a.Equal(svc.PublicKey(), resp.Key)
}

func TestIdentity_HexFormat(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	resp := svc.Identity("hex")
	a.Equal("hex", resp.Format)
	a.NotEmpty(resp.Key)
	// Hex should contain colon-separated uppercase hex bytes.
	a.Contains(resp.Key, ":")
	for _, c := range resp.Key {
		a.True(c == ':' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'),
			"unexpected character in hex output: %c", c)
	}
}

func TestIdentity_EmojiFormat(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	resp := svc.Identity("emoji")
	a.Equal("emoji", resp.Format)
	a.NotEmpty(resp.Key)
	// Emoji format joins 8 emojis with " • ".
	a.Contains(resp.Key, " • ")
	parts := strings.Split(resp.Key, " • ")
	a.Equal(8, len(parts), "emoji should produce 8 symbols, got %d", len(parts))
}

func TestIdentity_FingerprintFormat(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	resp := svc.Identity("fingerprint")
	a.Equal("fingerprint", resp.Format)
	a.NotEmpty(resp.Key)
	// Fingerprint is a SHA-256 digest base64-encoded; should differ from raw base64.
	base64Resp := svc.Identity("base64")
	a.NotEqual(base64Resp.Key, resp.Key, "fingerprint should differ from raw base64 key")
}

func TestIdentity_UnknownFormatFallsBackToBase64(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	resp := svc.Identity("unknown-format")
	a.Equal("base64", resp.Format)
	a.Equal(svc.PublicKey(), resp.Key)
}

func TestIdentity_FormatIsCaseInsensitive(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	lower := svc.Identity("hex")
	upper := svc.Identity("HEX")
	mixed := svc.Identity("Hex")

	a.Equal(lower.Key, upper.Key)
	a.Equal(lower.Key, mixed.Key)
	a.Equal("hex", lower.Format)
	a.Equal("hex", upper.Format)
	a.Equal("hex", mixed.Format)
}

func TestIdentity_FormatWithWhitespace(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	resp := svc.Identity("  emoji  ")
	a.Equal("emoji", resp.Format)
	a.Contains(resp.Key, " • ")
}

func TestIdentity_AlgorithmFieldIsSet(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	for _, format := range []string{"base64", "hex", "emoji", "fingerprint"} {
		resp := svc.Identity(format)
		a.NotEmpty(resp.Algorithm, "algorithm should be set for format %q", format)
	}
}

func TestIdentity_ConsistentAcrossCalls(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	resp1 := svc.Identity("emoji")
	resp2 := svc.Identity("emoji")
	a.Equal(resp1.Key, resp2.Key, "same format should return the same key across calls")

	resp3 := svc.Identity("hex")
	resp4 := svc.Identity("hex")
	a.Equal(resp3.Key, resp4.Key)
}

func TestIdentity_AllFormatsProduceDifferentOutput(t *testing.T) {
	a := assert.New(t)
	svc := newTestService(t)

	b64 := svc.Identity("base64").Key
	hex := svc.Identity("hex").Key
	emoji := svc.Identity("emoji").Key
	fp := svc.Identity("fingerprint").Key

	// Each encoding should produce a distinct string.
	keys := []string{b64, hex, emoji, fp}
	unique := make(map[string]bool)
	for _, k := range keys {
		unique[k] = true
	}
	a.Equal(4, len(unique), "all four formats should produce distinct outputs")
}
