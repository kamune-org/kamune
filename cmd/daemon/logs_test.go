package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/fingerprint"
)

// logMessages returns the messages in d's log buffer.
func logMessages(d *Daemon) []string {
	d.logMu.RLock()
	defer d.logMu.RUnlock()
	msgs := make([]string, len(d.logEntries))
	for i, e := range d.logEntries {
		msgs[i] = e.Message
	}
	return msgs
}

// Log messages name relay and p2p tokens by a short prefix, never in
// full: an unused relay token lets whoever reads the log join the
// session it was made for.
func TestLogsNameTokensByPrefix(t *testing.T) {
	tests := []struct {
		name string
		// run makes tokens on d, logging them, and returns them.
		run func(t *testing.T, d *Daemon, rec *eventRecorder) []string
	}{
		{
			name: "relay",
			run: func(t *testing.T, d *Daemon, rec *eventRecorder) []string {
				a := require.New(t)
				relay := newFakeRelay(t)
				startup := startRelayServer(t, d, rec, relay)
				token := generateRelayToken(t, d, rec, "token")
				d.handleRemoveRelayToken(Command{
					ID: "rm", Params: mustJSON(MapS{"token": token}),
				})
				evt := rec.waitFor(t, func(e recordedEvent) bool {
					return e.ID == "rm"
				})
				a.Equal(EvtResponse, evt.Evt, "remove failed: %v", evt.Data)
				return []string{startup, token}
			},
		},
		{
			name: "p2p",
			run: func(t *testing.T, d *Daemon, rec *eventRecorder) []string {
				a := require.New(t)
				broker := newFakeBroker(t, false)
				d.handleStartServer(Command{
					ID: "start",
					Params: mustJSON(StartServerParams{
						Addr: "127.0.0.1:0", Transport: "p2p",
						BrokerAddr: broker.addr(),
						PeerPubB64: fingerprint.Base64(newTestPeerKey(t)),
					}),
				})
				rec.waitFor(t, isEvent(EvtServerStarted))
				token, err := d.GenerateP2PToken(broker.addr(), "")
				a.NoError(err)
				a.NoError(d.RemoveP2PToken(token))
				return []string{token}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d, rec := newTestDaemon(t, VerificationModeQuick, false)
			t.Cleanup(d.stopServer)
			tokens := tt.run(t, d, rec)

			msgs := logMessages(d)
			for _, token := range tokens {
				a.Len(token, 32)
				named := false
				for _, msg := range msgs {
					a.NotContains(msg, token)
					named = named || strings.Contains(msg, shortToken(token))
				}
				a.True(named, "no log message names %s", shortToken(token))
			}
		})
	}
}

func TestShortToken(t *testing.T) {
	tests := []struct {
		token string
		want  string
	}{
		{token: "", want: ""},
		{token: "abcd", want: "abcd"},
		{token: "abcdef01", want: "abcdef01"},
		{token: "abcdef0123", want: "abcdef01..."},
		{token: strings.Repeat("ab", 32), want: "abababab..."},
	}
	for _, tt := range tests {
		t.Run(tt.token, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tt.want, shortToken(tt.token))
		})
	}
}

// export_logs writes a file that only the user can read, replaces a link
// at the path instead of writing through it, and escapes line breaks, so
// a peer's name cannot add forged entries.
func TestExportLogsWritesPrivateFile(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	forged := "x\n2026-01-01T00:00:00Z [INFO] [cmd/daemon] Accepted peer: Bob"
	d.addLogEntry("INFO", "Verifying peer: "+forged+"\u2028\x1b[2J")

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	a.NoError(os.WriteFile(target, []byte("keep"), 0o644))
	path := filepath.Join(dir, "logs.txt")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink: %v", err)
	}

	d.handleExportLogs(Command{
		ID: "export", Params: mustJSON(ExportLogsParams{FilePath: path}),
	})
	evt := rec.waitFor(t, func(e recordedEvent) bool { return e.ID == "export" })
	a.Equal(EvtResponse, evt.Evt, "export failed: %v", evt.Data)

	got, err := os.ReadFile(target)
	a.NoError(err)
	a.Equal("keep", string(got), "export wrote through the link")
	info, err := os.Lstat(path)
	a.NoError(err)
	a.True(info.Mode().IsRegular())
	a.Equal(os.FileMode(0o600), info.Mode().Perm())
	entries, err := os.ReadDir(dir)
	a.NoError(err)
	a.Len(entries, 2, "a temporary file was left behind")

	data, err := os.ReadFile(path)
	a.NoError(err)
	for _, line := range strings.Split(string(data), "\n") {
		a.False(strings.HasPrefix(line, "2026-01-01"), "forged: %q", line)
	}
	a.Contains(string(data), `peer: x\n2026-01-01T00:00:00Z [INFO] `+
		`[cmd/daemon] Accepted peer: Bob\u2028\x1b[2J`+"\n")
}

func TestEscapeLogText(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "plain text: 'quoted' \"x\" \\", want: "plain text: 'quoted' \"x\" \\"},
		{in: "two\nlines\r\n", want: `two\nlines\r\n`},
		{in: "tab\there", want: `tab\there`},
		{in: "esc\x1b[0m", want: `esc\x1b[0m`},
		{in: "sep\u2028\u2029", want: `sep\u2028\u2029`},
		{in: "bidi\u202e", want: `bidi\u202e`},
		{in: "naïve 日本", want: "naïve 日本"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tt.want, escapeLogText(tt.in))
		})
	}
}

// set_log_level applies to the log buffer, which get_logs and export_logs
// read, and to log_entry events, as it does to stderr: an entry below the
// level reaches none of them.
func TestLogLevelAppliesToBufferAndEvents(t *testing.T) {
	levels := []string{"DEBUG", "INFO", "WARN", "ERROR"}
	tests := []struct {
		level     string
		want      []string
		wantLevel slog.Level
	}{
		{level: "debug", wantLevel: slog.LevelDebug, want: levels},
		{level: "INFO", wantLevel: slog.LevelInfo, want: levels[1:]},
		{level: "WARN", wantLevel: slog.LevelWarn, want: levels[2:]},
		{level: "ERROR", wantLevel: slog.LevelError, want: levels[3:]},
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			a := require.New(t)
			d, rec := newTestDaemon(t, VerificationModeQuick, false)
			t.Cleanup(func() { daemonLogLevel.Set(slog.LevelInfo) })
			d.handleSetLogLevel(Command{
				ID:     "level",
				Params: mustJSON(SetLogLevelParams{Level: tt.level}),
			})
			evt := rec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "level"
			})
			a.Equal(EvtResponse, evt.Evt, "set_log_level failed: %v", evt.Data)
			a.Equal(tt.wantLevel, daemonLogLevel.Level())

			for _, level := range levels {
				d.addLogEntry(level, "probe at "+level)
			}

			var buffered []string
			for _, msg := range logMessages(d) {
				if level, ok := strings.CutPrefix(
					msg, "[cmd/daemon] probe at ",
				); ok {
					buffered = append(buffered, level)
				}
			}
			a.Equal(tt.want, buffered)

			var emitted []string
			rec.mu.Lock()
			for _, e := range rec.events {
				msg, _ := e.Data["message"].(string)
				if e.Evt != EvtLogEntry ||
					!strings.Contains(msg, "probe at ") {
					continue
				}
				emitted = append(emitted, e.Data["level"].(string))
			}
			rec.mu.Unlock()
			a.Equal(tt.want, emitted)
		})
	}
}
