package main

import (
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// openTestStorage opens an unencrypted storage at a new path in dir and
// loads it as open_storage does.
func openTestStorage(t *testing.T, d *Daemon, dir, name string) {
	a := require.New(t)
	a.NoError(d.openStorage(OpenStorageParams{
		StoragePath:    filepath.Join(dir, name),
		DBNoPassphrase: true,
	}))
	d.loadIdentityAndHistory()
}

func TestSettingsDoNotCarryOverToAnotherStorage(t *testing.T) {
	tests := []struct {
		beforeOpen func(d *Daemon)
		name       string
		wantMode   VerificationMode
	}{
		{
			name:     "defaults",
			wantMode: VerificationModeQuick,
		},
		{
			name: "mode set before any storage",
			beforeOpen: func(d *Daemon) {
				d.handleSetVerificationMode(Command{
					Params: mustJSON(SetVerificationModeParams{
						Mode: int(VerificationModeStrict),
					}),
				})
			},
			wantMode: VerificationModeStrict,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d := newQuietDaemon()
			t.Cleanup(func() {
				d.cancel()
				d.closeStore()
				daemonLogLevel.Set(slog.LevelInfo)
			})
			dir := t.TempDir()
			if tt.beforeOpen != nil {
				tt.beforeOpen(d)
			}

			openTestStorage(t, d, dir, "test-profile.db")
			d.handleSetVerificationMode(Command{
				Params: mustJSON(SetVerificationModeParams{
					Mode: int(VerificationModeAutoAccept),
				}),
			})
			d.handleSetIncognito(Command{
				Params: mustJSON(SetIncognitoParams{Enabled: true}),
			})
			d.handleSetFingerprintFormat(Command{
				Params: mustJSON(SetFingerprintFormatParams{Format: "emoji"}),
			})
			d.handleSetLogLevel(Command{
				Params: mustJSON(SetLogLevelParams{Level: "DEBUG"}),
			})
			testName := d.myName

			openTestStorage(t, d, dir, "real-profile.db")

			a.Equal(tt.wantMode, d.verifMode)
			a.False(d.incognito)
			a.Equal("hex", d.fingerprintFmt)
			a.Equal("INFO", d.logLevel)
			a.Equal(slog.LevelInfo, daemonLogLevel.Level())
			a.NotEqual(testName, d.myName)

			openTestStorage(t, d, dir, "test-profile.db")

			a.Equal(VerificationModeAutoAccept, d.verifMode)
			a.True(d.incognito)
			a.Equal("emoji", d.fingerprintFmt)
			a.Equal("DEBUG", d.logLevel)
			a.Equal(testName, d.myName)
		})
	}
}
