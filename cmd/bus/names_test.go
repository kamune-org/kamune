package main

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

func TestSanitizeName(t *testing.T) {
	long := strings.Repeat("word ", 40)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Bob", "Bob"},
		{"persian with zwnj", "علی\u200Cرضا", "علی\u200Cرضا"},
		{"newline", "Bob\n[INFO] forged", "Bob\uFFFD[INFO] forged"},
		{"bidi override", "Bob\u202Egnp.exe", "Bob\uFFFDgnp.exe"},
		{"isolate", "\u2066Bob\u2069", "\uFFFDBob\uFFFD"},
		{"escape", "\x1b[31mred", "\uFFFD[31mred"},
		{"invalid utf-8", "Bob\xff", "Bob\uFFFD"},
		{"zero width space", "B\u200Bob", "B\uFFFDob"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			got := sanitizeName(tc.in)
			a.Equal(tc.want, got)
			a.NoError(kamune.ValidatePeerName(got))
		})
	}

	t.Run("long", func(t *testing.T) {
		a := require.New(t)
		got := sanitizeName(long)
		a.LessOrEqual(len(got), kamune.MaxPeerNameLength)
		a.True(strings.HasSuffix(got, "…"))
		a.True(strings.HasPrefix(long, strings.TrimSuffix(got, "…")))
		a.True(utf8.ValidString(got))
		a.NoError(kamune.ValidatePeerName(got))
	})

	t.Run("long multibyte", func(t *testing.T) {
		a := require.New(t)
		got := sanitizeName(strings.Repeat("ب", 50))
		a.LessOrEqual(len(got), kamune.MaxPeerNameLength)
		a.True(utf8.ValidString(got))
		a.NoError(kamune.ValidatePeerName(got))
	})
}

func TestValidateLabel(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{"plain", "Bob", "Bob", nil},
		{"trimmed", "  Bob  ", "Bob", nil},
		{"empty", "   ", "", errNameRequired},
		{"newline", "Bob\nAlice", "", kamune.ErrInvalidPeerName},
		{"bidi", "\u202EboB", "", kamune.ErrInvalidPeerName},
		{"too long", strings.Repeat("x", kamune.MaxPeerNameLength+1), "",
			kamune.ErrInvalidPeerName},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			got, err := validateLabel(tc.in)
			if tc.wantErr != nil {
				a.ErrorIs(err, tc.wantErr)
				return
			}
			a.NoError(err)
			a.Equal(tc.want, got)
		})
	}
}

func TestEscapeLogText(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Accepted peer: Bob", "Accepted peer: Bob"},
		{"newline", "x\n2026-10-03T10:00:00Z [INFO] forged",
			`x\n2026-10-03T10:00:00Z [INFO] forged`},
		{"carriage return and tab", "a\rb\tc", `a\rb\tc`},
		{"bidi override", "Bob\u202Eexe", `Bob\u202Eexe`},
		{"invalid utf-8", "Bob\xff", `Bob\xff`},
		{"replacement char kept", "Bob\uFFFD", "Bob\uFFFD"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tc.want, escapeLogText(tc.in))
		})
	}
}

func TestAddLogEntryKeepsOneLine(t *testing.T) {
	a := require.New(t)
	app := &App{logBufferSize: 10}
	app.addLogEntry("INFO",
		"Verifying peer: x\n2026-10-03T10:00:00Z [INFO] Accepted peer: Bob")
	entries := app.GetLogEntries()
	a.Len(entries, 1)
	a.NotContains(entries[0].Message, "\n")
	a.Contains(entries[0].Message, `x\n2026`)
}

// TestNameSettersValidate checks every binding that stores a name typed in
// the UI against the protocol's name rule.
func TestNameSettersValidate(t *testing.T) {
	const bad = "Bob\u202Egnp"
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	store := app.store()

	key := newTestPubKey(t)
	keyB64 := fingerprint.Base64(key)
	a.ErrorIs(app.AddPeer(keyB64, bad), kamune.ErrInvalidPeerName)
	a.NoError(app.AddPeer(keyB64, "Bob"))
	a.ErrorIs(app.RenamePeer(keyB64, bad), kamune.ErrInvalidPeerName)
	a.NoError(app.RenamePeer(keyB64, "Robert"))
	got, err := store.FindPeer(key)
	a.NoError(err)
	a.Equal("Robert", got.Name)

	a.ErrorIs(app.SetMyName(bad), kamune.ErrInvalidPeerName)
	a.Error(app.SetMyName(strings.Repeat("x", maxLocalNameLength+1)))
	a.NoError(app.SetMyName("alice"))
	a.Equal("alice", app.GetMyName())

	app.sessions = []*liveSession{{ID: "s1", PeerName: "Bob"}}
	a.ErrorIs(app.RenameSession("s1", bad), kamune.ErrInvalidPeerName)
	a.ErrorIs(app.RenameSession("s1", " "), errNameRequired)
	a.Equal("Bob", app.sessions[0].PeerName)
	a.NoError(app.RenameSession("s1", "Bobby"))
	a.Equal("Bobby", app.sessions[0].PeerName)

	a.ErrorIs(app.RenameHistorySession("s1", bad), kamune.ErrInvalidPeerName)
}

// TestStoredNamesAreSanitized covers names stored before the protocol
// limited them: they are shown without their control characters.
func TestStoredNamesAreSanitized(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	store := app.store()

	peer := newTestPeer(t, "Bob")
	a.NoError(store.StorePeer(&storage.Peer{
		Name: "Bob\n[INFO] forged", PublicKey: peer.PublicKey,
	}))
	app.refreshPeersCache()

	id := app.identifyPeer(store, peer)
	a.Equal("Bob\uFFFD[INFO] forged", id.Label)
	peers := app.ListKnownPeers()
	a.Len(peers, 1)
	a.Equal("Bob\uFFFD[INFO] forged", peers[0].Name)
}
